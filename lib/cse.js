/*
 * Copyright 2017 Joyent, Inc.
 */

var crypto = require('crypto');

var assert = require('assert-plus');
var CipherStream = require('./cipher_stream');
var PassThrough = require('stream').PassThrough;
var b64 = require('b64');
var verror = require('verror');

var VError = verror.VError;


var VERSION = 1;
var CIPHERS = {
    'AES/CBC/PKCS5Padding': {
        string: 'aes-256-cbc',
        ivBytes: 16,
        keyBytes: 32
    },
    'AES/CTR/NoPadding': {
        string: 'aes-256-ctr',
        ivBytes: 16,
        keyBytes: 32
    },
    'AES/GCM/NoPadding': {
        string: 'aes-256-gcm',
        ivBytes: 12,
        keyBytes: 32
    }
};
var REQUIRED_HEADERS = [
    'm-encrypt-key-id',
    'm-encrypt-iv',
    'm-encrypt-cipher',
    'm-encrypt-hmac-type',
    'm-encrypt-type'
];


exports.decrypt = function decrypt(options, encrypted, res, cb) {
    assert.object(options, 'options');
    assert.object(res, 'res');
    assert.object(res.headers, 'res.headers');
    assert.stream(encrypted, 'encrypted');
    assert.func(options.cse_getKey, 'options.cse_getKey');

    var invalidHeaders = validateHeaders(res.headers);
    if (invalidHeaders) {
        cb(new Error('Headers are missing or invalid: ' +
            invalidHeaders), null, res);
        return;
    }

    options.cse_getKey(res.headers['m-encrypt-key-id'], function (err, key) {
        if (err) {
            cb(new VError(err, 'failed executing cse_getKey'), null, res);
            return;
        }

        var algorithm = getAlgorithm(res.headers['m-encrypt-cipher']);
        if (!algorithm) {
            cb(new Error('Unsupported cipher algorithm: ' +
                res.headers['m-encrypt-cipher']), null, res);
            return;
        }
        var hmacType = res.headers['m-encrypt-hmac-type'];
        var decipher = crypto.createDecipheriv(algorithm.string, key,
            b64.decode(new Buffer(res.headers['m-encrypt-iv'])));
        var hmac = crypto.createHmac(hmacType, key);
        var cipherStream = new CipherStream(hmacType,
            res.headers['content-length']);
        var output = new PassThrough();
        var byteLength = 0;

        function handleCipherData(data) {
            hmac.update(data);
        }

        function handleEncryptedError(streamErr) {
            cipherStream.removeListener('data', handleCipherData);
            decipher.removeListener('data', handleDecipherData);
            decipher.removeListener('error', handleDecipherError);
            decipher.removeListener('end', handleDecipherEnd);

            output.emit('error', new VError(streamErr,
                'failed to read encrypted data'));
        }

        function handleDecipherData(data) {
            byteLength += Buffer.byteLength(data);
        }

        function handleDecipherError(decErr) {
            decipher.removeListener('data', handleDecipherData);
            decipher.removeListener('end', handleDecipherEnd);
            output.emit('error', new VError(decErr,
                'failed to write to decipher'));
        }

        function handleDecipherEnd(data) {
            var digest = hmac.digest('base64');
            if (digest.toString() !== cipherStream.digest().toString()) {
                output.emit('error', new Error('cipher hmac doesn\'t match ' +
                    'stored hmac value'));
                return;
            }

            var origLength = res.headers['m-encrypt-plaintext-content-length'];
            if (origLength && byteLength !== parseInt(origLength, 10)) {
                output.emit('error', new Error(
                    'decrypted file size doesn\'t match original copy'));
                return;
            }
        }

        decryptMetadata(res.headers, key, function (metadataErr) {
            if (metadataErr) {
                cb(new VError(metadataErr, 'failed decrypting metadata: %s',
                    JSON.stringify(res.headers, null, '  ')), null, res);
                return;
            }

            cipherStream.on('data', handleCipherData);
            encrypted.once('error', handleEncryptedError);

            decipher.on('data', handleDecipherData);
            decipher.once('error', handleDecipherError);
            decipher.once('end', handleDecipherEnd);

            cb(null, output, res);
            encrypted.pipe(cipherStream).pipe(decipher).pipe(output);
        });
    });
};


exports.encrypt = function encrypt(options, input, cb) {
    assert.object(options, 'options');
    assert.stream(input, 'input');
    assert.string(options.cse_key, 'options.cse_key');
    assert.string(options.cse_cipher, 'options.cse_cipher');

    var algorithm = getAlgorithm(options.cse_cipher);
    if (!algorithm) {
        throw new Error('Unsupported cipher algorithm: ' + options.cse_cipher);
    }

    options.headers = options.headers || {};
    var iv = crypto.randomBytes(algorithm.ivBytes);
    var cipher = crypto.createCipheriv(algorithm.string, options.cse_key, iv);
    var hmac = crypto.createHmac('sha256', options.cse_key);
    var output = new PassThrough();

    function handleCipherData(data) {
        hmac.update(data);
    }

    cipher.on('data', handleCipherData);

    cipher.once('error', function (err) {
        cipher.removeListener('data', handleCipherData);
        output.emit('error', new VError(err, 'failed reading cipher'));
    });

    cipher.once('end', function (data) {
        // Append the digest to the end of the payload
        output.write(hmac.digest('base64'));
    });

    if (options.contentLength !== undefined) {
        options.headers['m-encrypt-plaintext-content-length'] =
            options.contentLength;
    }
    options.headers['m-encrypt-type'] = 'client/' + VERSION;
    options.headers['m-encrypt-key-id'] = options.cse_keyId;
    options.headers['m-encrypt-iv'] = b64.encode(iv).toString();
    options.headers['m-encrypt-cipher'] = options.cse_cipher;
    options.headers['m-encrypt-hmac-type'] = 'sha256';

    if (options.headers['m-encrypt-metadata']) {
        encryptMetadata(options.headers, options.cse_key,
            function (err) {
                if (err) {
                    cb(new VError(err, 'failed encrypting metadata: %s',
                        JSON.stringify(options.headers, null, '  ')));
                    return;
                }

                cb(null, output);
                input.pipe(cipher).pipe(output);
            });

        return;
    }

    cb(null, output);
    input.pipe(cipher).pipe(output);
};


exports.isSupportedVersion = function isSupportedVersion(version) {
    if (!/\d/.test(version)) {
        return (false);
    }

    var major = parseInt(version, 10);

    return (major === VERSION);
};


function validateHeaders(headers) {
    var missingHeaders = [];
    REQUIRED_HEADERS.forEach(function (header) {
        if (headers[header] === undefined || headers[header] === null) {
            missingHeaders.push(header);
        }
    });

    if ((headers['m-encrypt-metadata'] !== undefined &&
      headers['m-encrypt-metadata'] !== null) &&
      !headers['m-encrypt-metadata-cipher']) {

      missingHeaders.push('m-encrypt-metadata-cipher');
    }

    return (missingHeaders.length ? missingHeaders : null);
}


function decryptMetadata(headers, key, cb) {
    if (!headers['m-encrypt-metadata']) {
        cb();
        return;
    }

    var algorithm = getAlgorithm(headers['m-encrypt-metadata-cipher']);
    if (!algorithm) {
        cb(new Error('Unsupported cipher algorithm: ' +
            headers['m-encrypt-metadata-cipher']));
        return;
    }
    var decipher = crypto.createDecipheriv(algorithm.string, key,
        b64.decode(new Buffer(headers['m-encrypt-metadata-iv'])));
    var hmac = crypto.createHmac('sha256', key);

    var bufs = [];
    decipher.on('data', function (data) {
        bufs.push(data);
    });

    decipher.once('finish', function () {
        hmac.update(b64.decode(new Buffer(headers['m-encrypt-metadata'])));
        headers['m-encrypt-metadata'] = Buffer.concat(bufs).toString();

        if (headers['m-encrypt-metadata-mac'] !== hmac.digest('base64')) {
            cb(new Error('mac hash doesn\'t match'));
            return;
        }

        cb();
    });

    decipher.write(b64.decode(new Buffer(headers['m-encrypt-metadata'])));
    decipher.end();
}


function encryptMetadata(headers, key, cb) {
    var algorithm = getAlgorithm(headers['m-encrypt-metadata-cipher']);
    if (!algorithm) {
        cb(new Error('Unsupported cipher algorithm: ' +
            headers['m-encrypt-metadata-cipher']));
        return;
    }

    var iv = crypto.randomBytes(algorithm.ivBytes);
    headers['m-encrypt-metadata-iv'] = b64.encode(iv).toString();
    var cipher = crypto.createCipheriv(algorithm.string, key, iv);
    var hmac = crypto.createHmac('sha256', key);

    var bufs = [];
    function handleCipherData(data) {
        bufs.push(data);
    }

    function handleCipherFinish() {
        var encrypted = Buffer.concat(bufs);
        headers['m-encrypt-metadata'] = b64.encode(encrypted).toString();
        hmac.update(encrypted);
        headers['m-encrypt-metadata-mac'] = hmac.digest('base64');
        cb();
    }

    cipher.on('data', handleCipherData);
    cipher.once('finish', handleCipherFinish);

    cipher.once('error', function (err) {
        cipher.removeListener('data', handleCipherData);
        cipher.removeListener('finish', handleCipherFinish);
        cb(new VError(err, 'failed reading cipher'));
    });

    cipher.write(headers['m-encrypt-metadata']);
    cipher.end();
}


function getAlgorithm(cipher) {
    return (CIPHERS.hasOwnProperty(cipher) && CIPHERS[cipher]);
}
