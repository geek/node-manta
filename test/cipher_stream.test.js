/*
 * Copyright 2017 Joyent, Inc.
 */

var MemoryStream = require('readable-stream/passthrough.js');
var CipherStream = require('../lib/cipher_stream');


function test(name, testfunc) {
    module.exports[name] = testfunc;
}


test('splits a digest from the cipher stream', function (t) {
    var inputCipher = new Buffer(50);
    var inputDigest = new Buffer(44);
    inputCipher.fill('3');
    inputDigest.fill('4');

    var input = new MemoryStream();
    var output = new CipherStream('sha256', Buffer.byteLength(inputCipher) +
        Buffer.byteLength(inputDigest));

    var cipher = new Buffer('');
    output.on('data', function (data) {
        cipher = Buffer.concat([cipher, data]);
    });

    output.once('end', function () {
        t.equal(cipher.toString(), inputCipher.toString());
        t.equal(output.digest().toString(), inputDigest.toString());
        t.done();
    });

    input.pipe(output);
    input.write(inputCipher);
    input.write(inputDigest);
});


test('splits a multi-chunk digest from the cipher stream', function (t) {
    var inputCipher = new Buffer(50);
    var inputDigest1 = new Buffer(22);
    var inputDigest2 = new Buffer(22);
    inputCipher.fill('3');
    inputDigest1.fill('4');
    inputDigest2.fill('4');

    var input = new MemoryStream();
    var output = new CipherStream('sha256', Buffer.byteLength(inputCipher) +
        Buffer.byteLength(inputDigest1) + Buffer.byteLength(inputDigest2));

    var cipher = new Buffer('');
    output.on('data', function (data) {
        cipher = Buffer.concat([cipher, data]);
    });

    output.once('end', function () {
        t.equal(cipher.toString(), inputCipher.toString());
        t.equal(output.digest().toString(), inputDigest1.toString() +
            inputDigest2.toString());
        t.done();
    });

    input.pipe(output);
    input.write(inputCipher);
    input.write(inputDigest1);
    input.write(inputDigest2);
});

test('splits a multi-chunk digest from multi-chunk cipher', function (t) {
    var inputCipher1 = new Buffer(50);
    var inputCipher2 = new Buffer(50);
    var inputDigest1 = new Buffer(22);
    var inputDigest2 = new Buffer(22);
    inputCipher1.fill('3');
    inputCipher2.fill('3');
    inputDigest1.fill('4');
    inputDigest2.fill('4');

    var input = new MemoryStream();
    var output = new CipherStream('sha256',
        Buffer.byteLength(inputCipher1) + Buffer.byteLength(inputCipher2) +
        Buffer.byteLength(inputDigest1) + Buffer.byteLength(inputDigest2));

    var cipher = new Buffer('');
    output.on('data', function (data) {
        cipher = Buffer.concat([cipher, data]);
    });

    output.once('end', function () {
        t.equal(cipher.toString(), inputCipher1.toString() +
            inputCipher2.toString());
        t.equal(output.digest().toString(), inputDigest1.toString() +
            inputDigest2.toString());
        t.done();
    });

    input.pipe(output);
    input.write(inputCipher1);
    input.write(inputCipher2);
    input.write(inputDigest1);
    input.write(inputDigest2);
});
