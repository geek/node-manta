/*
 * Copyright 2017 Joyent, Inc.
 */

var MemoryStream = require('readable-stream/passthrough.js');

var cse = require('../lib/cse');


function test(name, testfunc) {
    module.exports[name] = testfunc;
}


test('isSupportedVersion() returns false for invalid versions', function (t) {
    var versions = [
        '',
        null,
        '0',
        '0.',
        'b.b'
    ];

    versions.forEach(function (version) {
        t.ok(!cse.isSupportedVersion(version));
    });
    t.done();
});


test('isSupportedVersion() returns true for valid versions', function (t) {
    var versions = [
        '1'
    ];

    versions.forEach(function (version) {
        t.ok(cse.isSupportedVersion(version));
    });
    t.done();
});


test('encrypt() throws with missing options', function (t) {
    var input = new MemoryStream();

    t.throws(function () {
        cse.encrypt(null, input, function (err, res) {

        });
    }, /options \(object\) is required/);

    t.done();
});


test('encrypt() throws with unsupported cipher alg', function (t) {
    var options = {
        cse_key: 'FFFFFFFBD96783C6C91E222211112222',
        cse_cipher: 'AES/CFB/NoPadding'
    };
    var input = new MemoryStream();

    t.throws(function () {
        cse.encrypt(options, input, function (err, res) {

        });
    }, /Unsupported cipher algorithm/);

    t.done();
});

test('encrypt() throws with alg "toString"', function (t) {
    var options = {
        cse_key: 'FFFFFFFBD96783C6C91E222211112222',
        cse_cipher: 'toString'
    };
    var input = new MemoryStream();

    t.throws(function () {
        cse.encrypt(options, input, function (err, res) {

        });
    }, /Unsupported cipher algorithm/);

    t.done();
});

test('encrypt() throws with invalid key length', function (t) {
    var options = {
        cse_key: 'FFFFFF',
        cse_cipher: 'AES/CTR/NoPadding'
    };
    var input = new MemoryStream();

    t.throws(function () {
        cse.encrypt(options, input, function (err, res) {

        });
    }, /Invalid key length/);

    t.done();
});

test('encrypt() throws with invalid input', function (t) {
    var options = {
      cse_key: 'FFFFFFFBD96783C6C91E222211112222',
      cse_keyId: 'dev/test',
      cse_cipher: 'AES/CTR/NoPadding'
    };

    t.throws(function () {
        cse.encrypt(options, null, function (err, res) {

        });
    }, /input \(stream\) is required/);

    t.done();
});


test('decrypt() throws with missing options', function (t) {
    var input = new MemoryStream();

    t.throws(function () {
        cse.decrypt(null, input, { headers: {} }, function (err, res) {

        });
    }, /options \(object\) is required/);

    t.done();
});

test('decrypt() throws with missing options.cse_getKey', function (t) {
    var input = new MemoryStream();

    t.throws(function () {
        cse.decrypt({}, input, { headers: {} }, function (err, res) {

        });
    }, /options\.cse_getKey \(func\) is required/);

    t.done();
});

test('decrypt() throws with invalid input', function (t) {
    var options = {
        cse_getKey: function (keyId, cb) {
            cb();
        }
    };

    t.throws(function () {
        cse.decrypt(options, null, { headers: {} }, function (err, res) {

        });
    }, /encrypted \(stream\) is required/);

    t.done();
});
