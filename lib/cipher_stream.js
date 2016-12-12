// Copyright (c) 2017 Joyent, Inc.  All rights reserved.

var util = require('util');
var stream = require('stream');


// Takes cipher + hmac digest stream of data and untangles the two
function CipherStream(hmacType, contentLength, options) {
    this._offset = calcOffset(hmacType, contentLength);
    this._digest = new Buffer('');
    this._bytesRead = 0;
    this._contentLength = contentLength;

    stream.Transform.call(this, options);
}
util.inherits(CipherStream, stream.Transform);


// Pass the chunks through until you have reached the offset for the hmac
// After the offset is reached, store the chunks in the _digest variable
CipherStream.prototype._transform =
    function _transform(chunk, encoding, callback) {

    var chunkSize = Buffer.byteLength(chunk);

    // Check if we have reached the offset
    if ((chunkSize + this._bytesRead) <= this._offset) {
        this._bytesRead += chunkSize;
        callback(null, chunk);
        return;
    }

    // Get number of bytes to read from the chunk into the cipher stream
    var bytesForCipher = this._offset - this._bytesRead;
    this._bytesRead += chunkSize;

    if (bytesForCipher > 0) {
        var cipher = chunk.slice(0, bytesForCipher);
        var hmac = chunk.slice(this._offset);
        this._digest = Buffer.concat([this._digest, hmac]);

        callback(null, cipher);
        return;
    }

    this._digest = Buffer.concat([this._digest, chunk]);

    // Mark the stream as processed
    if (this._bytesRead === this._contentLength) {
        this.push(null);
    }

    callback();
};


CipherStream.prototype.digest = function digest() {
    return (this._digest);
};


module.exports = CipherStream;


function calcOffset(hmacType, contentLength) {
    hmacType = hmacType.toLowerCase();
    if (hmacType === 'sha256') {
        return (contentLength - 44);
    }

    return (contentLength);
}
