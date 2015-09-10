import * as kdb from "../src/kdb.js"

describe("kdb", () => {
    it("should throw an error when reading a header with an unsupported encryption type", () => {
        let arr = new Uint8Array(256);
        let h = {};

        expect(() => { kdb.readHeader(arr.buffer, h) }).toThrow(
            new Error('We only support AES (aka Rijndael) encryption on KeePass KDB files.  This file is using something else.'));
    });
});
