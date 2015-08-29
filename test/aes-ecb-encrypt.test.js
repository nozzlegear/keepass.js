import aesEcbEncrypt from "../src/aes-ecb-encrypt.js";

describe('aes ecb encrypt', () => {
    it("should encrypt with one round properly", (done) => {
        let key = new Uint8Array(32);
        let data = new Uint8Array(32);
        let expectedEncryptionResult = new Uint8Array([
            0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
            0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
        ]);

        aesEcbEncrypt(key, data, 1).then((encrypted) => {
            expectArrayBuffersToBeEqual(encrypted, expectedEncryptionResult);
            done();
        });
    });

    it("should encrypt with two rounds properly", (done) => {
        let key = new Uint8Array(32);
        let data = new Uint8Array(32);
        let expectedEncryptionResult = new Uint8Array([
            0x08, 0xc3, 0x74, 0x84, 0x8c, 0x22, 0x82, 0x33, 0xc2, 0xb3, 0x4f, 0x33, 0x2b, 0xd2, 0xe9, 0xd3,
            0x08, 0xc3, 0x74, 0x84, 0x8c, 0x22, 0x82, 0x33, 0xc2, 0xb3, 0x4f, 0x33, 0x2b, 0xd2, 0xe9, 0xd3
        ]);
        
        aesEcbEncrypt(key, data, 2).then((encrypted) => {
            expectArrayBuffersToBeEqual(encrypted, expectedEncryptionResult);
            done();
        });
    });

    it("should encrypt with 0x10000 rounds properly", (done) => {
        let key = new Uint8Array(32);
        let data = new Uint8Array(32);
        let expectedEncryptionResult = new Uint8Array([
            0x7e, 0x69, 0x75, 0xaf, 0x91, 0x3f, 0xe4, 0x18, 0x21, 0xc7, 0x92, 0x51, 0x2b, 0x82, 0x79, 0xf8,
            0x7e, 0x69, 0x75, 0xaf, 0x91, 0x3f, 0xe4, 0x18, 0x21, 0xc7, 0x92, 0x51, 0x2b, 0x82, 0x79, 0xf8
        ]);
        
        aesEcbEncrypt(key, data, 0x10000).then((encrypted) => {
            expectArrayBuffersToBeEqual(encrypted, expectedEncryptionResult);
            done();
        });
    });

    it("should not encrypt anything if rounds is 0", (done) => {
        let data = new Uint8Array(32);
        aesEcbEncrypt(null, data, 0).then((encrypted) => {
            expectArrayBuffersToBeEqual(encrypted, data);
            done();
        });
    });

    function expectArrayBuffersToBeEqual (actual, expected) {
        expect(actual.byteLength).toBe(32);
        let actualIt = actual.values();
        for (let expectedValue of expected.values()) {
            expect(actualIt.next().value).toBe(expectedValue);
        }
    }
});
