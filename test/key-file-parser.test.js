import parseKeyFile from "../src/parse-key-file.js";
import { ab2str } from "../src/util.js";
import { fetchArrayBuffer } from "./libs/test-utils.js";

describe("key file parser", () => {
    it("should extract the key from an xml keyfile", (done) => {
        testParseKeyfile('base/test/data/key_file_xml.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a binary keyfile", (done) => {
        testParseKeyfile('base/test/data/key_file_binary.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a hex keyfile", (done) => {
        testParseKeyfile('base/test/data/key_file_hex.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a random keyfile", (done) => {
        // the random keyfile is 64 bytes long on purpose. It could have been longer, but like this it covers one more branch
        testParseKeyfile('base/test/data/key_file_random.dat', 'QHw3P28yrjhM2dl8ROi5lLt8wiNB4gwf0+K9wSIbM0k=', done);
    });
    
    it("should reject the promise if the keyfile is empty", (done) => {
        fetchArrayBuffer('base/test/data/key_file_empty.dat').then((fileContents) => {
            parseKeyFile(fileContents)
                .then((key) => {
                    fail('The success callback should not be called');
                    done();
                })
                .catch((err) => {
                    expect(err.message).toBe('key file has zero bytes');
                    done();
                });
        }, done.fail);
    });
    
    function testParseKeyfile(url, expectedKey, done) {
        fetchArrayBuffer(url).then((fileContents) => {
            parseKeyFile(fileContents)
                .then((key) => {
                    var keyBase64 = btoa(ab2str(key));
                    expect(keyBase64).toBe(expectedKey);
                    done();
                }, done.fail);
        }, done.fail);
    }
});
