import { getKeyFromFile } from "../src/key-file-parser.js";

describe("key file parser", function () {
    it("should extract the key from an xml keyfile", function (done) {
        testParseKeyfile('base/test/data/key_file_xml.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a binary keyfile", function (done) {
        testParseKeyfile('base/test/data/key_file_binary.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a hex keyfile", function (done) {
        testParseKeyfile('base/test/data/key_file_hex.dat', 'VRW2tloCaiwQ16Atdnlv5uyB1YH4Zfve4/G0buFz45A=', done);
    });
    
    it("should extract the key from a random keyfile", function (done) {
        // the random keyfile is 64 bytes long on purpose. It could have been longer, but like this it covers one more branch
        testParseKeyfile('base/test/data/key_file_random.dat', 'QHw3P28yrjhM2dl8ROi5lLt8wiNB4gwf0+K9wSIbM0k=', done);
    });
    
    it("should reject the promise if the keyfile is empty", function (done) {
        fetchArrayBuffer('base/test/data/key_file_empty.dat').then(function (fileContents) {
            getKeyFromFile(fileContents)
                .then(function (key) {
                    fail('The success callback should not be called');
                    done();
                })
                .catch(function (err) {
                    expect(err.message).toBe('key file has zero bytes');
                    done();
                });
        }, done.fail);
    });
    
    function testParseKeyfile(url, expectedKey, done) {
        fetchArrayBuffer(url).then(function (fileContents) {
            getKeyFromFile(fileContents)
                .then(function (key) {
                    var keyBase64 = btoa(ab2str(key));
                    expect(keyBase64).toBe(expectedKey);
                    done();
                }, done.fail);
        }, done.fail);
    }
            
    function fetchArrayBuffer(path) {
        return fetch(path)
            .then(function (response) {
                return response.arrayBuffer(); 
            });
    };

    // TODO: Use function from util
    function ab2str(arr) {
        var binary = '';
        var bytes = new Uint8Array(arr);
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return binary;
    }
});
