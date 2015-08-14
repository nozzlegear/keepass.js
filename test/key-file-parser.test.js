/// <reference path="../typings/tsd.d.ts" />

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
        loadFile('base/test/data/key_file_empty.dat', function (fileContents) {
            new Keepass.KeyFileParser().getKeyFromFile(fileContents)
                .then(function (key) {
                    fail('The success callback should not be called');
                    done();
                })
                .catch(function (err) {
                    expect(err.message).toBe('key file has zero bytes');
                    done();
                });
        });
    });
    
    function testParseKeyfile(url, expectedKey, done) {
        loadFile(url, function (fileContents) {
            new Keepass.KeyFileParser().getKeyFromFile(fileContents)
                .then(function (key) {
                    var keyBase64 = btoa(Keepass.Util.ab2str(key));
                    expect(keyBase64).toBe(expectedKey);
                    done();
                });
        });
    }
            
    function loadFile(path, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', path);
        xhr.responseType = "arraybuffer";
        xhr.onload = function (e) {
            if (xhr.status == 200) {
                callback(xhr.response);   
            }
            else {
                throw new Error('Request to ' + path + " returned " + xhr.status);
            }
        };
        xhr.send();
    };
});
