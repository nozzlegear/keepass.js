/// <reference path="../typings/tsd.d.ts" />

describe("kdbx", function () {
    it("should decrypt a kdbx file properly", function (done) {
        loadFile('base/test/data/000_example.kdbx.dat', function (fileContents) {
            var keepass = new Keepass.Database();

            keepass.getPasswords(fileContents, "test")
                .then(function (entries) {
                    expect(entries.length).toBe(1);

                    var entry = entries[0];
                    expect(entry.groupName).toBe("Root");
                    expect(entry.title).toBe("test_entry");
                    expect(entry.userName).toBe("test_username");
                    expect(keepass.decryptProtectedData(entry.protectedData.password, keepass.streamKey)).toBe("test_password");

                    done();
                });
        });
    });
    
    it("should decrypt a kdb file properly", function (done) {
         loadFile('base/test/data/001_example.kdb.dat', function (fileContents) {
            var keepass = new Keepass.Database();

            keepass.getPasswords(fileContents, "test")
                .then(function (entries) {
                    expect(entries.length).toBe(1);

                    var entry = entries[0];
                    expect(entry.groupName).toBe("test group");
                    expect(entry.title).toBe("test_entry");
                    expect(entry.userName).toBe("test_username");
                    expect(keepass.decryptProtectedData(entry.protectedData.password, keepass.streamKey)).toBe("test_password");

                    done();
                });
        });
    });

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
