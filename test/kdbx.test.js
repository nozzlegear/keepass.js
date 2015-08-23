/// <reference path="../typings/tsd.d.ts" />

describe("kdbx", function () {
    it("should decrypt a kdbx file properly", function (done) {
        fetchArrayBuffer('base/test/data/database_simple.kdbx.dat').then(function (fileContents) {
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
                }, done.fail);
        }, done.fail);
    });
    
    it("should decrypt a kdbx file protected with xml keyfile properly", function (done) {
        Promise.all([
            fetchArrayBuffer('base/test/data/database_with_xml_keyfile.kdbx.dat'),
            fetchArrayBuffer('base/test/data/key_file_xml.dat')
        ])
        .then(function (results) {
            var fileContents = results[0];
            var keyFile = results[1];
            var keepass = new Keepass.Database();

            keepass.getPasswords(fileContents, "test", keyFile)
                .then(function (entries) {
                    expect(entries.length).toBe(1);

                    var entry = entries[0];
                    expect(entry.groupName).toBe("Root");
                    expect(entry.title).toBe("test_entry");
                    expect(entry.userName).toBe("test_username");
                    expect(keepass.decryptProtectedData(entry.protectedData.password, keepass.streamKey)).toBe("test_password");

                    done();
                }, done.fail);
        }, done.fail);
    });
    
    it("should decrypt a kdb file properly", function (done) {
        fetchArrayBuffer('base/test/data/database_simple.kdb.dat').then(function (fileContents) {
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
                }, done.fail);
        }, done.fail);
    });

    function fetchArrayBuffer(path) {
        return fetch(path)
            .then(function (response) {
                return response.arrayBuffer(); 
            });
    };
});
