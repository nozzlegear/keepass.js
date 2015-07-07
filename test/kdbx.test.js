describe("kdbx", function () {
    it("should decrypt properly", function (done) {
        var result;

        loadFile('base/test/data/000_example.kdbx.dat', function (fileContents) {
            var keepass = new Keepass.Database();

            keepass.getPasswords(fileContents, "test")
                .then(function (entries) {
                    expect(entries.length).toBe(1);

                    var entry = entries[0];
                    expect(entry.title).toBe("test_entry");
                    expect(entry.userName).toBe("test_username");
                    expect(keepass.getDecryptedEntry(entry.protectedData.password, keepass.streamKey)).toBe("test_password");

                    done();
                });
        });
    });

    function loadFile(path, callback) {
        var req = new XMLHttpRequest();
        req.open('GET', path);
        req.responseType = "arraybuffer";
        req.onload = function (e) {
            callback(req.response);
        };
        req.send();
    };
});
