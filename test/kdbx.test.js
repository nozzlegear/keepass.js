describe("kdbx", function () {
    it("should decrypt properly", function (done) {
        var result;

        loadFile('base/test/data/000_example.kdbx.dat', function (response) {
            var credentials = [readPassword("test")];
            var dataView = new jDataView(response, 0, response.byteLength, true);

            result = readKeePassFile(dataView, credentials);
            
            expect(result.length).toBe(1);
            expect(result[0].Title).toBe("test_entry");
            expect(result[0].Password).toBe("test_password");
            expect(result[0].UserName).toBe("test_username");

            done();
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
