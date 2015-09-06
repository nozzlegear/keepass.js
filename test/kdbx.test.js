import * as Keepass from "../src/keepass.js"
import { fetchArrayBuffer } from "./libs/test-utils.js";

describe("kdbx", () => {
    it("should decrypt a kdbx file properly", (done) => {
        fetchArrayBuffer('base/test/data/database_simple.kdbx.dat').then((fileContents) => {
            decryptDatabaseAndVerify(done, fileContents, "test");
        }, done.fail);
    });
    
    it("should decrypt a kdbx file protected with xml keyfile properly", (done) => {
        Promise.all([
            fetchArrayBuffer('base/test/data/database_with_xml_keyfile.kdbx.dat'),
            fetchArrayBuffer('base/test/data/key_file_xml.dat')
        ])
        .then(([fileContents, keyFile]) => {
            decryptDatabaseAndVerify(done, fileContents, "test", keyFile);
        }, done.fail);
    });

    it("should decrypt a kdbx file without password properly", (done) => {
        fetchArrayBuffer('base/test/data/database_without_password.kdbx.dat').then((fileContents) => {
            decryptDatabaseAndVerify(done, fileContents);
        }, done.fail);
    });
    
    it("should decrypt a kdb file properly", (done) => {
        fetchArrayBuffer('base/test/data/database_simple.kdb.dat').then((fileContents) => {
            decryptDatabaseAndVerify(done, fileContents, "test");
        }, done.fail);
    });

    function decryptDatabaseAndVerify(done, fileContents, password, keyFile) {
        var db = new Keepass.Database();

        db.getPasswords(fileContents, password, keyFile)
            .then((entries) => {
                expect(entries.length).toBe(1);

                var entry = entries[0];
                expect(entry.groupName).toBe("test group");
                expect(entry.title).toBe("test_entry");
                expect(entry.userName).toBe("test_username");
                expect(db.decryptProtectedData(entry.protectedData.password, db.streamKey)).toBe("test_password");

                done();
            }, done.fail);
    }
});
