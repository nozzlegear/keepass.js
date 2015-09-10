import * as Keepass from "../src/keepass.js"
import { fetchArrayBuffer } from "./libs/test-utils.js";

describe("keepass.js", () => {
    it("should decrypt a kdbx file protected with password", (done) => {
        fetchArrayBuffer('base/test/data/database_with_password.kdbx.dat').then((fileContents) => {
            decryptDatabaseAndVerify(done, fileContents, "test");
        }, done.fail);
    });

    it("should decrypt a kdbx file protected with keyfile", (done) => {
        Promise.all([
            fetchArrayBuffer('base/test/data/database_with_random_keyfile.kdbx.dat'),
            fetchArrayBuffer('base/test/data/key_file_random.dat')
        ])
        .then(([fileContents, keyFile]) => {
            decryptDatabaseAndVerify(done, fileContents, null, keyFile);
        }, done.fail);
    });
    
    it("should decrypt a kdbx file protected with password and keyfile", (done) => {
        Promise.all([
            fetchArrayBuffer('base/test/data/database_with_password_and_random_keyfile.kdbx.dat'),
            fetchArrayBuffer('base/test/data/key_file_random.dat')
        ])
        .then(([fileContents, keyFile]) => {
            decryptDatabaseAndVerify(done, fileContents, "test", keyFile);
        }, done.fail);
    });

    it("should decrypt an unprotected kdbx file", (done) => {
        fetchArrayBuffer('base/test/data/database_unprotected.kdbx.dat').then((fileContents) => {
            decryptDatabaseAndVerify(done, fileContents);
        }, done.fail);
    });

    it("should throw an error when reading a non database file", (done) => {
        fetchArrayBuffer('base/test/data/key_file_random.dat').then((fileContents) => {
            var db = new Keepass.Database();

            db.getPasswords(fileContents, "test").catch((msg) => {
                expect(msg).toBe('Invalid KeePass file - file signature is not correct. (ef5a43a6:a876235a)');
                done();
            });
        }, done.fail);
    });

    function decryptDatabaseAndVerify(done, fileContents, password, keyFile) {
        var db = new Keepass.Database();

        return db.getPasswords(fileContents, password, keyFile)
            .then((entries) => {
                expect(entries.length).toBe(1);

                var entry = entries[0];
                expect(entry.keys).toEqual(['tags', 'additionalFieldWithNoValue', 'additionalFieldWithValue', 'notes', 'title', 'url', 'userName', 'binaryFiles']);
                expect(entry.groupName).toBe("test group");
                expect(entry.title).toBe("test_entry");
                expect(entry.userName).toBe("test_username");
                expect(db.decryptProtectedData(entry.protectedData.password)).toBe("test_password");
                expect(entry.additionalFieldWithNoValue).toBe("");
                expect(entry.additionalFieldWithValue).toBe("some value with\nnewlines");
                expect(db.decryptProtectedData(entry.protectedData.additionalEncryptedFieldNoValue)).toBe("");
                expect(db.decryptProtectedData(entry.protectedData.additionalEncryptedFieldWithValue)).toBe("some encrypted value with\r\nnewlines");
                expect(entry.tags).toBe('keepass.js test');

                done();
            }, done.fail);
    }
});
