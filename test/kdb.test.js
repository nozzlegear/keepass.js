import * as Keepass from "../src/keepass.js"
import { fetchArrayBuffer } from "./libs/test-utils.js";

describe("kdbx", () => {
    it("should decrypt a kdb file", (done) => {
        fetchArrayBuffer('base/test/data/database_with_password.kdb.dat').then((fileContents) => {
            var db = new Keepass.Database();

            return db.getPasswords(fileContents, "test")
                .then((entries) => {
                    expect(entries.length).toBe(1);

                    var entry = entries[0];
                    expect(entry.keys).toEqual([ 'title', 'url', 'userName', 'notes' ]);
                    expect(entry.groupName).toBe("test group");
                    expect(entry.title).toBe("test_entry");
                    expect(entry.userName).toBe("test_username");
                    expect(db.decryptProtectedData(entry.protectedData.password, db.streamKey)).toBe("test_password");

                    done();
                }, done.fail);
        }, done.fail);
    });
});
