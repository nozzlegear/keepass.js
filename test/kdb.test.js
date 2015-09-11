import * as kdb from "../src/kdb.js"
import { littleEndian } from "../src/util.js"

describe("kdb", () => {
    it("should throw an error when reading a header with an unsupported encryption type", () => {
        let arr = new Uint8Array(256);
        let h = {};

        expect(() => { kdb.readHeader(arr.buffer, h) }).toThrow(
            new Error('We only support AES (aka Rijndael) encryption on KeePass KDB files.  This file is using something else.'));
    });

    it("should ignore an entry with a field with type 0", () => {
        let h = {
            numberOfGroups: 1,
            numberOfEntries: 1
        };

        let arr = new Uint32Array(256);
        let dv = new DataView(arr.buffer);

        let pos = 0;
        // add one group: { id: 1, name: 'test' }
        pos = addEntry(pos, dv, 0x1, 0x4); // type: id, size: 4 bytes
        dv.setUint32(pos, 0x1, littleEndian); // value: groupId = 1
        pos += 4;

        pos = addEntry(pos, dv, 0x2, 0x2); // type: name, size: 2 bytes
        dv.setUint8(pos++, 0x67, littleEndian); // 'g'
        dv.setUint8(pos++, 0x00, littleEndian); // '\0'

        pos = addEntry(pos, dv, 0xFFFF, 0x0); // type: end marker

        // add one entry
        pos = addEntry(pos, dv, 0x2, 0x4); // type: groupId, size: 4 bytes
        dv.setUint32(pos, 0x1, littleEndian); // value: groupId = 1
        pos += 4;

        pos = addEntry(pos, dv, 0x4, 0x2); // type: title, size: 2 bytes
        dv.setUint8(pos++, 0x74, littleEndian); // 't'
        dv.setUint8(pos++, 0x0, littleEndian); // '\0'

        pos = addEntry(pos, dv, 0x0, 0x0); // next field; type: ignore, size: 0 bytes
        pos = addEntry(pos, dv, 0xFFFF, 0x0); // next field, type: end marker

        let entries = kdb.parse(arr.buffer, [], h);
        expect(entries).toEqual([{
            title: 't',
            groupName: 'g',
            groupId: 1,
            keys: ['title'],
            group: { id: 1, name: 'g' }
        }]);
    });

    function addEntry(pos, dv, fieldType, fieldSize) {
        dv.setUint16(pos, fieldType, littleEndian);
        dv.setUint32(pos + 2, fieldSize, littleEndian);
        return pos + 6;
    }

});
