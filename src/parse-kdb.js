import { littleEndian, convertArrayToUUID } from "./util.js"

export default function parse(buf, streamKey, h) {
    
    let iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
    let salsa = new Salsa20(new Uint8Array(streamKey), iv);
    let salsaPosition = 0;

    let pos = 0;
    let dv = new DataView(buf);
    let groups = [];
    for (let i = 0; i < h.numberOfGroups; i++) {
        let fieldType = 0, fieldSize = 0;
        let currentGroup = {};
        let preventInfinite = 100;
        while (fieldType != 0xFFFF && preventInfinite > 0) {
            fieldType = dv.getUint16(pos, littleEndian);
            fieldSize = dv.getUint32(pos + 2, littleEndian);
            pos += 6;

            readGroupField(fieldType, fieldSize, buf, pos, currentGroup);
            pos += fieldSize;
            preventInfinite -= 1;
        }

        groups.push(currentGroup);
    }

    let entries = [];
    for (let i = 0; i < h.numberOfEntries; i++) {
        let fieldType = 0, fieldSize = 0;
        let currentEntry: any = { keys: [] };
        let preventInfinite = 100;
        while (fieldType != 0xFFFF && preventInfinite > 0) {
            fieldType = dv.getUint16(pos, littleEndian);
            fieldSize = dv.getUint32(pos + 2, littleEndian);
            pos += 6;

            readEntryField(fieldType, fieldSize, buf, pos, currentEntry);
            pos += fieldSize;
            preventInfinite -= 1;
        }

        //if (Case.constant(currentEntry.title) != "META_INFO") {
        //meta-info items are not actual password entries
        currentEntry.group = groups.filter((grp) => {
            return grp.id == currentEntry.groupId;
        })[0];
        currentEntry.groupName = currentEntry.group.name;

        //in-memory-protect the password in the same way as on KDBX
        if (currentEntry.password) {
            let encoder = new TextEncoder();
            let passwordBytes = encoder.encode(currentEntry.password);
            let encPassword = salsa.encrypt(new Uint8Array(passwordBytes));
            currentEntry.protectedData = {
                password: {
                    data: encPassword,
                    position: salsaPosition
                }
            };
            currentEntry.password = btoa(encPassword);  //not used - just for consistency with KDBX

            salsaPosition += passwordBytes.byteLength;
        }

        if (!(currentEntry.title == 'Meta-Info' && currentEntry.userName == 'SYSTEM')
            && (currentEntry.groupName != 'Backup')
            && (currentEntry.groupName != 'Search Results'))

            entries.push(currentEntry);
        //}
    }

    return entries;
}

//read KDB entry field
function readEntryField(fieldType, fieldSize, buf, pos, entry) {
    let dv = new DataView(buf, pos, fieldSize);
    let arr = new Uint8Array(0);
    if (fieldSize > 0) {
        arr = new Uint8Array(buf, pos, fieldSize - 1);
    }
    let decoder = new TextDecoder();

    switch (fieldType) {
        case 0x0000:
            // Ignore field
            break;
        case 0x0001:
            entry.id = convertArrayToUUID(new Uint8Array(buf, pos, fieldSize));
            break;
        case 0x0002:
            entry.groupId = dv.getUint32(0, littleEndian);
            break;
        case 0x0003:
            entry.iconId = dv.getUint32(0, littleEndian);
            break;
        case 0x0004:
            entry.title = decoder.decode(arr);
            entry.keys.push('title');
            break;
        case 0x0005:
            entry.url = decoder.decode(arr);
            entry.keys.push('url');
            break;
        case 0x0006:
            entry.userName = decoder.decode(arr);
            entry.keys.push('userName');
            break;
        case 0x0007:
            entry.password = decoder.decode(arr);
            break;
        case 0x0008:
            entry.notes = decoder.decode(arr);
            entry.keys.push('notes');
            break;
        /*
              case 0x0009:
            ent.tCreation = new PwDate(buf, offset);
            break;
              case 0x000A:
            ent.tLastMod = new PwDate(buf, offset);
            break;
              case 0x000B:
            ent.tLastAccess = new PwDate(buf, offset);
            break;
              case 0x000C:
            ent.tExpire = new PwDate(buf, offset);
            break;
              case 0x000D:
            ent.binaryDesc = Types.readCString(buf, offset);
            break;
              case 0x000E:
            ent.setBinaryData(buf, offset, fieldSize);
            break;
        */
    }
}

function readGroupField(fieldType, fieldSize, buf, pos, group) {
    let dv = new DataView(buf, pos, fieldSize);
    let arr = new Uint8Array(0);
    if (fieldSize > 0) {
        arr = new Uint8Array(buf, pos, fieldSize - 1);
    }

    switch (fieldType) {
        case 0x0000:
            // Ignore field
            break;
        case 0x0001:
            group.id = dv.getUint32(0, littleEndian);
            break;
        case 0x0002:
            let decoder = new TextDecoder();
            group.name = decoder.decode(arr);
            break;
        /*
        case 0x0009:
          group.flags = dv.getUint32(0, littleEndian);
          break; 
        */
        /*
        case 0x0003:
          group.tCreation = new PwDate(buf, offset);
          break;
        case 0x0004:
          group.tLastMod = new PwDate(buf, offset);
          break;
        case 0x0005:
          group.tLastAccess = new PwDate(buf, offset);
          break;
        case 0x0006:
          group.tExpire = new PwDate(buf, offset);
          break;
        case 0x0007:
          group.icon = db.iconFactory.getIcon(LEDataInputStream.readInt(buf, offset));
          break;
        case 0x0008:
          group.level = LEDataInputStream.readUShort(buf, offset);
          break;
        case 0x0009:
          group.flags = LEDataInputStream.readInt(buf, offset);
          break;
        */
    }
}
