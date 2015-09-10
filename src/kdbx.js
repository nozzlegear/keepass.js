import * as util from "./util.js"

export function readHeader(buf, h) {
    let position = 8;
    try {
        let version = new DataView(buf, position, 4);
        h.majorVersion = version.getUint16(0, util.littleEndian);
        h.minorVersion = version.getUint16(2, util.littleEndian);
        position += 4;

        let done = false;
        while (!done) {
            [done, position] = readHeaderField(buf, position, h);
        }

        h.kdbx = true;
        h.dataStart = position;
    } catch (err) {
        throw new Error('Failed to parse KDBX file header - file is corrupt or format not supported');
    }
}

export function parse(decryptedData, streamKey, h) {
    //at this point we probably have successfully decrypted data, just need to double-check:

    let storedStartBytes = new Uint8Array(decryptedData, 0, 32);
    for (let i = 0; i < 32; i++) {
        if (storedStartBytes[i] != h.streamStartBytes[i]) {
            throw new Error('Decryption succeeded but payload corrupt');
        }
    }

    //ok, data decrypted, lets start parsing:
    let done = false, pos = 32;
    let blockArray = [], totalDataLength = 0;
    while (!done) {
        let blockHeader = new DataView(decryptedData, pos, 40);
        let blockId = blockHeader.getUint32(0, util.littleEndian);
        let blockSize = blockHeader.getUint32(36, util.littleEndian);
        let blockHash = new Uint8Array(decryptedData, pos + 4, 32);

        if (blockSize > 0) {
            let block = new Uint8Array(decryptedData, pos + 40, blockSize);

            blockArray.push(block);
            totalDataLength += blockSize;
            pos += blockSize + 40;
        } else {
            //final block is a zero block
            done = true;
        }
    }

    let allBlocks = new Uint8Array(totalDataLength);
    pos = 0;
    for (let block of blockArray) {
        allBlocks.set(block, pos);
        pos += block.byteLength;
    }

    if (h.compressionFlags == 1) {
        allBlocks = pako.inflate(allBlocks);
    }
    let decoder = new TextDecoder();
    let xml = decoder.decode(allBlocks);
    return parseXml(xml);
}

function readHeaderField(buf, position, h) {
    let done = false;
    let descriptor = new DataView(buf, position, 3);
    let fieldId = descriptor.getUint8(0);
    let len = descriptor.getUint16(1, util.littleEndian);

    let dv = new DataView(buf, position + 3, len);
    //console.log("fieldid " + fieldId + " found at " + position);
    position += 3;
    switch (fieldId) {
        case 0: //end of header
            done = true;
            break;
        case 2: //cipherid, 16 bytes
            h.cipher = new Uint8Array(buf, position, len);
            break;
        case 3: //compression flags, 4 bytes
            h.compressionFlags = dv.getUint32(0, util.littleEndian);
            break;
        case 4: //master seed
            h.masterSeed = new Uint8Array(buf, position, len);
            break;
        case 5: //transform seed
            h.transformSeed = new Uint8Array(buf, position, len);
            break;
        case 6: //transform rounds, 8 bytes
            h.keyRounds = dv.getUint32(0, util.littleEndian);
            h.keyRounds2 = dv.getUint32(4, util.littleEndian);
            break;
        case 7: //iv
            h.iv = new Uint8Array(buf, position, len);
            break;
        case 8: //protected stream key
            h.protectedStreamKey = new Uint8Array(buf, position, len);
            break;
        case 9:
            h.streamStartBytes = new Uint8Array(buf, position, len);
            break;
        case 10:
            h.innerRandomStreamId = dv.getUint32(0, util.littleEndian);
            break;
        default:
            break;
    }

    position += len;
    return [done, position];
}

/**
 * Parses the KDBX entries xml into an object format
 **/
function parseXml(xml) {
    let decoder = new TextDecoder();
    let parser = new DOMParser();
    let doc = parser.parseFromString(xml, "text/xml");
    //console.log(doc);

    let results = [];
    let entryNodes = doc.evaluate('//Entry', doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
    let protectedPosition = 0;
    for (let i = 0; i < entryNodes.snapshotLength; i++) {
        let entryNode: any = entryNodes.snapshotItem(i);
        //console.log(entryNode);
        let entry: any = {
            protectedData: {},
            keys: []
        };

        //exclude histories and recycle bin:
        if (entryNode.parentNode.nodeName != "History") {
            for (let m = 0; m < entryNode.parentNode.children.length; m++) {
                let groupNode = entryNode.parentNode.children[m];
                if (groupNode.nodeName == 'Name')
                    entry.groupName = groupNode.textContent;
            }

            if (entry.groupName != "Recycle Bin") {
                results.push(entry);
            }
        }
        for (let j = 0; j < entryNode.children.length; j++) {
            let childNode = entryNode.children[j];

            if (childNode.nodeName == "UUID") {
                entry.id = util.convertArrayToUUID(util.str2ab(atob(childNode.textContent)));
            } else if (childNode.nodeName == "IconID") {
                entry.iconId = Number(childNode.textContent);  //integer
            } else if (childNode.nodeName == "Tags" && childNode.textContent) {
                entry.tags = childNode.textContent;
                entry.keys.push('tags');
            } else if (childNode.nodeName == "Binary") {
                entry.binaryFiles = childNode.textContent;
                entry.keys.push('binaryFiles');  //the actual files are stored elsewhere in the xml, not sure where
            } else if (childNode.nodeName == "String") {
                let key = childNode.getElementsByTagName('Key')[0].textContent;
                key = Case.camel(key);
                let valNode = childNode.getElementsByTagName('Value')[0];
                let val = valNode.textContent;
                let protectedVal = valNode.hasAttribute('Protected');

                if (protectedVal) {
                    let encBytes = new Uint8Array(util.str2ab(atob(val)));
                    entry.protectedData[key] = {
                        position: protectedPosition,
                        data: encBytes
                    };

                    protectedPosition += encBytes.length;
                } else {
                    entry.keys.push(key);
                }
                entry[key] = val;
            }
        }
    }

    //console.log(results);
    return results;
}