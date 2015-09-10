import * as util from "./util.js"

export default function parseKdbx(decryptedData, streamKey, h) {
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