import parseHeader from "./parse-header.js";
import masterKey from "./master-key.js";
import parseKdb from "./parse-kdb.js";
import aesEcbEncrypt from "./aes-ecb-encrypt.js";
import * as util from "./util.js"

export class Database {

    getPasswords(buf, masterPassword, keyFile?) {
        let h = parseHeader(buf);
        if (!h) throw new Error('Failed to read file header');
        if (h.innerRandomStreamId != 2 && h.innerRandomStreamId != 0) throw new Error('Invalid Stream Key - Salsa20 is supported by this implementation, Arc4 and others not implemented.')

        let encData = new Uint8Array(buf, h.dataStart);
        //console.log("read file header ok.  encrypted data starts at byte " + h.dataStart);
        let SHA = {
            name: "SHA-256"
        };
        let AES = {
            name: "AES-CBC",
            iv: h.iv
        };

        return masterKey(h, masterPassword, keyFile).then((masterKey) => {
            //transform master key thousands of times
            return aesEcbEncrypt(h.transformSeed, masterKey, h.keyRounds);
        }).then(function(finalVal) {
            //do a final SHA-256 on the transformed key
            return window.crypto.subtle.digest({
                name: "SHA-256"
            }, finalVal);
        }).then(function(encMasterKey) {
            let finalKeySource = new Uint8Array(h.masterSeed.byteLength + 32);
            finalKeySource.set(h.masterSeed);
            finalKeySource.set(new Uint8Array(encMasterKey), h.masterSeed.byteLength);

            return window.crypto.subtle.digest(SHA, finalKeySource);
        }).then(function(finalKeyBeforeImport) {
            return window.crypto.subtle.importKey("raw", finalKeyBeforeImport, AES, false, ["decrypt"]);
        }).then(function(finalKey) {
            return window.crypto.subtle.decrypt(AES, finalKey, encData);
        }).then((decryptedData) => {
            //at this point we probably have successfully decrypted data, just need to double-check:
            if (h.kdbx) {
                //kdbx
                let storedStartBytes = new Uint8Array(decryptedData, 0, 32);
                for (let i = 0; i < 32; i++) {
                    if (storedStartBytes[i] != h.streamStartBytes[i]) {
                        throw new Error('Decryption succeeded but payload corrupt');
                        return;
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
                
                return this._decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                    let entries = this._parseXml(xml);
                    return entries; 
                });

            } else {
                return this._decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                    //kdb
                    let entries = parseKdb(decryptedData, streamKey, h);
                    return entries;
                });
            }
        });
    }

    /**
     * Returns the decrypted data from a protected element of a KDBX entry
     */
    decryptProtectedData(protectedData, streamKey) {
        if (protectedData === undefined) return "";  //can happen with entries with no password

        let iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
        let salsa = new Salsa20(new Uint8Array(streamKey || this.streamKey), iv);
        let decoder = new TextDecoder();

        salsa.getBytes(protectedData.position);
        let decryptedBytes = new Uint8Array(salsa.decrypt(protectedData.data));
        return decoder.decode(decryptedBytes);
    }

    _decryptStreamKey(protectedStreamKey) {
        return window.crypto.subtle.digest({
            name: "SHA-256"
        }, protectedStreamKey).then((streamKey) => {
            this.streamKey = streamKey;
            return streamKey; 
        });
    }

    /**
     * Parses the KDBX entries xml into an object format
     **/
    _parseXml(xml) {
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

                if (entry.groupName != "Recycle Bin")
                    results.push(entry);
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
}
