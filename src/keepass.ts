/// <reference path="../typings/tsd.d.ts" />

declare var pako, Salsa20, Case: any;

module Keepass {
    export class Database {
        private headerParser = new HeaderParser();
        public streamKey;

        private getKey(h, masterPassword, fileKey) {
            var partPromises = [];
            var SHA = {
                name: "SHA-256"
            };

            if (masterPassword || !fileKey) {
                var encoder = new TextEncoder();
                var masterKey = encoder.encode(masterPassword);

                var p = window.crypto.subtle.digest(SHA, new Uint8Array(masterKey));
                partPromises.push(p);
            }

            if (fileKey) {
                partPromises.push(Promise.resolve(fileKey));
            }

            return Promise.all(partPromises).then(function(parts) {
                if (h.kdbx || partPromises.length > 1) {
                    //kdbx, or kdb with fileKey + masterPassword, do the SHA a second time
                    var compositeKeySource = new Uint8Array(32 * parts.length);
                    for (var i = 0; i < parts.length; i++) {
                        compositeKeySource.set(new Uint8Array(parts[i]), i * 32);
                    }

                    return window.crypto.subtle.digest(SHA, compositeKeySource);
                } else {
                    //kdb with just only fileKey or masterPassword (don't do a second SHA digest in this scenario)
                    return partPromises[0];
                }

            });
        }

        getPasswords(buf, masterPassword, keyFile) {
            var fileKey = keyFile ? atob(keyFile) : null;

            var h = this.headerParser.readHeader(buf);
            if (!h) throw new Error('Failed to read file header');
            if (h.innerRandomStreamId != 2 && h.innerRandomStreamId != 0) throw new Error('Invalid Stream Key - Salsa20 is supported by this implementation, Arc4 and others not implemented.')

            var encData = new Uint8Array(buf, h.dataStart);
            //console.log("read file header ok.  encrypted data starts at byte " + h.dataStart);
            var SHA = {
                name: "SHA-256"
            };
            var AES = {
                name: "AES-CBC",
                iv: h.iv
            };

            var compositeKeyPromise = this.getKey(h, masterPassword, fileKey);

            return compositeKeyPromise.then((masterKey) => {
                //transform master key thousands of times
                return this.aes_ecb_encrypt(h.transformSeed, masterKey, h.keyRounds);
            }).then(function(finalVal) {
                //do a final SHA-256 on the transformed key
                return window.crypto.subtle.digest({
                    name: "SHA-256"
                }, finalVal);
            }).then(function(encMasterKey) {
                var finalKeySource = new Uint8Array(h.masterSeed.byteLength + 32);
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
                    var storedStartBytes = new Uint8Array(decryptedData, 0, 32);
                    for (var i = 0; i < 32; i++) {
                        if (storedStartBytes[i] != h.streamStartBytes[i]) {
                            throw new Error('Decryption succeeded but payload corrupt');
                            return;
                        }
                    }

                    //ok, data decrypted, lets start parsing:
                    var done = false, pos = 32;
                    var blockArray = [], totalDataLength = 0;
                    while (!done) {
                        var blockHeader = new DataView(decryptedData, pos, 40);
                        var blockId = blockHeader.getUint32(0, Util.littleEndian);
                        var blockSize = blockHeader.getUint32(36, Util.littleEndian);
                        var blockHash = new Uint8Array(decryptedData, pos + 4, 32);

                        if (blockSize > 0) {
                            var block = new Uint8Array(decryptedData, pos + 40, blockSize);

                            blockArray.push(block);
                            totalDataLength += blockSize;
                            pos += blockSize + 40;
                        } else {
                            //final block is a zero block
                            done = true;
                        }
                    }

                    var allBlocks = new Uint8Array(totalDataLength);
                    pos = 0;
                    for (var i = 0; i < blockArray.length; i++) {
                        allBlocks.set(blockArray[i], pos);
                        pos += blockArray[i].byteLength;
                    }

                    if (h.compressionFlags == 1) {
                        allBlocks = pako.inflate(allBlocks);
                    }
                    var decoder = new TextDecoder();
                    var xml = decoder.decode(allBlocks);
                    
                    return this.decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                        var entries = this.parseXml(xml);
                        return entries; 
                    });

                } else {
                    return this.decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                        //kdb
                        var entries = new KdbParser().parse(decryptedData, streamKey, h);
                        return entries;
                    });
                }
            });
        }
        
        private decryptStreamKey(protectedStreamKey) {
            return window.crypto.subtle.digest({
                name: "SHA-256"
            }, protectedStreamKey).then((streamKey) => {
                this.streamKey = streamKey;
                return streamKey; 
            });
        }

        /**
         * Returns the decrypted data from a protected element of a KDBX entry
         */
        public decryptProtectedData(protectedData, streamKey) {
            if (protectedData === undefined) return "";  //can happen with entries with no password

            var iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
            var salsa = new Salsa20(new Uint8Array(streamKey || this.streamKey), iv);
            var decoder = new TextDecoder();

            salsa.getBytes(protectedData.position);
            var decryptedBytes = new Uint8Array(salsa.decrypt(protectedData.data));
            return decoder.decode(decryptedBytes);
        }

        /**
         * Parses the KDBX entries xml into an object format
         **/
        private parseXml(xml) {
            var decoder = new TextDecoder();
            var parser = new DOMParser();
            var doc = parser.parseFromString(xml, "text/xml");
            //console.log(doc);

            var results = [];
            var entryNodes = doc.evaluate('//Entry', doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
            var protectedPosition = 0;
            for (var i = 0; i < entryNodes.snapshotLength; i++) {
                var entryNode: any = entryNodes.snapshotItem(i);
                //console.log(entryNode);
                var entry: any = {
                    protectedData: {},
                    keys: []
                };

                //exclude histories and recycle bin:
                if (entryNode.parentNode.nodeName != "History") {
                    for (var m = 0; m < entryNode.parentNode.children.length; m++) {
                        var groupNode = entryNode.parentNode.children[m];
                        if (groupNode.nodeName == 'Name')
                            entry.groupName = groupNode.textContent;
                    }

                    if (entry.groupName != "Recycle Bin")
                        results.push(entry);
                }
                for (var j = 0; j < entryNode.children.length; j++) {
                    var childNode = entryNode.children[j];

                    if (childNode.nodeName == "UUID") {
                        entry.id = Util.convertArrayToUUID(Util.str2ab(atob(childNode.textContent)));
                    } else if (childNode.nodeName == "IconID") {
                        entry.iconId = Number(childNode.textContent);  //integer
                    } else if (childNode.nodeName == "Tags" && childNode.textContent) {
                        entry.tags = childNode.textContent;
                        entry.keys.push('tags');
                    } else if (childNode.nodeName == "Binary") {
                        entry.binaryFiles = childNode.textContent;
                        entry.keys.push('binaryFiles');  //the actual files are stored elsewhere in the xml, not sure where
                    } else if (childNode.nodeName == "String") {
                        var key = childNode.getElementsByTagName('Key')[0].textContent;
                        key = Case.camel(key);
                        var valNode = childNode.getElementsByTagName('Value')[0];
                        var val = valNode.textContent;
                        var protectedVal = valNode.hasAttribute('Protected');

                        if (protectedVal) {
                            var encBytes = new Uint8Array(Util.str2ab(atob(val)));
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

        private aes_ecb_encrypt(rawKey, data, rounds) {
            data = new Uint8Array(data);
            //Simulate ECB encryption by using IV of the data.
            var blockCount = data.byteLength / 16;
            var blockPromises = new Array(blockCount);
            for (var i = 0; i < blockCount; i++) {
                var block = data.subarray(i * 16, i * 16 + 16);
                blockPromises[i] = ((iv) => {
                    return this.aes_cbc_rounds(iv, rawKey, rounds);
                })(block);
            }
            return Promise.all(blockPromises).then(function(blocks) {
                //we now have the blocks, so chain them back together
                var result = new Uint8Array(data.byteLength);
                for (var i = 0; i < blockCount; i++) {
                    result.set(blocks[i], i * 16);
                }
                return result;
            });
        }

        /*
        * Performs rounds of CBC encryption on data using rawKey
        */
        private aes_cbc_rounds(data, rawKey, rounds) {
            if (rounds == 0) {
                //just pass back the current value
                return data;
            } else if (rounds > 0xFFFF) {
                //limit memory use to avoid chrome crash:
                return this.aes_cbc_rounds_single(data, rawKey, 0xFFFF).then((result) => {
                    return this.aes_cbc_rounds(result, rawKey, rounds - 0xFFFF);
                });
            } else {
                //last iteration, or only iteration if original rounds was low:
                return this.aes_cbc_rounds_single(data, rawKey, rounds);
            }
        }

        private aes_cbc_rounds_single(data, rawKey, rounds) {
            var AES = {
                name: "AES-CBC",
                iv: data
            };
            return window.crypto.subtle.importKey("raw", rawKey, AES, false, ["encrypt"]).then(function(secureKey) {
                var fakeData = new Uint8Array(rounds * 16);
                return window.crypto.subtle.encrypt(AES, secureKey, fakeData);
            }).then(function(result) {
                return new Uint8Array(result, (rounds - 1) * 16, 16);
            });
        }
    }
}