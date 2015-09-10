import masterKey from "./master-key.js";
import * as kdbx from "./kdbx.js";
import * as kdb from "./kdb.js";
import aesEcbEncrypt from "./aes-ecb-encrypt.js";
import { littleEndian } from "./util.js"

const DBSIG_KEEPASS = 0x9AA2D903;
const DBSIG_KDBX = 0xB54BFB67;
const DBSIG_KDBX_ALPHA = 0xB54BFB66;
const DBSIG_KDB = 0xB54BFB55;
const DBSIG_KDB_NEW = 0xB54BFB65;

const VALID_KEEPASS_TYPES = [DBSIG_KDBX, DBSIG_KDBX_ALPHA, DBSIG_KDB, DBSIG_KDB_NEW];

export class Database {

    getPasswords(buf, masterPassword, keyFile?) {
        try {
            var h = this._parseHeader(buf);
        }
        catch (e) {
            return Promise.reject(e.message);
        }

        let encData = new Uint8Array(buf, h.dataStart);
        let SHA = { name: "SHA-256" };
        let AES = { name: "AES-CBC", iv: h.iv };

        return masterKey(h, masterPassword, keyFile).then((masterKey) => {
            //transform master key thousands of times
            return aesEcbEncrypt(h.transformSeed, masterKey, h.keyRounds);
        }).then(function(finalVal) {
            //do a final SHA-256 on the transformed key
            return window.crypto.subtle.digest(SHA, finalVal);
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
            return this._decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                if (h.kdbx) {
                    return kdbx.parse(decryptedData, streamKey, h);
                }
                else {
                    return kdb.parse(decryptedData, streamKey, h);
                }
            });
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

    _parseHeader(buf) {
        let sigHeader = new DataView(buf, 0, 8);
        let h = {
            sigKeePass: sigHeader.getUint32(0, littleEndian),
            sigKeePassType: sigHeader.getUint32(4, littleEndian)
        };

        if (h.sigKeePass !== DBSIG_KEEPASS || VALID_KEEPASS_TYPES.indexOf(h.sigKeePassType) < 0) {
            throw new Error('Invalid KeePass file - file signature is not correct. ('
                + h.sigKeePass.toString(16) + ":" + h.sigKeePassType.toString(16) + ')');
        }

        if (h.sigKeePassType === DBSIG_KDBX || h.sigKeePassType === DBSIG_KDBX_ALPHA) {
            kdbx.readHeader(buf, 8, h);
        } else {
            kdb.readHeader(buf, 8, h);
        }

        if (h.innerRandomStreamId != 2 && h.innerRandomStreamId != 0) {
            throw new Error('Invalid Stream Key - Salsa20 is supported by this implementation, Arc4 and others not implemented.');
        }

        return h;
    }
}
