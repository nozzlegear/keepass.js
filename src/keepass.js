import parseHeader from "./parse-header.js";
import masterKey from "./master-key.js";
import parseKdbx from "./parse-kdbx.js";
import parseKdb from "./parse-kdb.js";
import aesEcbEncrypt from "./aes-ecb-encrypt.js";

export class Database {

    getPasswords(buf, masterPassword, keyFile?) {
        let h = parseHeader(buf);

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
            return this._decryptStreamKey(h.protectedStreamKey).then((streamKey) => {
                if (h.kdbx) {
                    return parseKdbx(decryptedData, streamKey, h);
                }
                else {
                    return parseKdb(decryptedData, streamKey, h);
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
}
