import parseKeyFile from "./parse-key-file.js";

/**
 * Infers the master key from the master password and additionally from a keyfile
 */
 export default function inferMasterKey(h, masterPassword, keyFile?) {
    if (keyFile) {
        return parseKeyFile(keyFile).then((key) => {
            return infer(h, masterPassword, key);
        });
    }
    else {
        return infer(h, masterPassword);
    }
}
    
function infer(h, masterPassword, fileKey?) {
    let partPromises = [];
    let SHA = {
        name: "SHA-256"
    };

    if (masterPassword || !fileKey) {
        let encoder = new TextEncoder();
        let masterKey = encoder.encode(masterPassword);

        let p = window.crypto.subtle.digest(SHA, new Uint8Array(masterKey));
        partPromises.push(p);
    }

    if (fileKey) {
        partPromises.push(Promise.resolve(fileKey));
    }

    return Promise.all(partPromises).then(function(parts) {
        if (h.kdbx || partPromises.length > 1) {
            //kdbx, or kdb with fileKey + masterPassword, do the SHA a second time
            let compositeKeySource = new Uint8Array(32 * parts.length);
            for (let i = 0; i < parts.length; i++) {
                compositeKeySource.set(new Uint8Array(parts[i]), i * 32);
            }

            return window.crypto.subtle.digest(SHA, compositeKeySource);
        } else {
            //kdb with just only fileKey or masterPassword (don't do a second SHA digest in this scenario)
            return partPromises[0];
        }

    });
}
