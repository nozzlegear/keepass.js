export default function aesEcbEncrypt(rawKey, data, rounds) {
    data = new Uint8Array(data);
    //Simulate ECB encryption by using IV of the data.
    let blockCount = data.byteLength / 16;
    let blockPromises = new Array(blockCount);
    for (let i = 0; i < blockCount; i++) {
        let block = data.subarray(i * 16, i * 16 + 16);
        blockPromises[i] = _aesEcbRounds(block, rawKey, rounds);
    }
    return Promise.all(blockPromises).then((blocks) => {
        //we now have the blocks, so chain them back together
        let result = new Uint8Array(data.byteLength);
        for (let i = 0; i < blockCount; i++) {
            result.set(blocks[i], i * 16);
        }
        return result;
    });
}

/*
* Performs rounds of CBC encryption on data using rawKey
*/
function _aesEcbRounds(data, rawKey, rounds) {
    if (rounds === 0) {
        //just pass back the current value
        return data;
    } else if (rounds > 0xFFFF) {
        //limit memory use to avoid chrome crash:
        return _aesEcbRoundsSingle(data, rawKey, 0xFFFF).then((result) => {
            return _aesEcbRounds(result, rawKey, rounds - 0xFFFF);
        });
    } else {
        //last iteration, or only iteration if original rounds was low:
        return _aesEcbRoundsSingle(data, rawKey, rounds);
    }
}

function _aesEcbRoundsSingle(data, rawKey, rounds) {
    let AES = {
        name: "AES-CBC",
        iv: data
    };
    return window.crypto.subtle.importKey("raw", rawKey, AES, false, ["encrypt"]).then((secureKey) => {
        let fakeData = new Uint8Array(rounds * 16);
        return window.crypto.subtle.encrypt(AES, secureKey, fakeData);
    }).then(function(result) {
        return new Uint8Array(result, (rounds - 1) * 16, 16);
    });
}