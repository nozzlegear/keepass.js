
export const littleEndian = (function() {
    let buffer = new ArrayBuffer(2);
    new DataView(buffer).setInt16(0, 256, true);
    return new Int16Array(buffer)[0] === 256;
})();

export function convertArrayToUUID(arr) {
    let int8Arr = new Uint8Array(arr);
    let result = new Array(int8Arr.byteLength * 2);
    for (let i = 0; i < int8Arr.byteLength; i++) {
        result[i * 2] = int8Arr[i].toString(16).toUpperCase();
    }
    return result.join("");
}
    
/**
 * Converts the given ArrayBuffer to a binary string
 */
export function ab2str(arr) {
    let binary = '';
    let bytes = new Uint8Array(arr);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}
    
/**
 * Converts the given binaryString to an ArrayBuffer
 */
export function str2ab(binaryString) {
    let len = binaryString.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++)        {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

export function hex2arr(hex) {
    if (hex.length % 2 != 0 || !/^[0-9A-Fa-f]+$/.test(hex)) {
        return [];
    }
    
    let arr = [];
    for (let i = 0; i < hex.length; i += 2)
        arr.push(parseInt(hex.substr(i, 2), 16));
    return arr;
}
