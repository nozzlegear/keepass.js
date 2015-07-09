module Keepass {
    export class Util {
        public static littleEndian = (function() {
            var buffer = new ArrayBuffer(2);
            new DataView(buffer).setInt16(0, 256, true);
            return new Int16Array(buffer)[0] === 256;
        })();
        
        public static convertArrayToUUID(arr) {
            var int8Arr = new Uint8Array(arr);
            var result = new Array(int8Arr.byteLength * 2);
            for (var i = 0; i < int8Arr.byteLength; i++) {
                result[i * 2] = int8Arr[i].toString(16).toUpperCase();
            }
            return result.join("");
        }
    }
}