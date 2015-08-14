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
        
        /**
         * Converts the given ArrayBuffer to a binary string
         */
        public static ab2str(arr): String {
            var binary = '';
            var bytes = new Uint8Array(arr);
            for (var i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return binary;
        }
        
        /**
         * Converts the given binaryString to an ArrayBuffer
         */
        public static str2ab(binaryString: String): ArrayBuffer {
            var len = binaryString.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++)        {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        public static hex2arr(hex: string) {
            if (hex.length % 2 != 0 || !/^[0-9A-Fa-f]+$/.test(hex)) {
                return [];
            }
            
            var arr = [];
            for (var i = 0; i < hex.length; i += 2)
                arr.push(parseInt(hex.substr(i, 2), 16));
            return arr;
        }
    }
}