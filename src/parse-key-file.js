import * as util from "./util.js";

/**
* Parses a KeePass key file
*/
export default function parse(arr) {
    if (arr.byteLength == 0) {
        return Promise.reject(new Error('key file has zero bytes'));
    } else if (arr.byteLength == 32) {
        //file content is the key
        return Promise.resolve(arr);
    } else if (arr.byteLength == 64) {
        //file content may be a hex string of the key
        let decoder = new TextDecoder();
        let hexString = decoder.decode(arr);
        let newArr = util.hex2arr(hexString);
        if (newArr.length == 32) {
            return Promise.resolve(newArr);
        }
        // continue, no valid hex file
    }

    //attempt to parse xml
    try {
        let decoder = new TextDecoder();
        let xml = decoder.decode(arr);
        let parser = new DOMParser();
        let doc = parser.parseFromString(xml, "text/xml");
        let keyNode = doc.evaluate('//KeyFile/Key/Data', doc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
        if (keyNode.singleNodeValue && keyNode.singleNodeValue.textContent) {
            return Promise.resolve(util.str2ab(atob(keyNode.singleNodeValue.textContent)));
        }
    } catch (err) {
        //continue, not valid xml keyfile
    }

    // finally just create a sha256 hash from the file contents
    return window.crypto.subtle.digest({ name: "SHA-256" }, arr);
}
