keepass.js
==========

A JavaScript library for reading <a href="http://keepass.info/" target="_blank">KeePass</a> databases in the browser (writing KeePass files is to be implemented).

It uses the Web Cryptography API for high performance and is therefore only working in newer browser versions.

Compared to <a href="https://github.com/NeoXiD/" target="_blank">keepass.io</a>, this library is for the **browser**, keepass.io is written for Node.js which uses APIs that are only availabie in Node.js.

The keepass decryption algorithm is based on: https://github.com/perfectapi/CKP


## Running the tests

```
npm install
bower install
npm test
```
