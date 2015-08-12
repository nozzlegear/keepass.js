# keepass.js

[![Build Status](https://travis-ci.org/ulich/keepass.js.svg?branch=master)](https://travis-ci.org/ulich/keepass.js) [![devDependency Status](https://david-dm.org/ulich/keepass.js/dev-status.svg)](https://david-dm.org/ulich/keepass.js#info=devDependencies)

A JavaScript library for reading <a href="http://keepass.info/" target="_blank">KeePass</a> databases in the browser (writing KeePass files is to be implemented).

It uses the Web Cryptography API for high performance and is therefore only working in newer browser versions.

Compared to <a href="https://github.com/NeoXiD/" target="_blank">keepass.io</a>, this library is for the **browser**, keepass.io is written for Node.js which uses APIs that are only availabie in Node.js.

The keepass decryption algorithm is based on: https://github.com/perfectapi/CKP

## Usage

```
var keepass = new Keepass.Database();

keepass.getPasswords(fileAsArrayBuffer, password)
    .then(function (entries) {
        var entry = entries[0];
        console.log(entry.title);
        console.log(entry.userName);
        
        var password = keepass.decryptProtectedData(entry.protectedData.password, keepass.streamKey))
        console.log(password);
    });
```

## Building

You must have the following tools installed:

- node.js
- bower (npm install -g bower)
- tsd (npm install -g tsd)
- gulp-cli (npm install -g gulp-cli)

Now run
```
npm install
bower install
tsd install
gulp
```

For development, run `gulp watch` instead of `gulp` to automatically rebuild when changing the source code.


## Running the tests

```
npm test
```
