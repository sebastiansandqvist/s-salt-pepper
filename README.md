# s-salt-pepper
[![NPM version](https://img.shields.io/npm/v/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Dependencies](https://img.shields.io/david/sebastiansandqvist/s-salt-pepper.svg) [![build status](http://img.shields.io/travis/sebastiansandqvist/s-salt-pepper.svg)](https://travis-ci.org/sebastiansandqvist/s-salt-pepper) [![NPM license](https://img.shields.io/npm/l/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Stability](https://img.shields.io/badge/stability-stable-green.svg) [![Test Coverage](https://codeclimate.com/github/sebastiansandqvist/s-salt-pepper/badges/coverage.svg)](https://codeclimate.com/github/sebastiansandqvist/s-salt-pepper)

## Password hashing and comparison
#### With salt and variable iterations of pbkdf2
* **Dependency-free**
* **Tested on node & iojs**

## Installation
```bash
npm install s-salt-pepper
```

## Usage
Generate a password hash with a salt when a user signs up:
```javascript
var password = require('s-salt-pepper');

// configure once
password.configure({
	pepper: 'your random string goes here'
});

// hash a string 'foo' and save returned salt and hash to (fake) user
password.hash('foo', function(err, salt, hash) {
	if (err) {
		// handle error
	}
	user.salt = salt;
	user.hash = hash;
});
```
Compare hashes when user logs in:
```javascript
password.compare('foo', user.salt, function(err, hash) {
	if (user.hash === hash) {
		// it worked, password 'foo' was correct
	}
});
```

## About
S-salt-pepper is based on [node-pwd](https://github.com/tj/node-pwd) and usage is almost identical. This is more secure in the case that the database is compromised, but not the server, as part of the salt (the pepper) is saved on the server.

## Config
**Important: you must set your own pepper. Do not leave this to the default.**

The following can be configured:
```javascript
password.configure({
	hashLength: 256, // bytes of pbkdf2 hash
	saltLength: 128, // number of random bytes for salt
	pepper: 'something secret' // your unique pepper, to be concatenated with salt when comparing passwords
});
```

You can configure the length of the final hash and salt `hashlength` and `saltLength` in bytes (before base64 conversion, roughly 3/4 of final length). The pepper is concatenated to to the salt then hashed.

## License
Copyright (c) 2015, Sebastian Sandqvist <s.github@sparque.me>

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.