# s-salt-pepper
[![NPM version](https://img.shields.io/npm/v/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Dependencies](https://img.shields.io/david/sebastiansandqvist/s-salt-pepper.svg) [![build status](http://img.shields.io/travis/sebastiansandqvist/s-salt-pepper.svg)](https://travis-ci.org/sebastiansandqvist/s-salt-pepper) [![NPM license](https://img.shields.io/npm/l/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Stability](https://img.shields.io/badge/stability-stable-green.svg)

## Password hashing and comparison
#### With salt and variable iterations of pbkdf2
* **Dependency-free**
* **Tested on node & iojs**
* **100% test coverage (`npm test`)**
	* Run `npm run coverage`
	* See etc/coverage.html

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
	key: 'my secret key',
	iterations: [12000, 13000]
});

// hash a string ('foo'), save returned salt and hash
password.hash('foo', function(err, salt, hash) {
	// in this example, save salt/hash to a user
	user.salt = salt;
	user.hash = hash;
});
```
Compare hashes when user logs in:
```javascript
password.compare('foo', user.salt, function(err, hash) {
	if(user.hash === hash) {
		// it worked, password 'foo' was correct
	}
});
```

## About
S-salt-pepper is based on [node-pwd](https://github.com/tj/node-pwd) and usage is almost identical. This improves upon node-pwd by also randomizing the number of iterations of pbkdf2 to run. The number of iterations is concatenated to the salt, then the salt is encrypted with AES256 (using the `key` set in `password.configure`).

## Config
**Important: you must set your own encryption key. Do not leave this to the default.**

The following are the most common options to change:
```javascript
password.configure({
	key: 'MY ENCRYPTION KEY', // can include symbols
	iterations: [12000, 15000] // range of values for pbkdf2 iterations
});
```
In the iterations array, `iterations[0]` is the minimum number of iterations of pbkdf2 to run, and `iterations[1]` is the maximum number. The actual number of iterations will vary randomly between those values per-user. If the hashing function is running too quickly, you can make it more secure by increasing the number of iterations in the range. Note that the range should not differ too significantly, or some users will be able to authenticate very quickly while others will not.

You can also change the hashLength (note: this is before base64 conversion, so it will be about 3/4 of the final length) and the salt length before it is concatenated to the iteration count and encrypted. Increasing these will increase the time it takes to hash and compare passwords.
```javascript
password.configure({
	hashLength: 128,
	unencryptedSaltMinLength: 32
});
```

## License
Copyright (c) 2015, Sebastian Sandqvist <s.github@sparque.me>

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.