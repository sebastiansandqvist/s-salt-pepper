# s-salt-pepper
[![NPM version](https://img.shields.io/npm/v/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Dependencies](https://img.shields.io/david/sebastiansandqvist/s-salt-pepper.svg) [![build status](http://img.shields.io/travis/sebastiansandqvist/s-salt-pepper.svg)](https://travis-ci.org/sebastiansandqvist/s-salt-pepper) [![NPM license](https://img.shields.io/npm/l/s-salt-pepper.svg)](https://www.npmjs.com/package/s-salt-pepper) ![Stability](https://img.shields.io/badge/stability-stable-green.svg) [![Test Coverage](https://codeclimate.com/github/sebastiansandqvist/s-salt-pepper/badges/coverage.svg)](https://codeclimate.com/github/sebastiansandqvist/s-salt-pepper)

## About
This dependency-free module provides password hashing and comparison with salt and variable iterations of pbkdf2. Additional "pepper" (optional) is concatenated to the salt before hashing. The salts are kept in your database, the pepper is saved on your server.

## Installation
```bash
npm install s-salt-pepper
```

## Usage
1. Generate a password hash with a salt (for example, when a user signs up) using `password.hash()`
2. Whenever the user logs in or needs to verify their password, compare the provided login password with the user's saved salt and hash using `password.compare()`

```js
const password = require('s-salt-pepper');

// configure once
password.iterations(75000); // optionally set number of pbkdf2 iterations
password.pepper('your random string goes here');

// hash a string and save returned salt and hash to (fake) user
const user = {
  password: {
    hash: null,
    salt: null
  }
};

async () => {
  // set the user's password to { hash: String, salt: String }
  user.password = await password.hash('foo');

  // ...later, verify that a given string matches the user's password data
  await password.compare('bar', user.password); // false
  await password.compare('foo', user.password); // true
}
```

## API
#### `async password.hash(String)`
Accepts a string password argument, returns a promise that resolves to an object of the shape:
```js
{
  hash: String,
  salt: String
}
```

#### `async password.compare(String, { hash: String, salt: String })`
Accepts a string password as the first argument and an object like the one given by `password.hash()` as the second argument. Returns a promise that resolves to `true` if the password is a match, `false` otherwise.

#### `password.saltLength(Number?)`
Returns the salt length if called without any arguments. Sets the salt length (in bytes, before base64 conversion) if called with one argument.

#### `password.iterations(Number?)`
Returns the number of pbkdf2 iterations to run if called without any arguments. Sets the number of pbkdf2 iterations if called with one argument.

#### `password.keyLength(Number?)`
Returns the pbkdf2 key length if called without any arguments. Sets the key length (in bytes, before base64 conversion) if called with one argument.

#### `password.digest(String?)`
Returns the pbkdf2 digest algorithm if called without any arguments. Sets the digest algorithm if called with one argument.

#### `password.pepper(String?)`
Returns the pepper if called without any arguments. Sets the pepper if called with one argument.

## Config options
The following can be configured (defaults displayed below):
```js
password.saltLength(32);
password.iterations(100000); // ~200ms to compute with current key/salt lengths
password.keyLength(128);
password.digest('sha512');
password.pepper('');
```

Calling those functions without any arguments returns their current value.
```js
password.saltLength(); // => 32
```
