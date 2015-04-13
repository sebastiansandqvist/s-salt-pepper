'use strict';

// ----- dependencies
// ---------------------------------------
var crypto = require('crypto');
var helpers = require('./src/helpers.js');


// ----- exported object
// ---------------------------------------
var password = {};


// ----- defaults
// ---------------------------------------
password.defaults = {
	// ~ three fourths of actual hashLength
	// (see: http://stackoverflow.com/questions/13378815/base64-length-calculation)
	hashLength: 128, 
	iterations: [12000, 15000],
	key: 'ENCRYPTION KEY',
	unencryptedSaltMinLength: 32
};

// helper...
var toStr = Object.prototype.toString;


// ----- allow user to set config options
//		--	but restrict them to props in `password.defaults`
//		--	and make sure types are correct
// ---------------------------------------
password.configure = function(obj) {

	for (var prop in obj) {
		if (obj.hasOwnProperty(prop) && password.defaults.hasOwnProperty(prop)) {
			if (toStr.call(obj[prop]) !== toStr.call(password.defaults[prop])) {
				throw(new Error(prop + ' must be of type ' + typeof password.defaults[prop]));
			}
			password[prop] = obj[prop];
		}
	}

	return obj;

};


// ----- set defaults
// ---------------------------------------
password.configure(password.defaults);


// --------------------------------- methods ---------------------------------

// ----- hash password
//		--	@param input {string}
//		--	@param fn {function} callback
//		--	@return callback(err, salt, hash);
// ---------------------------------------
password.hash = function(input, fn) {


	if (toStr.call(input) !== '[object String]' || !input && toStr.call(fn) === '[object Function]') {
		return fn(new TypeError('invalid input for hash method'));
	}

	if (toStr.call(fn) !== '[object Function]' || toStr.call(input) !== '[object String]' || arguments.length !== 2) {
		throw(new TypeError('hash method takes two parameters: input and callback'));
	}

	helpers._random(password.iterations[0], password.iterations[1], function(err, iterations) {

		if (err) {
			return fn(err);
		}

		try {

			helpers._salt(iterations, password.unencryptedSaltMinLength, function(err, unencryptedSalt) {

				if (err) {
					return fn(err);
				}

				try {
					var salt = helpers._encrypt('aes256', password.key, unencryptedSalt);
				}
				catch(e) {
					return fn(e);
				}

				try {

					crypto.pbkdf2(input, salt, iterations, password.hashLength, function(err, hash) {

						if (err) {
							return fn(err);
						}

						return fn(null, salt, hash.toString('base64'));

					}); // end pbkdf2

				}
				catch(e) {
					return fn(e);
				}

			}); // end _salt

		} // end try
		catch(e) {
			return fn(e);
		}

	}); // end _random

}; // end hash



// ----- compare hashes
//		--	@param input {string}
//		--	@param salt {string}
//		--	@param fn {function} callback
//		--	@return callback(err, hash)
// ---------------------------------------
password.compare = function(input, salt, fn) {

	if (toStr.call(input) !== '[object String]' || !input && toStr.call(fn) === '[object Function]') {
		return fn(new TypeError('invalid input for compare method'));
	}

	if (toStr.call(salt) !== '[object String]' || !salt && toStr.call(fn) === '[object Function]') {
		return fn(new TypeError('invalid salt for compare method'));
	}

	if (toStr.call(fn) !== '[object Function]' || toStr.call(input) !== '[object String]' || toStr.call(salt) !== '[object String]' || arguments.length !== 3) {
		throw(new TypeError('compare method takes three parameters: input, salt, and callback'));
	}

	try {
		var decrypted = helpers._decrypt('aes256', password.key, salt);
		var iterations = helpers._getIterations(decrypted, password.unencryptedSaltMinLength);
		if (isNaN(iterations)) {
			return fn(new Error('could not get hash iterations'));
		}
	}
	catch(e) {
		return fn(e);
	}

	try {
		crypto.pbkdf2(input, salt, iterations, password.hashLength, function(err, hash) {

			if (err) {
				return fn(err);
			}

			return fn(null, hash.toString('base64'));

		});
	}
	catch(e) {
		return fn(e);
	}

};


module.exports = password;