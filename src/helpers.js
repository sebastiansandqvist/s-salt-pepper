'use strict';

// ----- dependencies
// ---------------------------------------
var crypto = require('crypto');

// ----- exported object
// ---------------------------------------
var helpers = {};


// --------------------------------- methods ---------------------------------

// ----- encrypt strings
//		--	@param algorithm {string}
//		--	@param key {string}
//		--	@param text {string}
//		--	@return encrypted {string}
// ---------------------------------------
helpers._encrypt = function(algorithm, key, text) {

	var cipher = crypto.createCipher(algorithm, key);
	var encrypted = cipher.update(text, 'utf8', 'base64');
	
	encrypted += cipher.final('base64');
	
	return encrypted;

};


// ----- decrypt strings
//		--	@param algorithm {string}
//		--	@param key {string}
//		--	@param text {string}
//		--	@return decrypted {string}
// ---------------------------------------
helpers._decrypt = function(algorithm, key, encrypted) {

	var decipher = crypto.createDecipher('aes256', key);
	var decrypted = decipher.update(encrypted, 'base64', 'utf8');

	decrypted += decipher.final('utf8');

	return decrypted;

};


// ----- random number in range
//		--	@param min {number}
//		--	@param max {number}
//		--	@param fn {function}
//		--	@return fn(err, number)
// ---------------------------------------
helpers._random = function(min, max, fn) {

	if (typeof min !== 'number' || typeof max !== 'number') {
		return fn(new TypeError('numbers expected for min and max values of random number in range'));
	}
	
	if (min > max) {
		return fn(new Error('invalid min and max values for random number within range'));
	}

	var randomNumber = Math.floor(Math.random() *  (max - min + 1) + min);

	return fn(null, randomNumber);

};



// ----- unencrypted salt creation
//		--	@param iterations {number} pbkdf2 iterations concatenated to salt
//		--	@param len {number} length of salt before concatenation ^
//		--	@param fn {function} callback
//		--	@return callback(err, salt)
// ---------------------------------------
helpers._salt = function(iterations, len, fn) {

	crypto.randomBytes(len, function(err, randomBytes) {

		if (err) {
			return fn(err)
		}

		var salt = randomBytes
			.toString('base64')
			.substr(0, len) + iterations.toString();

		return fn(null, salt);

	});

};


// ----- retrieve iterations concatenated to salt
//		--	@param salt {string}
//		--	@param len {number}
// ---------------------------------------
helpers._getIterations = function(salt, len) {

	var iterations = salt.substr(len);
	return parseInt(iterations, 10);

};

module.exports = helpers;