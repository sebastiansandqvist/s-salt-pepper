'use strict';

// ----- dependencies
// ---------------------------------------
var crypto = require('crypto');


// ----- exported object
// ---------------------------------------
var password = {};


// ----- defaults
// ---------------------------------------
password.defaults = {
	// ~ three fourths of actual hashLength
	// (see: http://stackoverflow.com/questions/13378815/base64-length-calculation)
	hashLength: 256, 
	saltLength: 128,
	iterations: 15000,
	pepper: 'THIS SHOULD BE RANDOM AND KEPT SECRET'
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

	try {
		var salt = crypto.randomBytes(password.saltLength).toString('base64');
	}
	catch(e) {
		return fn(e);
	}

	var peppered = password.pepper + salt;

	try {
		var hash = crypto.pbkdf2Sync(input, peppered, password.iterations, password.hashLength);
		return fn(null, salt, hash.toString('base64'));
	}
	catch(e) {
		return fn(e);
	}

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
		salt = password.pepper + salt;
		var hash = crypto.pbkdf2Sync(input, salt, password.iterations, password.hashLength);
		return fn(null, hash.toString('base64'));
	}
	catch(e) {
		return fn(e);
	}

};


module.exports = password;