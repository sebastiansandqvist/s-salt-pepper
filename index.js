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
function type(input) {
	var type = Object.prototype.toString.call(input);
	return type.replace('[object ', '').replace(']', '');
}

// ----- allow user to set config options
//		--	but restrict them to props in `password.defaults`
//		--	and make sure types are correct
// ---------------------------------------
password.configure = function(obj) {

	for (var prop in obj) {
		if (obj.hasOwnProperty(prop) && password.defaults.hasOwnProperty(prop)) {
			if (type(obj[prop]) !== type(password.defaults[prop])) {
				throw(new Error(prop + ' must be of type ' + type(password.defaults[prop])));
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


	if (type(input) !== 'String' || !input && type(fn) === 'Function') {
		return fn(new TypeError('invalid input for hash method'));
	}

	if (type(fn) !== 'Function' || type(input) !== 'String' || arguments.length !== 2) {
		throw(new TypeError('hash method takes two parameters: input and callback'));
	}

	if (!password.hashLength) {
		return fn(new TypeError('hashLength is required'));
	}

	crypto.randomBytes(password.saltLength, function(err, salt) {
		if (err) { return fn(err); }
		salt = salt.toString('base64');
		var peppered = password.pepper + salt;
		crypto.pbkdf2(input, peppered, password.iterations, password.hashLength, function(err, hash) {
			if (err) { return fn(err); }
			return fn(null, salt, hash.toString('base64'));
		});
	});

}; // end hash



// ----- compare hashes
//		--	@param input {string}
//		--	@param salt {string}
//		--	@param fn {function} callback
//		--	@return callback(err, hash)
// ---------------------------------------
password.compare = function(input, salt, fn) {

	if (type(input) !== 'String' || !input && type(fn) === 'Function') {
		return fn(new TypeError('invalid input for compare method'));
	}

	if (type(salt) !== 'String' || !salt && type(fn) === 'Function') {
		return fn(new TypeError('invalid salt for compare method'));
	}

	if (type(fn) !== 'Function' || type(input) !== 'String' || type(salt) !== 'String' || arguments.length !== 3) {
		throw(new TypeError('compare method takes three parameters: input, salt, and callback'));
	}
	
	if (!password.hashLength) {
		return fn(new TypeError('hashLength is required'));
	}

	salt = password.pepper + salt;

	crypto.pbkdf2(input, salt, password.iterations, password.hashLength, function(err, hash) {
		if (err) { return fn(err); }
		return fn(null, hash.toString('base64'));	
	});
	

};


module.exports = password;