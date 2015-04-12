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
	algorithm: 'aes256',
	hashLength: 128,
	iterations: [12000, 15000],
	key: 'ENCRYPTION KEY',
	unencryptedSaltMinLength: 32
};


// ----- allow user to set config options
//		--	but restrict them to props in `password.defaults`
//		--	and make sure types are correct
// ---------------------------------------
password.configure = function(obj) {

	var _toString = Object.prototype.toString;
	
	for (var prop in obj) {
		if (obj.hasOwnProperty(prop) && password.defaults.hasOwnProperty(prop)) {
			if (_toString.call(obj[prop]) !== _toString.call(password.defaults[prop])) {
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

// ----- encrypt strings
//		--	@param key {string}
//		--	@param text {string}
//		--	@return encrypted {string}
//		--	@api private
// ---------------------------------------
// password._encrypt = function(key, text) {

// };

module.exports = password;