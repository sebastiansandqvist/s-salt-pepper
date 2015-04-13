// ----- dependencies
// ---------------------------------------
var expect = require('chai').expect;
var helpers = require('../src/helpers.js');
var password = require('../index.js');


// ----- tests
// ---------------------------------------
describe('_encrypt', function() {

	it('should return encrypted text', function() {
		var encrypted = helpers._encrypt('aes256', 'foo', 'bar');
		expect(encrypted).to.not.equal('bar');
		expect(encrypted.length).to.be.at.least(3);
	});

});


describe('_decrypt', function() {

	it('should return decrypted text', function() {
		var encrypted = helpers._encrypt('aes256', 'foo', 'bar');
		expect(helpers._decrypt('aes256', 'foo', encrypted)).to.equal('bar');
	});

});


describe('_random', function() {

	it('should return random number in range', function(done) {
		helpers._random(0, 100, function(err, number) {
			expect(err).to.not.exist;
			expect(number).to.be.a.number;
			expect(number).to.be.at.least(0);
			expect(number).to.be.at.most(100);
			done();
		});
	});

	it('should return error if min > max', function(done) {
		helpers._random(100, 0, function(err, number) {
			expect(err.message).to.include('invalid min and max values');
			expect(number).to.not.exist;
			done();
		});
	});

	it('should return an error if min and max are not numbers', function(done) {
		helpers._random(undefined, 'foo', function(err, number) {
			expect(err.message).to.include('numbers expected for min and max values of random number in range');
			expect(number).to.not.exist;
			done();
		});
	});

});


describe('_salt', function() {

	it('should return a random string of length > unencryptedSaltMinLength', function(done) {
		helpers._salt(1000, password.unencryptedSaltMinLength, function(err, salt) {
			expect(err).to.not.exist;
			expect(salt).to.be.a.string;
			expect(salt.length).to.be.at.least(password.unencryptedSaltMinLength);
			done();
		});
	});

	it('should contain the iteration number', function(done) {
		helpers._salt(12345, password.unencryptedSaltMinLength, function(err, salt) {
			expect(err).to.be.null;
			expect(salt).to.include('12345');
			done();
		});
	});

});


describe('_getIterations', function() {

	it('should return the correct number of iterations', function(done) {

		helpers._salt(15555, password.unencryptedSaltMinLength, function(err, salt) {

			var iterations = helpers._getIterations(salt, password.unencryptedSaltMinLength);
			expect(iterations).to.equal(15555);
			done();

		});

	});

});