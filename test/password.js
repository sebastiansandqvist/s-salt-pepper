// ----- dependencies
// ---------------------------------------
var expect = require('chai').expect;
var password = require('../index.js');


// ----- tests
// ---------------------------------------
describe('defaults', function() {

	it('should have correct defaults', function() {
		expect(password.defaults.algorithm).to.equal('aes256');
		expect(password.defaults.hashLength).to.equal(128);
		expect(password.defaults.iterations).to.deep.equal([12000, 15000]);
		expect(password.defaults.key).to.equal('ENCRYPTION KEY');
		expect(password.defaults.unencryptedSaltMinLength).to.equal(32);
	});

	it('should have correct defaults configured', function() {
		expect(password.algorithm).to.equal('aes256');
		expect(password.hashLength).to.equal(128);
		expect(password.iterations).to.deep.equal([12000, 15000]);
		expect(password.key).to.equal('ENCRYPTION KEY');
		expect(password.unencryptedSaltMinLength).to.equal(32);
	});

});

describe('configure', function() {

	it('should be possible to change defaults', function() {
		
		expect(password.configure).to.be.a.function;

		password.configure({
			algorithm: 'aes-256-cbc',
			hashLength: 256,
			iterations: [12500, 13500],
			key: 'test key',
			unencryptedSaltMinLength: 64
		});

		expect(password.algorithm).to.equal('aes-256-cbc');
		expect(password.hashLength).to.equal(256);
		expect(password.iterations).to.deep.equal([12500, 13500]);
		expect(password.key).to.equal('test key');
		expect(password.unencryptedSaltMinLength).to.equal(64);

	});

	it('should not be possible to create new keys in defaults', function() {

		password.configure({
			foo: 'bar',
			key: 'test key 2'
		});

		expect(password.foo).to.be.undefined;
		expect(password.key).to.equal('test key 2');

	});

	it('should not be possible to set defaults to wrong type', function() {

		expect(function() {
			password.configure({ algorithm: 123 });
		}).to.throw();

		expect(function() {
			password.configure({ hashLength: 'foo' });
		}).to.throw();

		expect(function() {
			password.configure({ iterations: {} });
		}).to.throw();

		expect(function() {
			password.configure({ key: 123 });
		}).to.throw();

		expect(function() {
			password.configure({ unencryptedSaltMinLength: 'foo' });
		}).to.throw();

	});

});


// describe('Encrypt', function() {

// 	it('should return encrypted text', function() {
// 		var encrypted = password._encrypt('foo', 'bar');
// 		expect(encrypted)to.not.equal('bar');
// 		expect(encrypted.length)to.be.greater.than(3);
// 	});

// });