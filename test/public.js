// ----- dependencies
// ---------------------------------------
var expect = require('chai').expect;
var password = require('../index.js');
var helpers = require('../src/helpers.js');


// ----- tests
// ---------------------------------------
describe('defaults', function() {

	it('should have correct defaults', function() {
		expect(password.defaults.hashLength).to.equal(128);
		expect(password.defaults.iterations).to.deep.equal([12000, 15000]);
		expect(password.defaults.key).to.equal('ENCRYPTION KEY');
		expect(password.defaults.unencryptedSaltMinLength).to.equal(32);
	});

	it('should have correct defaults configured', function() {
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
			hashLength: 256,
			iterations: [12500, 13500],
			key: 'test key',
			unencryptedSaltMinLength: 64
		});

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


describe('hash', function() {

	it('should throw if missing parameters', function() {

		expect(function() {
			password.hash();
		}).to.throw();

		expect(function() {
			password.hash('foo', 'bar', function() {});
		}).to.throw();


	});

	it('should not throw for empty input', function() {
		
		expect(function() {
			password.hash(null, function() {});
		}).to.not.throw();

		expect(function() {
			password.hash('', function() {});
		}).to.not.throw();

	});

	it('should return function with error for null input', function(done) {
		password.hash(null, function(err, salt, hash) {
			expect(err.message).to.include('invalid input');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return function with error for undefined input', function(done) {
		password.hash(undefined, function(err, salt, hash) {
			expect(err.message).to.include('invalid input');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return function with error for other input', function(done) {
		password.hash(12, function(err, salt, hash) {
			expect(err.message).to.include('invalid input');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return a hash and salt', function(done) {
		password.hash('foo', function(err, salt, hash) {
			expect(err).to.not.exist;
			expect(salt).to.be.a.string;
			expect(salt.length).to.be.at.least(32);
			expect(hash).to.be.a.string;
			expect(hash).to.not.equal('foo');
			expect(hash.length).to.be.at.least(128);
			done();
		});
	});

	it('should return a salt that includes iteration count in range', function(done) {

		password.hash('foo', function(err, salt, hash) {
			var unencryptedSalt = helpers._decrypt('aes256', password.key, salt);
			var iterations = helpers._getIterations(unencryptedSalt, password.unencryptedSaltMinLength);
			expect(iterations).to.be.a.number;
			expect(iterations).to.be.at.least(password.iterations[0]);
			expect(iterations).to.be.at.most(password.iterations[1]);
			done();
		});

	});

	it('should return an error if iterations are incorrect', function(done) {
		password.iterations = [100, 50];
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('invalid min and max values');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return an error if iterations are not numbers', function(done) {
		password.iterations = [undefined, 'foo'];
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('min and max values');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return an error if randomBytes fails in helpers._salt', function(done) {
		password.iterations = [12000, 15000];
		password.unencryptedSaltMinLength = null;
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('size must be a number >= 0');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done()
		});
	});

	it('should return an error if helpers._encrypt fails', function(done) {
		password.unencryptedSaltMinLength = 32;
		password.key = 12;
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('key');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return an error if pbkdf2 fails', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [12000, 15000],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 32
		});
		password.hashLength = null;
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('Key length not a number');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should throw if no callback', function() {
		expect(function() {
			password.hash('input', null);
		}).to.throw();
	});

});

describe('compare', function() {

	it('should return an error if not given an input', function(done) {
		password.compare(null, 'salt', function(err, hash) {
			expect(err.message).to.include('invalid input');
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return an error if not given a salt', function(done) {
		password.compare('input', null, function(err, hash) {
			expect(err.message).to.include('invalid salt');
			expect(hash).to.not.exist;
			done();
		});
	});

	it ('should return an error if input is empty string', function(done) {
		password.compare('', 'salt', function(err, hash) {
			expect(err.message).to.include('invalid input');
			expect(hash).to.not.exist;
			done();
		});
	});

	it ('should return an error if salt is empty string', function(done) {
		password.compare('input', '', function(err, hash) {
			expect(err.message).to.include('invalid salt');
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should throw if no callback', function() {
		expect(function() {
			password.compare('input', 'salt', null);
		}).to.throw();
	});

	it('should throw if no input', function() {
		expect(function() {
			password.compare('salt', function(err, hash) {});
		}).to.throw();
	});

	it('should return an error if decryption fails', function(done) {
		password.key = null;
		password.compare('input', 'salt', function(err, hash) {
			expect(err.message).to.include('cipher');
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should return an error if getIterations fails', function(done) {
		var test = helpers._encrypt('aes256', 'encryption_key', 'test');
		password.key = 'encryption_key';
		password.compare('input', test, function(err, hash) {
			expect(err.message).to.include('iterations');
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should hash correctly', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [12000, 15000],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should return an error if pbkdf2 fails', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [12000, 15000],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.hashLength = null;
			password.compare('test', salt, function(err, hash2) {
				expect(err.message).to.include('length');
				expect(hash2).to.not.exist;
				done();
			});
		});
	});

});

describe('using other minLengths', function() {

	it('should work with a minLength of 0 (but... this is still bad)', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [12000, 15000],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 0
		});

		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});

	});

	it('should work with a high minLength', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [10, 20],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 1000000
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});

	});

});

describe('using other hashLengths', function() {

	it('should work with a hashLength of 0 (but... this is still bad)', function(done) {
		password.configure({
			hashLength: 0, 
			iterations: [12000, 15000],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				expect(hash).to.equal('');
				done();
			});
		});
	});

	it('should work with a high hashLength', function(done) {
		password.configure({
			hashLength: 1000, 
			iterations: [100, 200],
			key: 'ENCRYPTION KEY',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

});

describe('using other encryption keys', function() {

	it('should work with symbols in the key', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [100, 200],
			key: '~!@#$%^&*()_+`1234567890-=\'][{}|,./<>?"asd"',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should work with UTF-8 characters in the key', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [100, 200],
			key: '° © ® ™ • ½ ¼ ¾ ⅓ ⅔ † ‡ µ ¢ £ € « » ♤ ♧ ♥ ♢ ¿ � 汉语 漢語 华语 華語 中文',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should work with a short key', function(done) {
		password.configure({
			hashLength: 128, 
			iterations: [100, 200],
			key: '0',
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should work with a long key', function(done) {
		var key = new Array(10000).join('test ');
		password.configure({
			hashLength: 128, 
			iterations: [100, 200],
			key: key,
			unencryptedSaltMinLength: 32
		});
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

});