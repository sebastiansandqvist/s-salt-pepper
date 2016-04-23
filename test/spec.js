// ----- dependencies
// ---------------------------------------
require('blanket')({
	pattern: function (filename) {
		return !/node_modules/.test(filename);
	}
});

var expect = require('chai').expect;
var password = require('../index.js');


// ----- tests
// ---------------------------------------
describe('defaults', function() {

	it('should have correct defaults', function() {
		expect(password.defaults.hashLength).to.equal(256);
		expect(password.defaults.saltLength).to.equal(128);
		expect(password.defaults.iterations).to.equal(15000);
		expect(password.defaults.pepper).to.equal('THIS SHOULD BE RANDOM AND KEPT SECRET');
	});

	it('should have correct defaults configured', function() {
		expect(password.hashLength).to.equal(256);
		expect(password.saltLength).to.equal(128);
		expect(password.iterations).to.equal(15000);
		expect(password.pepper).to.equal('THIS SHOULD BE RANDOM AND KEPT SECRET');
	});

});


describe('configure', function() {

	it('should be possible to change defaults', function() {
		
		expect(password.configure).to.be.a.function;

		password.configure({
			hashLength: 1,
			saltLength: 2,
			iterations: 10,
			pepper: 'foo',
		});

		expect(password.hashLength).to.equal(1);
		expect(password.saltLength).to.equal(2);
		expect(password.iterations).to.equal(10);
		expect(password.pepper).to.equal('foo');

		password.configure(password.defaults);

	});

	it('should not be possible to create new keys in defaults', function() {

		password.configure({
			foo: 'bar',
			iterations: 12
		});

		expect(password.foo).to.be.undefined;
		expect(password.iterations).to.equal(12);

		password.configure(password.defaults);

	});

	it('should not be possible to set defaults to wrong type', function() {

		expect(function() {
			password.configure({ hashLength: 'foo' });
		}).to.throw();

		expect(function() {
			password.configure({ iterations: {} });
		}).to.throw();

		expect(function() {
			password.configure({ pepper: 123 });
		}).to.throw();

		expect(function() {
			password.configure({ saltLength: 'foo' });
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

		password.configure(password.defaults);

		password.hash('foo', function(err, salt, hash) {
			expect(err).to.not.exist;
			expect(salt).to.be.a.string;
			expect(salt.length).to.be.at.least(password.pepper.length + password.saltLength);
			expect(hash).to.be.a.string;
			expect(hash).to.not.equal('foo');
			expect(hash.length).to.be.at.least(password.hashLength);
			done();
		});
	});

	it('should return an error if pbkdf2 fails', function(done) {
		password.configure(password.defaults);
		password.hashLength = null;
		password.hash('foo', function(err, salt, hash) {
			expect(err.message).to.include('hashLength is required');
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

	it('should hash correctly', function(done) {
		password.configure(password.defaults);
		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should return an error if pbkdf2 fails', function(done) {
		password.configure(password.defaults);
		password.hash('test', function(err, salt, hash) {
			password.hashLength = null;
			password.compare('test', salt, function(err, hash2) {
				expect(err.message).to.include('hashLength is required');
				expect(hash2).to.not.exist;
				done();
			});
		});
	});

});


describe('using other saltLengths', function() {

	it('should work with a high saltLength', function(done) {
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			saltLength: 100000
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

	it('should not work with a hashLength of 0', function(done) {
		password.configure(password.defaults);
		password.configure({
			hashLength: 0
		});

		password.hash('test', function(err, salt, hash) {
			expect(err.message).to.include('hashLength is required');
			expect(salt).to.not.exist;
			expect(hash).to.not.exist;
			done();
		});
	});

	it('should work with a high hashLength', function(done) {
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			hashLength: 100000
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

describe('using other peppers', function() {

	it('should work with symbols in the pepper', function(done) {
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			pepper: '~!@#$%^&*()_+`1234567890-=\'][{}|,./<>?"asd"'
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
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			pepper: '° © ® ™ • ½ ¼ ¾ ⅓ ⅔ † ‡ µ ¢ £ € « » ♤ ♧ ♥ ♢ ¿ � 汉语 漢語 华语 華語 中文'
		});

		password.hash('test', function(err, salt, hash) {
			password.compare('test', salt, function(err, hash2) {
				expect(err).to.not.exist;
				expect(hash2).to.equal(hash);
				done();
			});
		});
	});

	it('should work with a short pepper', function(done) {
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			pepper: '0'
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
		var pepper = new Array(100000).join('test ');
		password.configure(password.defaults);
		password.configure({
			iterations: 10,
			pepper: pepper
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