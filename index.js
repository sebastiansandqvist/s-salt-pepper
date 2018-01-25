const crypto = require('crypto');
const { promisify } = require('util');

const randomBytes = promisify(crypto.randomBytes);
const pbkdf2 = promisify(crypto.pbkdf2);

const defaults = {
  saltLength: 32,
  iterations: 100000, // ~200ms to compute with current key/salt lengths
  keyLength: 128,
  digest: 'sha512',
  pepper: ''
};

// make defaults all getter/setter functions
// so password.saltLength(32) sets saltLength,
// password.saltLength() returns saltLength
for (const key in defaults) {
  exports[key] = (...args) => args.length === 0 ?
    defaults[key] :
    defaults[key] = args[0];
}

exports.hash = async function(password) {
  const salt = (await randomBytes(defaults.saltLength)).toString('base64');
  const pepperedSalt = defaults.pepper.concat(salt);
  const hash = (await pbkdf2(password, pepperedSalt, defaults.iterations, defaults.keyLength, defaults.digest)).toString('base64');
  return { salt, hash };
};

exports.compare = async function(password, { salt, hash }) {
  const pepperedSalt = defaults.pepper.concat(salt);
  const comparisonHash = (await pbkdf2(password, pepperedSalt, defaults.iterations, defaults.keyLength, defaults.digest)).toString('base64');
  return comparisonHash === hash;
};
