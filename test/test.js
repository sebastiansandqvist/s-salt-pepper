import test from 'ava';
import password from '../';

test.beforeEach(() => {
  password.saltLength(32);
  password.iterations(10); // lowered so tests run faster
  password.keyLength(128);
  password.digest('sha512');
  password.pepper('test_pepper_123');
});

test('hash', async (t) => {
  const { hash, salt } = await password.hash('foo');
  t.is(typeof hash, 'string');
  t.is(typeof salt, 'string');
  t.true(hash.length >= 128);
  t.true(salt.length >= 32);
  t.true(hash !== 'foo');
  t.true(salt !== 'test');
  t.true(!(hash.includes('test_pepper_123')));
  t.true(!(salt.includes('test_pepper_123')));
});

test('compare', async (t) => {
  const hashAndSalt = await password.hash('foo');
  t.true(await password.compare('foo', hashAndSalt));
});

test('increased iterations take longer', async (t) => {
  const NS_PER_SEC = 1e9;
  password.iterations(100);
  const start1 = process.hrtime();
  await password.hash('foo');
  const end1 = process.hrtime();
  const ns1 = (end1[0] * NS_PER_SEC + end1[1]) - (start1[0] * NS_PER_SEC + start1[1]);

  password.iterations(100000);
  const start2 = process.hrtime();
  await password.hash('foo');
  const end2 = process.hrtime();
  const ns2 = (end2[0] * NS_PER_SEC + end2[1]) - (start2[0] * NS_PER_SEC + start2[1]);

  t.true(ns2 > ns1);
});

test('getter/setters', (t) => {
  password.saltLength(123);
  password.iterations(456);
  password.keyLength(789);
  password.digest('sha256');
  password.pepper('foo');
  t.is(password.saltLength(), 123);
  t.is(password.iterations(), 456);
  t.is(password.keyLength(), 789);
  t.is(password.digest(), 'sha256');
  t.is(password.pepper(), 'foo');
});
