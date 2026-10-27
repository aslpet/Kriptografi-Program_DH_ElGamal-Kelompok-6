import test from 'node:test';
import assert from 'node:assert/strict';
import {
  modExp,
  modExpWithSteps,
  egcd,
  modInv,
  isProbablePrime,
  genPrime,
  genSafePrime,
  findGenerator,
  isInSubgroup,
  isValidSubgroupElement,
  bitLength,
  getRfc3526Group14
} from '../shared/math_utils.js';

test('modExp: test vectors dan edge cases', () => {
  // Test vectors dari Bagian 6.10
  assert.equal(modExp(4n, 11n, 23n), 1n);
  assert.equal(modExp(4n, 6n, 23n), 2n);
  assert.equal(modExp(18n, 6n, 23n), 8n);
  assert.equal(modExp(2n, 3n, 23n), 8n);

  // Edge cases
  assert.equal(modExp(5n, 0n, 23n), 1n);
  assert.equal(modExp(0n, 5n, 23n), 0n);
  assert.equal(modExp(0n, 0n, 23n), 1n);
  assert.equal(modExp(123n, 456n, 1n), 0n);

  // Basis negatif
  assert.equal(modExp(-5n, 2n, 23n), 2n); // (-5)^2 = 25 = 2 mod 23

  // modExpWithSteps
  const stepsRes = modExpWithSteps(4n, 6n, 23n);
  assert.equal(stepsRes.result, 2n);
  assert.ok(stepsRes.steps.length > 0);
});

test('egcd & modInv: kebenaran invers modular', () => {
  const { g, x, y } = egcd(240n, 46n);
  assert.equal(g, 2n);
  assert.equal(240n * x + 46n * y, 2n);

  // modInv(4, 23) = 6 karena 4 * 6 = 24 = 1 mod 23
  assert.equal(modInv(4n, 23n), 6n);
  assert.equal((4n * 6n) % 23n, 1n);

  // Pasangan koprima acak
  for (let i = 2; i < 50; i++) {
    const a = BigInt(i);
    const m = 97n; // 97 prima
    const inv = modInv(a, m);
    assert.equal((a * inv) % m, 1n);
  }

  // Error jika tidak koprima
  assert.throws(() => modInv(6n, 9n), /Invers modular tidak ada/);
});

test('isProbablePrime & genPrime: prima vs komposit vs Carmichael', () => {
  const primeCandidate = genPrime(16);
  assert.ok(isProbablePrime(primeCandidate, 20));

  const primes = [2n, 3n, 5n, 97n, 7919n, 104729n];
  for (const p of primes) {
    assert.ok(isProbablePrime(p, 20), `${p} seharusnya terdeteksi prima`);
  }

  const composites = [0n, 1n, 4n, 9n, 100n, 561n, 1105n, 1729n, 2047n];
  for (const c of composites) {
    assert.ok(!isProbablePrime(c, 20), `${c} seharusnya terdeteksi komposit`);
  }
});

test('genSafePrime & findGenerator: parameter subgrup orde q', () => {
  const { p, q } = genSafePrime(16);
  assert.equal(p, 2n * q + 1n);
  assert.ok(isProbablePrime(q, 20));
  assert.ok(isProbablePrime(p, 20));

  const g = findGenerator(p, q);
  assert.notEqual(g, 1n);
  assert.equal(modExp(g, q, p), 1n);

  // Validasi keanggotaan subgrup
  assert.ok(isInSubgroup(g, p, q));
  assert.ok(!isInSubgroup(0n, p, q));
  assert.ok(!isInSubgroup(1n, p, q));
  assert.ok(!isInSubgroup(p - 1n, p, q));
  assert.ok(!isInSubgroup(p, p, q));

  assert.ok(isValidSubgroupElement(1n, p, q)); // g^0 = 1 valid untuk ElGamal
  assert.ok(isValidSubgroupElement(g, p, q));
});

test('RFC3526 Group 14 2048-bit parameter valid', () => {
  const group = getRfc3526Group14();
  assert.equal(bitLength(group.p), 2048);
  assert.equal(group.p, 2n * group.q + 1n);
  assert.equal(group.g, 2n);
  // Verifikasi 2^q mod p == 1
  assert.equal(modExp(group.g, group.q, group.p), 1n);
});
