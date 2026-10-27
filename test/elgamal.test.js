import test from 'node:test';
import assert from 'node:assert/strict';
import {
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  elgamalMultiply,
  encryptBallot,
  aggregateBallots,
  recoverTally,
  elgamalSignKeygen,
  elgamalSign,
  elgamalVerify
} from '../shared/elgamal.js';
import { genSafePrime, findGenerator, modExp } from '../shared/math_utils.js';

test('ElGamal: Test Vector Eksak Bagian 6.10 (p=23, q=11, g=4)', () => {
  const params = { p: 23n, q: 11n, g: 4n };

  // EA Keygen: x = 7 -> h = 4^7 mod 23 = 8
  const { x, h } = elgamalKeygen(params, 7n);
  assert.equal(x, 7n);
  assert.equal(h, 8n);

  // Voter 1: memilih kandidat (v=1, m = g^1 = 4), k = 3
  const v1 = elgamalEncrypt(params, h, 4n, 3n);
  assert.equal(v1.c1, 18n); // 4^3 mod 23 = 18
  assert.equal(v1.c2, 1n);  // 4 * 8^3 mod 23 = 1

  // Voter 2: tidak memilih (v=0, m = g^0 = 1), k = 5
  const v2 = elgamalEncrypt(params, h, 1n, 5n);
  assert.equal(v2.c1, 12n); // 4^5 mod 23 = 12
  assert.equal(v2.c2, 16n); // 1 * 8^5 mod 23 = 16

  // Agregasi: C1 = 18 * 12 mod 23 = 9, C2 = 1 * 16 mod 23 = 16
  const agg = elgamalMultiply(params, v1, v2);
  assert.equal(agg.c1, 9n);
  assert.equal(agg.c2, 16n);

  // Dekripsi total: s = 9^7 mod 23 = 4, g^T = 16 * 4^-1 mod 23 = 4
  const gT = elgamalDecrypt(params, x, agg);
  assert.equal(gT, 4n);

  // Pemulihan T: g^1 = 4 -> T = 1
  const tally = recoverTally(params, gT, 2);
  assert.equal(tally.T, 1);
  assert.equal(tally.iterations, 2);
});

test('ElGamal: Dekripsi acak & sifat probabilistik ciphertext', () => {
  const { p, q } = genSafePrime(24);
  const g = findGenerator(p, q);
  const params = { p, q, g };

  const { x, h } = elgamalKeygen(params);

  // Pesan m di subgrup (m = g^10 mod p)
  const m = modExp(g, 10n, p);

  const ct1 = elgamalEncrypt(params, h, m);
  const ct2 = elgamalEncrypt(params, h, m);

  // Nonce acak berbeda menghasilkan ciphertext berbeda
  assert.notEqual(ct1.c1, ct2.c1);
  assert.notEqual(ct1.c2, ct2.c2);

  // Kedua ciphertext tetap terdekripsi ke m yang sama
  assert.equal(elgamalDecrypt(params, x, ct1), m);
  assert.equal(elgamalDecrypt(params, x, ct2), m);
});

test('ElGamal: Agregasi Multi-kandidat & Multi-voter', () => {
  const { p, q } = genSafePrime(24);
  const g = findGenerator(p, q);
  const params = { p, q, g };
  const { x, h } = elgamalKeygen(params);

  // 3 kandidat, 5 pemilih:
  // V1 -> K1 (0), V2 -> K2 (1), V3 -> K1 (0), V4 -> K3 (2), V5 -> K1 (0)
  // Target hasil: K1 = 3, K2 = 1, K3 = 1, Total = 5
  const choices = [0, 1, 0, 2, 0];
  const ballots = choices.map(choice => encryptBallot(params, h, choice, 3));

  const aggregates = aggregateBallots(params, ballots, 3);
  assert.equal(aggregates.length, 3);

  const results = aggregates.map(agg => {
    const gT = elgamalDecrypt(params, x, { c1: agg.C1, c2: agg.C2 });
    return recoverTally(params, gT, 5).T;
  });

  assert.deepEqual(results, [3, 1, 1]);
  assert.equal(results.reduce((a, b) => a + b, 0), 5);
});

test('ElGamal: Tanda Tangan Digital Server [BONUS]', () => {
  const { p, q } = genSafePrime(24);
  const g = findGenerator(p, q);
  const params = { p, q, g };

  const { xs, ys } = elgamalSignKeygen(params);
  const message = 'transcript-sessionId-A-B';

  const sig = elgamalSign(params, xs, message);
  assert.ok(elgamalVerify(params, ys, message, sig), 'Tanda tangan asli harus terverifikasi');

  // Pesan diubah 1 karakter -> gagal
  assert.ok(!elgamalVerify(params, ys, message + '!', sig), 'Pesan termodifikasi harus gagal verifikasi');

  // Nilai r atau s diubah -> gagal
  const tamperedSig = { r: (sig.r + 1n) % p, s: sig.s };
  assert.ok(!elgamalVerify(params, ys, message, tamperedSig), 'Tanda tangan dengan r palsu harus gagal');
});
