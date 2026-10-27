import test from 'node:test';
import assert from 'node:assert/strict';
import { genSafePrime, findGenerator } from '../shared/math_utils.js';
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';

test('Diffie-Hellman: Kesepakatan K voter == K server', () => {
  const { p, q } = genSafePrime(24);
  const g = findGenerator(p, q);
  const params = { p, q, g };

  // Uji beberapa iterasi
  for (let i = 0; i < 20; i++) {
    const voter = dhGenerateKeyPair(params);
    const server = dhGenerateKeyPair(params);

    const Kvoter = dhComputeShared(params, voter.priv, server.pub);
    const Kserver = dhComputeShared(params, server.priv, voter.pub);

    assert.equal(Kvoter, Kserver, `Iterasi ${i}: K voter (${Kvoter}) harus sama dengan K server (${Kserver})`);
    assert.ok(Kvoter > 1n && Kvoter < p);
  }
});

test('Diffie-Hellman: Nilai publik tidak valid ditolak', () => {
  const { p, q } = genSafePrime(24);
  const g = findGenerator(p, q);
  const params = { p, q, g };
  const alice = dhGenerateKeyPair(params);

  // Nilai 0, 1, p-1, p
  assert.throws(() => dhComputeShared(params, alice.priv, 0n), /tidak valid/);
  assert.throws(() => dhComputeShared(params, alice.priv, 1n), /tidak valid/);
  assert.throws(() => dhComputeShared(params, alice.priv, p - 1n), /tidak valid/);
  assert.throws(() => dhComputeShared(params, alice.priv, p), /tidak valid/);
  assert.throws(() => dhComputeShared(params, alice.priv, p + 5n), /tidak valid/);
});
