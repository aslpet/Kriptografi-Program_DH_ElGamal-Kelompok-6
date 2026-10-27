import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveKeys, seal, open } from '../shared/channel.js';

test('Channel: Derivasi Kunci, Seal dan Open sukses', () => {
  const params = { p: 23n, q: 11n, g: 4n };
  const K = 8n;
  const sessionId = 'test-session-1234';
  const A = 2n;
  const B = 18n;

  const keys = deriveKeys(params, K, sessionId, A, B);
  assert.equal(keys.encKey.length, 32);
  assert.equal(keys.macKey.length, 32);

  const payload = { voterId: 'V001', pin: '123456' };

  // Voter -> Server: dir = 1, seq = 1
  const packet = seal(keys, 1, 1, payload);
  assert.equal(packet.seq, 1);
  assert.ok(packet.ct.length > 0);
  assert.ok(packet.tag.length === 64); // 32-byte hex

  // Server buka paket
  const opened = open(keys, 1, packet, 0);
  assert.deepEqual(opened, payload);
});

test('Channel: Anti-Tamper - modifikasi ciphertext atau tag ditolak', () => {
  const params = { p: 23n, q: 11n, g: 4n };
  const keys = deriveKeys(params, 8n, 'session-abc', 2n, 18n);
  const packet = seal(keys, 1, 1, { data: 'secret' });

  // 1. Modifikasi 1 karakter di ct
  const tamperedCt = (packet.ct[0] === 'a' ? 'b' : 'a') + packet.ct.slice(1);
  assert.throws(
    () => open(keys, 1, { ...packet, ct: tamperedCt }, 0),
    /Integritas paket gagal/
  );

  // 2. Modifikasi 1 karakter di tag
  const tamperedTag = (packet.tag[0] === 'a' ? 'b' : 'a') + packet.tag.slice(1);
  assert.throws(
    () => open(keys, 1, { ...packet, tag: tamperedTag }, 0),
    /Integritas paket gagal/
  );
});

test('Channel: Anti-Replay dan Anti-Reflection', () => {
  const params = { p: 23n, q: 11n, g: 4n };
  const keys = deriveKeys(params, 8n, 'session-abc', 2n, 18n);

  const packet1 = seal(keys, 1, 1, { message: 'first' });
  const packet2 = seal(keys, 1, 2, { message: 'second' });

  // Paket 1 berhasil dibuka
  open(keys, 1, packet1, 0);

  // Replay packet1 dengan lastSeq = 1 -> tolak
  assert.throws(
    () => open(keys, 1, packet1, 1),
    /Replay attack terdeteksi/
  );

  // Paket 2 berhasil dibuka dengan lastSeq = 1
  const opened2 = open(keys, 1, packet2, 1);
  assert.deepEqual(opened2, { message: 'second' });

  // Reflection: arah dir ditukar (voter ke server tapi diverifikasi dengan dir server ke voter)
  assert.throws(
    () => open(keys, 2, packet2, 1),
    /Integritas paket gagal/
  );
});
