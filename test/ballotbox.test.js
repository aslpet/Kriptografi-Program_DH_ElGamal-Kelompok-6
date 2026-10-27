import test from 'node:test';
import assert from 'node:assert/strict';
import { castBallot, getBallots, resetBallotBox } from '../server/ballotbox.js';
import { registerVoters, resetVoters } from '../server/voters.js';
import { genSafePrime, findGenerator } from '../shared/math_utils.js';
import { toHex } from '../shared/encoding.js';
import { elgamalEncrypt } from '../shared/elgamal.js';

test('BallotBox: Penyimpanan anonim dan proteksi double voting', () => {
  resetVoters();
  resetBallotBox();

  const { p, q } = genSafePrime(20);
  const g = findGenerator(p, q);
  const rawParams = { p, q, g };

  registerVoters([
    { id: 'V001', pin: '111111' },
    { id: 'V002', pin: '222222' }
  ]);

  // Buat ballot valid 3 kandidat untuk V001
  const h = g; // dummy public key
  const ct1 = elgamalEncrypt(rawParams, h, g); // vote 1
  const ct2 = elgamalEncrypt(rawParams, h, 1n); // vote 0
  const ct3 = elgamalEncrypt(rawParams, h, 1n); // vote 0

  const ballotPayload = {
    cts: [
      { c1: toHex(ct1.c1), c2: toHex(ct1.c2) },
      { c1: toHex(ct2.c1), c2: toHex(ct2.c2) },
      { c1: toHex(ct3.c1), c2: toHex(ct3.c2) }
    ]
  };

  // Suara pertama V001 sukses
  const res1 = castBallot('V001', ballotPayload, rawParams, 3);
  assert.ok(res1.ok);
  assert.ok(res1.receipt);

  // Periksa bahwa ballot tersimpan tanpa identitas voterId
  const storedBallots = getBallots();
  assert.equal(storedBallots.length, 1);
  assert.equal(storedBallots[0].voterId, undefined);
  assert.equal(storedBallots[0].receipt, res1.receipt);

  // Percobaan kedua dari V001 harus ditolak (Double Voting)
  assert.throws(() => castBallot('V001', ballotPayload, rawParams, 3), {
    status: 409
  });

  // V002 memberikan suara sukses
  const res2 = castBallot('V002', ballotPayload, rawParams, 3);
  assert.ok(res2.ok);
  assert.equal(getBallots().length, 2);
});

test('BallotBox: Validasi panjang kandidat dan keanggotaan subgrup', () => {
  resetVoters();
  resetBallotBox();

  const { p, q } = genSafePrime(20);
  const g = findGenerator(p, q);
  const rawParams = { p, q, g };

  registerVoters([{ id: 'V003', pin: '333333' }]);

  // Panjang hanya 2 padahal diharapkan 3 kandidat
  const invalidLengthPayload = {
    cts: [
      { c1: toHex(g), c2: toHex(g) },
      { c1: toHex(g), c2: toHex(g) }
    ]
  };
  assert.throws(() => castBallot('V003', invalidLengthPayload, rawParams, 3), {
    status: 400
  });

  // Elemen bukan subgrup (mis. nilai 0 atau p-1 yang bukan subgrup)
  const invalidSubgroupPayload = {
    cts: [
      { c1: toHex(0n), c2: toHex(g) },
      { c1: toHex(g), c2: toHex(g) },
      { c1: toHex(g), c2: toHex(g) }
    ]
  };
  assert.throws(() => castBallot('V003', invalidSubgroupPayload, rawParams, 3), {
    status: 400
  });
});
