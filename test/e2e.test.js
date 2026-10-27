import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../server/server.js';
import { CONFIG } from '../config.js';
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';
import { elgamalVerify, encryptBallot } from '../shared/elgamal.js';
import { deriveKeys, seal, open } from '../shared/channel.js';
import { fromHex, toHex } from '../shared/encoding.js';
import { modExp } from '../shared/math_utils.js';

test('End-to-End: Alur Pemilu Lengkap (DH + Saluran Aman + ElGamal Homomorfik)', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    server.close();
  });

  const adminHeaders = {
    'Content-Type': 'application/json',
    'x-admin-token': CONFIG.ADMIN_TOKEN
  };

  // 1. Setup Pemilu (Mode Demo 32-bit)
  const setupRes = await fetch(`${baseUrl}/api/admin/setup`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ mode: 'demo' })
  });
  const setupData = await setupRes.json();
  assert.equal(setupRes.status, 200);
  assert.equal(setupData.state, 'REGISTRATION');
  assert.ok(setupData.params.p);
  assert.ok(setupData.params.h);
  assert.ok(setupData.params.ys);

  const pubParams = setupData.params;
  const rawP = fromHex(pubParams.p);
  const rawQ = fromHex(pubParams.q);
  const rawG = fromHex(pubParams.g);
  const rawH = fromHex(pubParams.h);
  const rawYs = fromHex(pubParams.ys);
  const cryptoParams = { p: rawP, q: rawQ, g: rawG };

  // 2. Registrasi 5 Pemilih (V001..V005)
  const votersRes = await fetch(`${baseUrl}/api/admin/voters`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ voters: CONFIG.DEFAULT_VOTERS })
  });
  const votersData = await votersRes.json();
  assert.equal(votersRes.status, 200);
  assert.equal(votersData.voters.length, 5);

  // 3. Buka Pemungutan Suara
  const openRes = await fetch(`${baseUrl}/api/admin/open`, {
    method: 'POST',
    headers: adminHeaders
  });
  assert.equal(openRes.status, 200);

  // Helper fungsi untuk alur lengkap 1 Voter: Handshake DH -> Confirm -> Login -> Vote
  async function voteFlow(voterId, pin, choiceIndex) {
    // A. Handshake DH
    const voterDh = dhGenerateKeyPair(cryptoParams);
    const initRes = await fetch(`${baseUrl}/api/handshake/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ voterId, A: toHex(voterDh.pub) })
    });
    const initData = await initRes.json();
    assert.equal(initRes.status, 200, `Init gagal untuk ${voterId}: ${JSON.stringify(initData)}`);

    const { sessionId, B: B_hex, sig } = initData;
    const serverB = fromHex(B_hex);

    // Verifikasi tanda tangan ElGamal server atas transkrip [BONUS]
    const transcriptStr = `${sessionId}|${toHex(voterDh.pub)}|${B_hex}`;
    const sigValid = elgamalVerify(cryptoParams, rawYs, transcriptStr, {
      r: fromHex(sig.r),
      s: fromHex(sig.s)
    });
    assert.ok(sigValid, `Tanda tangan server harus valid untuk ${voterId}`);

    // Hitung K = B^a mod p dan turunkan kunci sesi
    const K = dhComputeShared(cryptoParams, voterDh.priv, serverB);
    const keys = deriveKeys(cryptoParams, K, sessionId, voterDh.pub, serverB);

    // B. Konfirmasi Handshake
    let clientSeq = 1;
    const confirmPacket = seal(keys, 1, clientSeq, `READY|${sessionId}`);
    const confirmRes = await fetch(`${baseUrl}/api/handshake/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, ...confirmPacket })
    });
    const confirmData = await confirmRes.json();
    assert.equal(confirmRes.status, 200);

    // Server balas dengan paket aman
    const confirmReply = open(keys, 2, confirmData.packet, 0);
    assert.equal(confirmReply.status, 'OK');

    // C. Login di dalam Saluran Terenkripsi
    clientSeq++;
    const loginPacket = seal(keys, 1, clientSeq, { voterId, pin });
    const loginRes = await fetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, ...loginPacket })
    });
    const loginData = await loginRes.json();
    assert.equal(loginRes.status, 200);

    const loginReply = open(keys, 2, loginData.packet, 1);
    assert.ok(loginReply.ok);

    // D. Enkripsi Suara ElGamal di Browser Klien & Kirim via Paket Aman
    clientSeq++;
    const ballotEnc = encryptBallot(cryptoParams, rawH, choiceIndex, 3);
    const hexBallot = {
      cts: ballotEnc.cts.map(c => ({ c1: toHex(c.c1), c2: toHex(c.c2) }))
    };

    const votePacket = seal(keys, 1, clientSeq, { ballot: hexBallot });
    const voteRes = await fetch(`${baseUrl}/api/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, ...votePacket })
    });
    const voteData = await voteRes.json();
    assert.equal(voteRes.status, 200);

    const voteReply = open(keys, 2, voteData.packet, 2);
    assert.ok(voteReply.ok);
    assert.ok(voteReply.receipt);

    return { sessionId, keys, votePacket, receipt: voteReply.receipt, clientSeq };
  }

  // 4. Voter V001 Memilih Kandidat 1 (index 0)
  const v1 = await voteFlow('V001', '111111', 0);
  assert.ok(v1.receipt);

  // 5. Uji Serangan: Double Voting oleh V001 harus ditolak
  const doubleVoteInit = await fetch(`${baseUrl}/api/handshake/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ voterId: 'V001', A: toHex(4n) })
  });
  assert.equal(doubleVoteInit.status, 409, 'Inisialisasi handshake ulang setelah vote harus 409 Conflict');

  // 6. Uji Serangan: Replay Packet Lama ke /api/vote harus ditolak (409 Conflict)
  const replayRes = await fetch(`${baseUrl}/api/vote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId: v1.sessionId, ...v1.votePacket })
  });
  assert.equal(replayRes.status, 409, 'Replay packet lama harus ditolak dengan status 409 Conflict');

  // 7. Uji Serangan: Tampered Packet (Modifikasi 1 bit ciphertext)
  const tamperedCt = (v1.votePacket.ct[0] === 'a' ? 'b' : 'a') + v1.votePacket.ct.slice(1);
  const tamperRes = await fetch(`${baseUrl}/api/vote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionId: v1.sessionId,
      seq: v1.clientSeq + 1,
      ct: tamperedCt,
      tag: v1.votePacket.tag
    })
  });
  assert.equal(tamperRes.status, 401, 'Paket yang dimodifikasi harus ditolak karena HMAC gagal');

  // 8. Pemilih Sisa Memilih Sesuai Skenario Presentasi Bagian 14.2:
  // V002 -> K2 (1), V003 -> K1 (0), V004 -> K3 (2), V005 -> K1 (0)
  // Target Hasil Akhir: K1 = 3, K2 = 1, K3 = 1 (Total = 5)
  await voteFlow('V002', '222222', 1);
  await voteFlow('V003', '333333', 0);
  await voteFlow('V004', '444444', 2);
  await voteFlow('V005', '555555', 0);

  // Periksa isi Ballot Box publik
  const ballotsRes = await fetch(`${baseUrl}/api/ballots`);
  const ballotsData = await ballotsRes.json();
  assert.equal(ballotsData.total, 5);

  // 9. Tutup Pemungutan Suara
  const closeRes = await fetch(`${baseUrl}/api/admin/close`, {
    method: 'POST',
    headers: adminHeaders
  });
  assert.equal(closeRes.status, 200);

  // 10. Jalankan Tally Homomorfik & Dekripsi Total
  const tallyRes = await fetch(`${baseUrl}/api/admin/tally`, {
    method: 'POST',
    headers: adminHeaders
  });
  const tallyData = await tallyRes.json();
  assert.equal(tallyRes.status, 200);
  assert.equal(tallyData.state, 'TALLIED');

  // 11. Periksa Hasil Akhir Melalui GET /api/results
  const resultsRes = await fetch(`${baseUrl}/api/results`);
  const resultsData = await resultsRes.json();
  assert.equal(resultsRes.status, 200);
  assert.equal(resultsData.V, 5);
  assert.equal(resultsData.consistent, true, 'Audit konsistensi sum(T_j) == V harus valid');

  const perCandidate = resultsData.perCandidate;
  assert.equal(perCandidate.length, 3);
  assert.equal(perCandidate[0].T, 3, 'Kandidat 1 harus mendapatkan tepat 3 suara');
  assert.equal(perCandidate[1].T, 1, 'Kandidat 2 harus mendapatkan tepat 1 suara');
  assert.equal(perCandidate[2].T, 1, 'Kandidat 3 harus mendapatkan tepat 1 suara');
});

test('End-to-End: Re-open Voting dari status CLOSED & Proteksi Voting saat Ditutup', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    server.close();
  });

  const adminHeaders = {
    'Content-Type': 'application/json',
    'x-admin-token': CONFIG.ADMIN_TOKEN
  };

  // 1. Setup & Daftarkan Voter
  const setupRes = await fetch(`${baseUrl}/api/admin/setup`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ mode: 'demo' })
  });
  const setupData = await setupRes.json();
  const rawP = fromHex(setupData.params.p);
  const rawG = fromHex(setupData.params.g);
  const validA = toHex(modExp(rawG, 5n, rawP));

  await fetch(`${baseUrl}/api/admin/voters`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ voters: [{ id: 'V100', pin: '999999' }] })
  });

  // 2. Buka Pemungutan Suara
  const openRes1 = await fetch(`${baseUrl}/api/admin/open`, {
    method: 'POST',
    headers: adminHeaders
  });
  const openData1 = await openRes1.json();
  assert.equal(openData1.state, 'VOTING');

  // 3. Tutup Pemungutan Suara (CLOSED)
  const closeRes = await fetch(`${baseUrl}/api/admin/close`, {
    method: 'POST',
    headers: adminHeaders
  });
  const closeData = await closeRes.json();
  assert.equal(closeData.state, 'CLOSED');

  // 4. Coba Handshake saat CLOSED -> harus ditolak (HTTP 403 Forbidden)
  const blockedInit = await fetch(`${baseUrl}/api/handshake/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ voterId: 'V100', A: validA })
  });
  assert.equal(blockedInit.status, 403, 'Handshake saat status CLOSED harus ditolak 403');

  // 5. BUKA KEMBALI PEMUNGUTAN SUARA (RE-OPEN) -> harus berhasil!
  const reopenRes = await fetch(`${baseUrl}/api/admin/open`, {
    method: 'POST',
    headers: adminHeaders
  });
  const reopenData = await reopenRes.json();
  assert.equal(reopenRes.status, 200);
  assert.equal(reopenData.state, 'VOTING', 'Status harus kembali ke VOTING setelah re-open');

  // 6. Coba Handshake setelah RE-OPEN -> harus diizinkan (200 OK)
  const allowedInit = await fetch(`${baseUrl}/api/handshake/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ voterId: 'V100', A: validA })
  });
  assert.equal(allowedInit.status, 200, 'Handshake setelah re-open harus berhasil');
});
