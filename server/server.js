// Server HTTP Express untuk Sistem E-Voting Diffie-Hellman & ElGamal
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFIG } from '../config.js';
import { getState, transitionTo, requireState, STATES, resetState } from './electionState.js';
import { setupElection, getPublicParams, getRawParams, tallyElection, resetAuthority } from './authority.js';
import { registerVoters, getVoterPublicList, verifyVoterPin, resetVoters } from './voters.js';
import { castBallot, getBallots, resetBallotBox } from './ballotbox.js';
import { initHandshake, confirmHandshake, openVoterPacket, sealServerPacket, setSessionAuthed, getSession, resetSessions } from './session.js';
import { getLogs, clearLogs, logStep } from './logger.js';
import { seedDemoReadyState } from './storage.js';
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';
import { encryptBallot } from '../shared/elgamal.js';
import { toHex, fromHex } from '../shared/encoding.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp() {
  const app = express();
  app.use(express.json());

  // Sajikan berkas statis frontend (public/) dan modul bersama (shared/)
  app.use(express.static(path.resolve(__dirname, '../public')));
  app.use('/shared', express.static(path.resolve(__dirname, '../shared')));

  // Middleware pemeriksaan token admin
  function requireAdmin(req, res, next) {
    const token = req.headers['x-admin-token'] || req.body?.adminToken;
    if (token !== CONFIG.ADMIN_TOKEN) {
      return res.status(401).json({ error: 'Token otorisasi admin tidak valid' });
    }
    next();
  }

  // Verifikasi login token admin
  app.post('/api/admin/verify-token', requireAdmin, (_req, res) => {
    res.json({ ok: true, message: 'Otentikasi panitia berhasil' });
  });

  // ==========================================
  // API Publik
  // ==========================================

  // Mendapatkan parameter pemilu saat ini
  app.get('/api/params', (_req, res) => {
    res.json({
      state: getState(),
      params: getPublicParams(),
      voters: getVoterPublicList(),
      ballotCount: getBallots().length
    });
  });

  // Mendapatkan riwayat log kriptografi sisi server
  app.get('/api/log', (req, res) => {
    res.json(getLogs(req.query.sinceId));
  });

  // Mendapatkan daftar seluruh ballot terenkripsi (tanpa identitas)
  app.get('/api/ballots', (_req, res) => {
    res.json({
      ballots: getBallots(),
      total: getBallots().length
    });
  });

  // Hasil pemilu setelah status TALLIED
  let cachedTally = null;
  app.get('/api/results', (_req, res) => {
    try {
      requireState(STATES.TALLIED);
      if (!cachedTally) {
        cachedTally = tallyElection(getBallots());
      }
      res.json({ ok: true, ...cachedTally });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // ==========================================
  // API Admin & Election Authority (EA)
  // ==========================================

  // Setup pemilu: bangkitkan parameter grup dan kunci EA
  app.post('/api/admin/setup', requireAdmin, (req, res) => {
    try {
      cachedTally = null;
      resetState();
      resetBallotBox();
      resetSessions();
      const { mode, customBits, candidates } = req.body || {};
      const params = setupElection({ mode, customBits, candidates });
      transitionTo(STATES.REGISTRATION);
      res.json({ ok: true, state: getState(), params });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Daftarkan voter
  app.post('/api/admin/voters', requireAdmin, (req, res) => {
    try {
      requireState([STATES.REGISTRATION, STATES.SETUP]);
      const { voters } = req.body;
      const list = registerVoters(voters || CONFIG.DEFAULT_VOTERS);
      res.json({ ok: true, voters: list });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Buka pemungutan suara (bisa dipanggil saat REGISTRATION maupun re-open dari CLOSED)
  app.post('/api/admin/open', requireAdmin, (_req, res) => {
    try {
      cachedTally = null;
      transitionTo(STATES.VOTING);
      logStep('SERVER', 'SYSTEM', 'Buka Pemungutan Suara', '', {}, 'Status pemilu beralih ke VOTING');
      res.json({ ok: true, state: getState() });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Tutup pemungutan suara
  app.post('/api/admin/close', requireAdmin, (_req, res) => {
    try {
      transitionTo(STATES.CLOSED);
      logStep('SERVER', 'SYSTEM', 'Tutup Pemungutan Suara', '', {}, 'Status pemilu beralih ke CLOSED');
      res.json({ ok: true, state: getState() });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Jalankan agregasi homomorfik dan dekripsi total oleh EA
  app.post('/api/admin/tally', requireAdmin, (_req, res) => {
    try {
      requireState(STATES.CLOSED);
      transitionTo(STATES.TALLIED);
      cachedTally = tallyElection(getBallots());
      res.json({ ok: true, state: getState(), results: cachedTally });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Reset data pemilu atau muat data siap demo
  app.post('/api/admin/reset', requireAdmin, (req, res) => {
    try {
      cachedTally = null;
      const { demoReady, mode } = req.body || {};
      if (demoReady) {
        const result = seedDemoReadyState(mode || 'demo');
        return res.json(result);
      }
      resetState();
      resetAuthority();
      resetVoters();
      resetBallotBox();
      resetSessions();
      clearLogs();
      res.json({ ok: true, state: getState() });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Fitur bantu presentasi: simulasikan suara pemilih V002..V005
  app.post('/api/admin/simulate-votes', requireAdmin, (_req, res) => {
    try {
      requireState(STATES.VOTING);
      const rawParams = getRawParams();
      const numCandidates = rawParams.candidates?.length || CONFIG.DEFAULT_CANDIDATES.length;

      // Distribusi target demo: V001->K1, V002->K2, V003->K1, V004->K3, V005->K1
      // Simulasi untuk voter yang belum memilih di antara V002..V005
      const simulationPlan = [
        { id: 'V002', choice: 1 },
        { id: 'V003', choice: 0 },
        { id: 'V004', choice: 2 },
        { id: 'V005', choice: 0 }
      ];

      const simulated = [];
      for (const item of simulationPlan) {
        try {
          const enc = encryptBallot(rawParams, rawParams.h, item.choice, numCandidates);
          const hexCts = enc.cts.map(c => ({ c1: toHex(c.c1), c2: toHex(c.c2) }));
          const castRes = castBallot(item.id, { cts: hexCts }, rawParams, numCandidates);
          simulated.push({ voterId: item.id, choice: item.choice, receipt: castRes.receipt });
        } catch {
          // Lewati jika voter sudah memilih
        }
      }

      res.json({ ok: true, simulated, totalBallots: getBallots().length });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // ==========================================
  // API Voter: Protokol Diffie-Hellman & Suara
  // ==========================================

  // Langkah 1: Inisialisasi Handshake DH (Voter mengirim A = g^a mod p)
  app.post('/api/handshake/init', (req, res) => {
    try {
      const { voterId, A } = req.body || {};
      if (!voterId || !A) {
        return res.status(400).json({ error: 'voterId dan A diperlukan' });
      }
      const handshake = initHandshake(voterId, A);
      res.json({ ok: true, ...handshake });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Langkah 2: Konfirmasi Handshake DH (Voter membuktikan kepemilikan K via paket aman)
  app.post('/api/handshake/confirm', (req, res) => {
    try {
      const { sessionId, seq, ct, tag } = req.body || {};
      if (!sessionId || !ct || !tag) {
        return res.status(400).json({ error: 'sessionId dan paket aman diperlukan' });
      }
      const replyPacket = confirmHandshake(sessionId, { seq, ct, tag });
      res.json({ ok: true, packet: replyPacket });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Langkah 3: Login Voter di dalam Saluran Terenkripsi
  app.post('/api/login', (req, res) => {
    try {
      const { sessionId, seq, ct, tag } = req.body || {};
      if (!sessionId || !ct || !tag) {
        return res.status(400).json({ error: 'sessionId dan paket aman diperlukan' });
      }

      const payload = openVoterPacket(sessionId, { seq, ct, tag }, false);
      const { voterId, pin } = payload || {};

      const session = getSession(sessionId);
      if (session && session.voterId !== voterId) {
        return res.status(401).json({ error: 'voterId pada payload tidak sesuai dengan inisialisasi sesi' });
      }

      const verifyRes = verifyVoterPin(voterId, pin);
      if (!verifyRes.ok) {
        return res.status(401).json({ error: verifyRes.error, remainingAttempts: verifyRes.remainingAttempts });
      }

      setSessionAuthed(sessionId, true);

      logStep(
        'SERVER',
        'CHANNEL',
        `Autentikasi PIN Berhasil: Voter ${voterId}`,
        'PIN dikirim melalui ciphertext saluran DH, diverifikasi via constantTimeEqual',
        { voterId },
        'Login voter berhasil; sesi diberi izin untuk memberikan suara'
      );

      const rawParams = getRawParams();
      const replyData = {
        ok: true,
        voterId,
        candidates: rawParams.candidates || CONFIG.DEFAULT_CANDIDATES,
        publicKey: {
          p: toHex(rawParams.p),
          q: toHex(rawParams.q),
          g: toHex(rawParams.g),
          h: toHex(rawParams.h)
        }
      };

      const secureReply = sealServerPacket(sessionId, replyData);
      res.json({ ok: true, packet: secureReply });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // Langkah 4: Pengiriman Suara (Ballot ElGamal) di dalam Saluran Terenkripsi
  app.post('/api/vote', (req, res) => {
    try {
      requireState(STATES.VOTING);
      const { sessionId, seq, ct, tag } = req.body || {};
      if (!sessionId || !ct || !tag) {
        return res.status(400).json({ error: 'sessionId dan paket aman diperlukan' });
      }

      const session = getSession(sessionId);
      if (!session) {
        return res.status(401).json({ error: 'Sesi tidak ditemukan atau kedaluwarsa' });
      }

      const payload = openVoterPacket(sessionId, { seq, ct, tag }, true);
      const { ballot } = payload || {};

      const rawParams = getRawParams();
      const numCandidates = rawParams.candidates?.length || CONFIG.DEFAULT_CANDIDATES.length;

      const castResult = castBallot(session.voterId, ballot, rawParams, numCandidates);

      const secureReply = sealServerPacket(sessionId, {
        ok: true,
        receipt: castResult.receipt,
        message: 'Suara berhasil diterima dan tersimpan di Ballot Box'
      });

      res.json({ ok: true, packet: secureReply });
    } catch (err) {
      res.status(err.status || 400).json({ error: err.message });
    }
  });

  // ==========================================
  // Playground Lab API (Hitungan Terisolasi)
  // ==========================================

  app.post('/api/lab/dh-step', (req, res) => {
    try {
      const { p: pHex, q: qHex, g: gHex, priv: privHex, otherPub: otherPubHex } = req.body;
      const params = { p: fromHex(pHex), q: fromHex(qHex), g: fromHex(gHex) };
      const priv = fromHex(privHex);
      const pub = dhGenerateKeyPair(params, priv).pub;
      let K = null;
      if (otherPubHex) {
        const otherPub = fromHex(otherPubHex);
        K = dhComputeShared(params, priv, otherPub);
      }
      res.json({
        ok: true,
        pub: toHex(pub),
        K: K !== null ? toHex(K) : null
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  return app;
}

// Jalankan server jika berkas ini dieksekusi langsung
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = createApp();
  // Seeding otomatis state siap demo saat server pertama kali dijalankan
  seedDemoReadyState(CONFIG.DEFAULT_MODE);
  app.listen(CONFIG.PORT, () => {
    console.log(`================================================================`);
    console.log(`✓ Server E-Voting Diffie-Hellman & ElGamal berjalan pada:`);
    console.log(`  http://localhost:${CONFIG.PORT}`);
    console.log(`✓ Mode Kripto Default: ${CONFIG.DEFAULT_MODE} (32-bit Safe Prime)`);
    console.log(`✓ 5 Pemilih Demo Siap: V001..V005 (PIN: 111111..555555)`);
    console.log(`================================================================`);
  });
}
