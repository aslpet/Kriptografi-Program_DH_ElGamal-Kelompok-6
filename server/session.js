// Modul Pengelolaan Sesi Diffie-Hellman dan Paket Aman Sisi Server
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';
import { deriveKeys, seal, open } from '../shared/channel.js';
import { fromHex, toHex, bytesToHex } from '../shared/encoding.js';
import { randomBytes } from '../shared/rng.js';
import { isInSubgroup } from '../shared/math_utils.js';
import { getRawParams, signHandshake } from './authority.js';
import { getVoter, hasVoted } from './voters.js';
import { requireState, STATES } from './electionState.js';
import { logStep } from './logger.js';
import { CONFIG } from '../config.js';

const sessionsMap = new Map();

export function initHandshake(voterId, A_hex) {
  // 1. Validasi state pemilu
  requireState(STATES.VOTING);

  // 2. Validasi status voter
  const voter = getVoter(voterId);
  if (!voter) {
    const err = new Error(`Voter '${voterId}' tidak terdaftar`);
    err.status = 404;
    throw err;
  }
  if (voter.locked) {
    const err = new Error(`Akun voter '${voterId}' terkunci`);
    err.status = 403;
    throw err;
  }
  if (hasVoted(voterId)) {
    const err = new Error(`Voter '${voterId}' sudah memberikan suara`);
    err.status = 409;
    throw err;
  }

  // 3. Validasi nilai publik A dari voter di subgrup orde q
  const params = getRawParams();
  const A = fromHex(A_hex);
  if (!isInSubgroup(A, params.p, params.q)) {
    const err = new Error('Nilai publik A tidak valid (bukan anggota subgrup orde q)');
    err.status = 400;
    throw err;
  }

  // 4. Server membangkitkan pasangan kunci DH (b, B = g^b mod p)
  const serverDh = dhGenerateKeyPair(params);
  const b = serverDh.priv;
  const B = serverDh.pub;

  // 5. Server menghitung shared secret K = A^b mod p
  const K = dhComputeShared(params, b, A);

  // 6. Buat sessionId dan turunkan kunci sesi (encKey, macKey)
  const sessionId = bytesToHex(randomBytes(16));
  const keys = deriveKeys(params, K, sessionId, A, B);

  // 7. [BONUS] Server menandatangani transkrip (sessionId || A || B) dengan kunci ElGamal xs
  const sig = signHandshake(sessionId, A_hex, toHex(B));

  sessionsMap.set(sessionId, {
    id: sessionId,
    voterId,
    A,
    B,
    b,
    K,
    keys,
    lastSeqIn: 0,
    seqOut: 0,
    confirmed: false,
    authed: false,
    createdAt: Date.now()
  });

  logStep(
    'SERVER',
    'DH',
    `Handshake DH Sisi Server: Voter ${voterId}`,
    'b in [2, q-1], B = g^b mod p, K = A^b mod p',
    {
      A: A_hex,
      b: toHex(b),
      B: toHex(B),
      K: toHex(K)
    },
    `Shared secret K berhasil dihitung; transkrip ditandatangani dengan kunci ElGamal server`
  );

  return {
    sessionId,
    B: toHex(B),
    sig
  };
}

export function confirmHandshake(sessionId, packet) {
  const session = sessionsMap.get(sessionId);
  if (!session) {
    const err = new Error('Sesi tidak ditemukan atau telah kedaluwarsa');
    err.status = 401;
    throw err;
  }

  // Buka paket konfirmasi seq: 1 dari voter (dir: 1)
  const plaintext = open(session.keys, 1, packet, session.lastSeqIn);
  session.lastSeqIn = packet.seq;

  const expectedMsg = `READY|${sessionId}`;
  if (plaintext !== expectedMsg) {
    const err = new Error('Pesan konfirmasi handshake tidak sesuai');
    err.status = 400;
    throw err;
  }

  session.confirmed = true;

  logStep(
    'SERVER',
    'CHANNEL',
    `Konfirmasi Kunci Sesi DH: Voter ${session.voterId}`,
    'Verifikasi HMAC(macKey, READY|sessionId)',
    { sessionId },
    'Bukti kriptografis berhasil: voter dan server memegang shared secret K yang identik'
  );

  // Balas voter dengan paket aman seq: 1 (dir: 2)
  session.seqOut = 1;
  const replyPacket = seal(session.keys, 2, session.seqOut, {
    status: 'OK',
    message: 'Handshake DH terverifikasi, saluran aman siap'
  });

  return replyPacket;
}

export function getSession(sessionId) {
  const session = sessionsMap.get(sessionId);
  if (!session) return null;
  if (Date.now() - session.createdAt > CONFIG.SESSION_TTL_MS) {
    sessionsMap.delete(sessionId);
    return null;
  }
  return session;
}

export function setSessionAuthed(sessionId, authed = true) {
  const session = getSession(sessionId);
  if (session) session.authed = authed;
}

export function openVoterPacket(sessionId, packet, requireAuthed = true) {
  const session = getSession(sessionId);
  if (!session || !session.confirmed) {
    const err = new Error('Sesi belum terkonfirmasi');
    err.status = 401;
    throw err;
  }

  if (requireAuthed && !session.authed) {
    const err = new Error('Sesi belum terotentikasi (harus login terlebih dahulu)');
    err.status = 401;
    throw err;
  }

  const payload = open(session.keys, 1, packet, session.lastSeqIn);
  session.lastSeqIn = packet.seq;
  return payload;
}

export function sealServerPacket(sessionId, payload) {
  const session = getSession(sessionId);
  if (!session) {
    const err = new Error('Sesi tidak ditemukan');
    err.status = 401;
    throw err;
  }

  session.seqOut++;
  return seal(session.keys, 2, session.seqOut, payload);
}

export function resetSessions() {
  sessionsMap.clear();
}
