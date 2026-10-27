// Pengelolaan Data Pemilih Terdaftar, Salt & Hash PIN, dan Proteksi Lockout
import { randomBytes } from '../shared/rng.js';
import { sha256Hex } from '../shared/sha256.js';
import { constantTimeEqual } from '../shared/hmac.js';
import { hexToBytes, concatBytes, utf8ToBytes, bytesToHex } from '../shared/encoding.js';
import { CONFIG } from '../config.js';

const votersMap = new Map();

export function registerVoters(voterList) {
  if (!Array.isArray(voterList)) throw new TypeError('voterList harus berupa array');

  for (const v of voterList) {
    if (!v.id || !v.pin) throw new Error('Setiap voter harus memiliki id dan pin');
    const saltBytes = randomBytes(16);
    const pinBytes = utf8ToBytes(v.pin);
    const pinHash = sha256Hex(concatBytes(saltBytes, pinBytes));

    votersMap.set(v.id, {
      id: v.id,
      saltHex: bytesToHex(saltBytes),
      pinHash,
      hasVoted: false,
      failedAttempts: 0,
      locked: false
    });
  }

  return getVoterPublicList();
}

export function getVoter(voterId) {
  return votersMap.get(voterId) || null;
}

export function verifyVoterPin(voterId, pin) {
  const voter = votersMap.get(voterId);
  if (!voter) {
    return { ok: false, error: 'Kredensial tidak valid' };
  }

  if (voter.locked) {
    return { ok: false, error: 'Akun terkunci akibat terlalu banyak percobaan login yang gagal' };
  }

  const saltBytes = hexToBytes(voter.saltHex);
  const pinBytes = utf8ToBytes(String(pin));
  const candidateHash = sha256Hex(concatBytes(saltBytes, pinBytes));

  const isMatch = constantTimeEqual(hexToBytes(candidateHash), hexToBytes(voter.pinHash));

  if (isMatch) {
    voter.failedAttempts = 0;
    return { ok: true, voterId };
  }

  voter.failedAttempts++;
  if (voter.failedAttempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
    voter.locked = true;
    return { ok: false, error: 'Akun terkunci setelah 3 kali percobaan gagal', locked: true };
  }

  return { ok: false, error: 'Kredensial tidak valid', remainingAttempts: CONFIG.MAX_LOGIN_ATTEMPTS - voter.failedAttempts };
}

export function markVoterVoted(voterId) {
  const voter = votersMap.get(voterId);
  if (!voter) throw new Error(`Voter '${voterId}' tidak terdaftar`);
  if (voter.hasVoted) return false;
  voter.hasVoted = true;
  return true;
}

export function hasVoted(voterId) {
  const voter = votersMap.get(voterId);
  return voter ? voter.hasVoted : false;
}

export function getVoterPublicList() {
  const list = [];
  for (const v of votersMap.values()) {
    list.push({
      id: v.id,
      hasVoted: v.hasVoted,
      locked: v.locked
    });
  }
  return list;
}

export function resetVoters() {
  votersMap.clear();
}
