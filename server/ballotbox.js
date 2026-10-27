// Modul Ballot Box Publik
// Menjamin penyimpanan ciphertext suara secara anonim dan pencegahan pemilihan ganda (anti-double voting)
import { isValidSubgroupElement } from '../shared/math_utils.js';
import { fromHex, canonicalJson } from '../shared/encoding.js';
import { sha256Hex } from '../shared/sha256.js';
import { markVoterVoted, hasVoted } from './voters.js';
import { logStep } from './logger.js';

let castBallots = [];

export function castBallot(voterId, ballotPayload, rawParams, expectedNumCandidates) {
  if (!voterId) throw new Error('Identitas voter tidak ditemukan pada sesi');
  if (hasVoted(voterId)) {
    const err = new Error('Pemilihan ganda ditolak: voter ini sudah pernah memberikan suara');
    err.status = 409;
    throw err;
  }

  if (!ballotPayload || !Array.isArray(ballotPayload.cts)) {
    const err = new Error('Format payload ballot tidak valid');
    err.status = 400;
    throw err;
  }

  if (ballotPayload.cts.length !== expectedNumCandidates) {
    const err = new Error(`Panjang vektor ballot (${ballotPayload.cts.length}) tidak sesuai dengan jumlah kandidat (${expectedNumCandidates})`);
    err.status = 400;
    throw err;
  }

  const { p, q } = rawParams;

  // Validasi keanggotaan subgrup untuk setiap ciphertext (c1, c2)
  for (let i = 0; i < ballotPayload.cts.length; i++) {
    const { c1, c2 } = ballotPayload.cts[i];
    if (!c1 || !c2) {
      const err = new Error(`Komponen ciphertext kandidat ${i + 1} tidak lengkap`);
      err.status = 400;
      throw err;
    }
    const c1Big = fromHex(c1);
    const c2Big = fromHex(c2);

    if (!isValidSubgroupElement(c1Big, p, q) || !isValidSubgroupElement(c2Big, p, q)) {
      const err = new Error(`Ciphertext kandidat ${i + 1} bukan elemen subgrup orde q yang valid`);
      err.status = 400;
      throw err;
    }
  }

  // Tandai voter sudah memilih secara atomik
  const marked = markVoterVoted(voterId);
  if (!marked) {
    const err = new Error('Pemilihan ganda ditolak: voter ini sudah pernah memberikan suara');
    err.status = 409;
    throw err;
  }

  // Hitung kode receipt: SHA-256 dari JSON kanonikal vektor ciphertext
  const receipt = sha256Hex(canonicalJson(ballotPayload.cts));

  // Simpan ke Ballot Box TANPA identitas voterId untuk menjaga kerahasiaan pilihan
  const record = {
    receipt,
    cts: ballotPayload.cts,
    castAt: new Date().toISOString()
  };

  castBallots.push(record);

  logStep(
    'BALLOT_BOX',
    'ELGAMAL',
    'Penerimaan & Penyimpanan Ballot',
    'receipt = SHA256(canonicalJson(cts))',
    { receipt, totalBallots: castBallots.length },
    'Ciphertext ballot berhasil disimpan ke kotak suara publik tanpa menyimpan voterId'
  );

  return { ok: true, receipt };
}

export function getBallots() {
  return [...castBallots];
}

export function getReceipts() {
  return castBallots.map(b => ({
    receipt: b.receipt,
    castAt: b.castAt
  }));
}

export function getBallotCount() {
  return castBallots.length;
}

export function resetBallotBox() {
  castBallots = [];
}
