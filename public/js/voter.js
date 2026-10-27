// Logika Sisi Klien untuk Bilik Suara Pemilih (Voter)
import { CryptoLogPanel } from './logPanel.js';
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';
import { elgamalVerify, encryptBallot } from '../shared/elgamal.js';
import { deriveKeys, seal, open } from '../shared/channel.js';
import { fromHex, toHex } from '../shared/encoding.js';

const logPanel = new CryptoLogPanel('crypto-log-container');
logPanel.startAutoPoll(2000);

let cryptoParams = null; // { p, q, g }
let publicKeyH = null;
let serverSignPubYs = null;
let voterId = 'V001';
let voterDhKey = null;
let serverB = null;
let sessionId = null;
let sharedK = null;
let channelKeys = null;
let clientSeq = 0;
let serverSeqIn = 0;
let candidates = [];
let selectedCandidateIndex = 0;
let clientBallot = null;
let lastVotePacket = null;
let currentElectionState = 'SETUP';

function showNotification(message, isError = false) {
  let toast = document.getElementById('voter-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'voter-toast';
    toast.style.position = 'fixed';
    toast.style.bottom = '20px';
    toast.style.left = '20px';
    toast.style.padding = '0.75rem 1.25rem';
    toast.style.borderRadius = '0.5rem';
    toast.style.fontSize = '0.875rem';
    toast.style.fontWeight = '500';
    toast.style.zIndex = '9999';
    toast.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.5)';
    toast.style.transition = 'all 0.3s ease';
    document.body.appendChild(toast);
  }
  toast.style.backgroundColor = isError ? '#ef4444' : '#10b981';
  toast.style.color = '#ffffff';
  toast.textContent = message;
  toast.style.display = 'block';
  toast.style.opacity = '1';

  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => { toast.style.display = 'none'; }, 300);
  }, 3500);
}

function goToStep(stepNum) {
  for (let i = 1; i <= 4; i++) {
    const nav = document.getElementById(`step-nav-${i}`);
    const card = document.getElementById(`card-step-${i}`);
    if (nav) {
      if (i < stepNum) {
        nav.className = 'step-item completed';
      } else if (i === stepNum) {
        nav.className = 'step-item active';
      } else {
        nav.className = 'step-item';
      }
    }
    if (card) {
      card.style.display = i === stepNum ? 'block' : 'none';
    }
  }
}

function updateBoothState(state) {
  currentElectionState = state;
  const stateBadge = document.getElementById('current-state-badge');
  const banner = document.getElementById('booth-status-banner');
  const bannerText = document.getElementById('booth-status-text');
  const btnStartDh = document.getElementById('btn-start-dh');

  if (stateBadge) {
    stateBadge.textContent = `Status: ${state}`;
    stateBadge.className = `status-badge status-${state}`;
  }

  if (banner && bannerText && btnStartDh) {
    banner.style.display = 'block';
    if (state === 'VOTING') {
      banner.style.borderColor = '#10b981';
      banner.style.background = 'rgba(16, 185, 129, 0.1)';
      bannerText.style.color = '#34d399';
      bannerText.textContent = '🟢 BILIK SUARA DIBUKA: Pemungutan suara sedang aktif. Silakan pilih ID Anda dan mulai Langkah 1.';
      btnStartDh.removeAttribute('disabled');
      btnStartDh.style.opacity = '1';
    } else {
      banner.style.borderColor = '#f59e0b';
      banner.style.background = 'rgba(245, 158, 11, 0.1)';
      bannerText.style.color = '#fbbf24';
      bannerText.textContent = `⚠️ BILIK SUARA DITUTUP (Status Pemilu: ${state}). Pemungutan suara saat ini tidak aktif. Silakan tunggu Panitia membuka bilik suara.`;
      btnStartDh.setAttribute('disabled', 'true');
      btnStartDh.style.opacity = '0.5';
    }
  }
}

function populateVotersDropdown(voters) {
  const select = document.getElementById('voter-id-select');
  if (!select) return;

  const currentVal = select.value;
  select.textContent = '';

  if (!voters || voters.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '-- Belum Ada Pemilih Terdaftar --';
    select.appendChild(opt);
    return;
  }

  const defaultOpt = document.createElement('option');
  defaultOpt.value = '';
  defaultOpt.textContent = '-- Pilih ID Pemilih Anda --';
  select.appendChild(defaultOpt);

  voters.forEach(v => {
    const opt = document.createElement('option');
    opt.value = v.id;
    if (v.hasVoted) {
      opt.textContent = `${v.id} (Sudah Memilih - Selesai)`;
      opt.disabled = true;
    } else if (v.locked) {
      opt.textContent = `${v.id} (Terkunci 3x Gagal)`;
      opt.disabled = true;
    } else {
      opt.textContent = `${v.id} (Belum Memilih - Siap)`;
    }
    select.appendChild(opt);
  });

  const customOpt = document.createElement('option');
  customOpt.value = '__custom__';
  customOpt.textContent = '-- Masukkan ID Pemilih Manual --';
  select.appendChild(customOpt);

  if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
    select.value = currentVal;
  } else {
    // Cari yang belum memilih pertama
    const firstEligible = voters.find(v => !v.hasVoted && !v.locked);
    if (firstEligible) {
      select.value = firstEligible.id;
    }
  }
}

async function loadElectionParams() {
  try {
    const res = await fetch('/api/params');
    if (!res.ok) return;
    const data = await res.json();

    updateBoothState(data.state);

    if (data.params) {
      cryptoParams = {
        p: fromHex(data.params.p),
        q: fromHex(data.params.q),
        g: fromHex(data.params.g)
      };
      publicKeyH = fromHex(data.params.h);
      serverSignPubYs = fromHex(data.params.ys);
      candidates = data.params.candidates || [];
    }

    if (data.voters) {
      populateVotersDropdown(data.voters);
    }
  } catch (err) {
    console.error('Gagal memuat parameter pemilu:', err);
  }
}

function renderCandidatesRadio() {
  const container = document.getElementById('candidates-radio-container');
  if (!container) return;
  container.textContent = '';

  candidates.forEach((candName, idx) => {
    const label = document.createElement('label');
    label.style.display = 'flex';
    label.style.alignItems = 'center';
    label.style.gap = '0.5rem';
    label.style.padding = '0.6rem 0.8rem';
    label.style.backgroundColor = 'var(--bg-primary)';
    label.style.border = '1px solid var(--border-color)';
    label.style.borderRadius = '0.375rem';
    label.style.cursor = 'pointer';

    const radio = document.createElement('input');
    radio.type = 'radio';
    radio.name = 'candidate';
    radio.value = String(idx);
    if (idx === 0) radio.checked = true;

    radio.addEventListener('change', () => {
      selectedCandidateIndex = idx;
    });

    const span = document.createElement('span');
    span.style.fontWeight = '500';
    span.textContent = candName;

    label.appendChild(radio);
    label.appendChild(span);
    container.appendChild(label);
  });
}

function resetBoothState() {
  voterDhKey = null;
  serverB = null;
  sessionId = null;
  sharedK = null;
  channelKeys = null;
  clientSeq = 0;
  serverSeqIn = 0;
  clientBallot = null;
  lastVotePacket = null;

  const pinInput = document.getElementById('voter-pin-input');
  if (pinInput) pinInput.value = '';

  const dhBox = document.getElementById('dh-result-box');
  if (dhBox) dhBox.style.display = 'none';

  const encBox = document.getElementById('encryption-result-box');
  if (encBox) encBox.style.display = 'none';

  const rcBox = document.getElementById('receipt-display-box');
  if (rcBox) rcBox.style.display = 'none';

  goToStep(1);
  loadElectionParams();
  showNotification('✓ Bilik suara siap untuk pemilih berikutnya.');
}

document.addEventListener('DOMContentLoaded', () => {
  loadElectionParams();
  setInterval(loadElectionParams, 3000);

  // Toggle manual voter ID input
  const select = document.getElementById('voter-id-select');
  const groupCustom = document.getElementById('group-custom-voter');
  select?.addEventListener('change', (e) => {
    if (groupCustom) {
      groupCustom.style.display = e.target.value === '__custom__' ? 'block' : 'none';
    }
  });

  // Langkah 1: Handshake DH
  document.getElementById('btn-start-dh')?.addEventListener('click', async () => {
    if (currentElectionState !== 'VOTING') {
      showNotification('Bilik suara sedang ditutup! Harap tunggu panitia membuka voting.', true);
      return;
    }

    const selVal = select?.value || '';
    if (selVal === '__custom__') {
      const customInput = document.getElementById('voter-id-custom');
      voterId = customInput?.value?.trim() || '';
    } else {
      voterId = selVal;
    }

    if (!voterId) {
      showNotification('Silakan pilih atau masukkan ID Pemilih Anda', true);
      return;
    }

    if (!cryptoParams) {
      await loadElectionParams();
      if (!cryptoParams) {
        showNotification('Parameter pemilu belum siap dari Admin', true);
        return;
      }
    }

    try {
      // 1. Voter bangkitkan a dan A = g^a mod p di browser
      voterDhKey = dhGenerateKeyPair(cryptoParams);

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'DH',
        step: `Handshake DH Klien: Voter ${voterId}`,
        formula: 'a in [2, q-1], A = g^a mod p',
        values: {
          a: toHex(voterDhKey.priv),
          A: toHex(voterDhKey.pub)
        },
        summary: 'Kunci privat a tersimpan aman di browser voter; A dikirim ke server'
      });

      // 2. Kirim A ke server
      const initRes = await fetch('/api/handshake/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voterId, A: toHex(voterDhKey.pub) })
      });
      const initData = await initRes.json();
      if (!initRes.ok) throw new Error(initData.error || 'Gagal inisialisasi handshake');

      sessionId = initData.sessionId;
      serverB = fromHex(initData.B);

      // 3. Verifikasi tanda tangan ElGamal server [BONUS]
      const transcriptStr = `${sessionId}|${toHex(voterDhKey.pub)}|${initData.B}`;
      const sigValid = elgamalVerify(cryptoParams, serverSignPubYs, transcriptStr, {
        r: fromHex(initData.sig.r),
        s: fromHex(initData.sig.s)
      });

      if (!sigValid) {
        throw new Error('Verifikasi tanda tangan ElGamal server GAGAL! Kemungkinan serangan MITM.');
      }

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'ELGAMAL',
        step: 'Verifikasi Tanda Tangan Server [BONUS]',
        formula: 'g^H == ys^r * r^s mod p',
        values: { r: initData.sig.r, s: initData.sig.s },
        summary: 'Tanda tangan server valid: menjamin keaslian nilai B dan menangkal MITM'
      });

      // 4. Voter hitung K = B^a mod p dan turunkan kunci sesi
      sharedK = dhComputeShared(cryptoParams, voterDhKey.priv, serverB);
      channelKeys = deriveKeys(cryptoParams, sharedK, sessionId, voterDhKey.pub, serverB);

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'DH',
        step: 'Perhitungan Shared Secret K Sisi Voter',
        formula: 'K = B^a mod p',
        values: { K: toHex(sharedK) },
        summary: 'Shared secret K berhasil dihitung; identik dengan K sisi server'
      });

      // 5. Kirim konfirmasi paket aman seq: 1 (READY|sessionId)
      clientSeq = 1;
      const confirmPacket = seal(channelKeys, 1, clientSeq, `READY|${sessionId}`);
      const confirmRes = await fetch('/api/handshake/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, ...confirmPacket })
      });
      const confirmData = await confirmRes.json();
      if (!confirmRes.ok) throw new Error(confirmData.error || 'Konfirmasi handshake ditolak');

      // Buka paket balasan dari server
      open(channelKeys, 2, confirmData.packet, serverSeqIn);
      serverSeqIn = confirmData.packet.seq;

      // Tampilkan hasil di box
      const box = document.getElementById('dh-result-box');
      if (box) box.style.display = 'block';

      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };

      setVal('voter-val-a', toHex(voterDhKey.priv));
      setVal('voter-val-A', toHex(voterDhKey.pub));
      setVal('voter-val-B', initData.B);
      setVal('voter-val-K', toHex(sharedK));

      showNotification('✓ Handshake DH Sukses! K voter == K server terbukti.');
    } catch (err) {
      showNotification(`Handshake Gagal: ${err.message}`, true);
    }
  });

  // Tombol lanjut ke langkah 2
  document.getElementById('btn-goto-step-2')?.addEventListener('click', () => {
    goToStep(2);
  });

  // Langkah 2: Login Aman di Saluran DH
  document.getElementById('btn-submit-login')?.addEventListener('click', async () => {
    const pin = document.getElementById('voter-pin-input')?.value?.trim();
    if (!pin) {
      showNotification('Silakan masukkan PIN', true);
      return;
    }

    try {
      clientSeq++;
      // Enkripsi { voterId, pin } ke dalam paket aman
      const loginPacket = seal(channelKeys, 1, clientSeq, { voterId, pin });

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'CHANNEL',
        step: `Login Voter Terenkripsi: ${voterId}`,
        formula: 'ct = plaintext XOR keystream, tag = HMAC(macKey, dir||seq||ct)',
        values: { seq: clientSeq, tag: loginPacket.tag },
        summary: 'PIN dienkripsi dengan kunci sesi DH sebelum dikirim ke jaringan'
      });

      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, ...loginPacket })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login gagal');

      // Buka balasan terenkripsi dari server
      const serverPayload = open(channelKeys, 2, data.packet, serverSeqIn);
      serverSeqIn = data.packet.seq;

      if (serverPayload.candidates) {
        candidates = serverPayload.candidates;
      }
      renderCandidatesRadio();

      showNotification('✓ Login Berhasil! Akses bilik suara diberikan.');
      goToStep(3);
    } catch (err) {
      showNotification(`Login Gagal: ${err.message}`, true);
    }
  });

  // Langkah 3: Enkripsi Suara di Browser (ElGamal Eksponensial)
  document.getElementById('btn-encrypt-vote')?.addEventListener('click', () => {
    if (!cryptoParams || !publicKeyH) {
      showNotification('Parameter ElGamal belum lengkap', true);
      return;
    }

    try {
      // clientBallot: { cts, nonces, mValues, vector }
      clientBallot = encryptBallot(cryptoParams, publicKeyH, selectedCandidateIndex, candidates.length);

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'ELGAMAL',
        step: `Enkripsi Suara di Browser (Pilihan: Kandidat ${selectedCandidateIndex + 1})`,
        formula: 'm_i = g^{v_i}, c1_i = g^{k_i}, c2_i = m_i * h^{k_i} mod p',
        values: {
          v: JSON.stringify(clientBallot.vector),
          k_selected: toHex(clientBallot.nonces[selectedCandidateIndex])
        },
        summary: 'Suara dienkripsi secara probabilistik dengan nonce k independen per kandidat'
      });

      // Tampilkan tabel hasil enkripsi di sisi klien
      const tbody = document.getElementById('client-ciphertext-table');
      if (tbody) {
        tbody.textContent = '';
        clientBallot.cts.forEach((ct, idx) => {
          const tr = document.createElement('tr');

          const tdCand = document.createElement('td');
          tdCand.textContent = candidates[idx] || `Kandidat ${idx + 1}`;

          const tdV = document.createElement('td');
          tdV.style.fontWeight = '700';
          tdV.style.color = clientBallot.vector[idx] === 1 ? '#34d399' : '#94a3b8';
          tdV.textContent = String(clientBallot.vector[idx]);

          const tdM = document.createElement('td');
          tdM.textContent = toHex(clientBallot.mValues[idx]);

          const tdK = document.createElement('td');
          tdK.textContent = toHex(clientBallot.nonces[idx]);

          const tdC1 = document.createElement('td');
          tdC1.textContent = toHex(ct.c1);

          const tdC2 = document.createElement('td');
          tdC2.textContent = toHex(ct.c2);

          tr.appendChild(tdCand);
          tr.appendChild(tdV);
          tr.appendChild(tdM);
          tr.appendChild(tdK);
          tr.appendChild(tdC1);
          tr.appendChild(tdC2);
          tbody.appendChild(tr);
        });
      }

      const resBox = document.getElementById('encryption-result-box');
      if (resBox) resBox.style.display = 'block';

      showNotification('✓ Suara berhasil dienkripsi dengan Exponential ElGamal!');
    } catch (err) {
      showNotification(`Enkripsi gagal: ${err.message}`, true);
    }
  });

  // Tombol lanjut ke langkah 4
  document.getElementById('btn-goto-step-4')?.addEventListener('click', () => {
    goToStep(4);
  });

  // Langkah 4: Kirim Ballot Terenkripsi ke Server
  document.getElementById('btn-cast-vote')?.addEventListener('click', async () => {
    if (!clientBallot) {
      showNotification('Silakan lakukan enkripsi suara terlebih dahulu pada Langkah 3', true);
      return;
    }

    try {
      clientSeq++;
      const hexCts = clientBallot.cts.map(c => ({ c1: toHex(c.c1), c2: toHex(c.c2) }));
      const votePayload = { ballot: { cts: hexCts } };

      const votePacket = seal(channelKeys, 1, clientSeq, votePayload);
      lastVotePacket = { ...votePacket }; // Simpan untuk pengujian replay

      logPanel.addEntry({
        actor: 'VOTER',
        algo: 'CHANNEL',
        step: 'Pengiriman Ballot Aman ke Ballot Box',
        formula: 'seal(encKey, macKey, seq, ballot)',
        values: { seq: clientSeq, tag: votePacket.tag },
        summary: 'Paket ballot dikirimkan melalui saluran terenkripsi DH'
      });

      const res = await fetch('/api/vote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, ...votePacket })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Pengiriman suara ditolak');

      const serverReply = open(channelKeys, 2, data.packet, serverSeqIn);
      serverSeqIn = data.packet.seq;

      // Tampilkan Receipt
      const receiptBox = document.getElementById('receipt-display-box');
      const receiptCodeEl = document.getElementById('voter-receipt-code');
      if (receiptBox) receiptBox.style.display = 'block';
      if (receiptCodeEl) receiptCodeEl.textContent = serverReply.receipt;

      // Update perbandingan 3 sudut pandang
      const viewVoter = document.getElementById('view-voter');
      const viewNet = document.getElementById('view-network');
      const viewSrv = document.getElementById('view-server');

      if (viewVoter) {
        viewVoter.textContent = `Pilihan: ${candidates[selectedCandidateIndex]}\nv = ${JSON.stringify(clientBallot.vector)}\nK = ${toHex(sharedK).slice(0, 16)}...`;
      }
      if (viewNet) {
        viewNet.textContent = `ct: ${votePacket.ct.slice(0, 32)}...\ntag: ${votePacket.tag}\nseq: ${votePacket.seq}`;
      }
      if (viewSrv) {
        viewSrv.textContent = `Receipt: ${serverReply.receipt}\n3 Ciphertexts ElGamal tersimpan\nVoterId: TIDAK DISIMPAN (Anonim)`;
      }

      showNotification('🎉 Suara Anda berhasil diterima dan disimpan di Ballot Box!');
    } catch (err) {
      showNotification(`Gagal mengirim suara: ${err.message}`, true);
    }
  });

  // Tombol Selesai & Keluar Bilik Suara
  document.getElementById('btn-finish-vote')?.addEventListener('click', () => {
    resetBoothState();
  });

  // Uji Serangan 1: Double Voting
  document.getElementById('btn-test-double-vote')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('attack-test-result');
    try {
      const res = await fetch('/api/handshake/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voterId, A: toHex(voterDhKey.pub) })
      });
      const data = await res.json();
      if (res.status === 409) {
        if (resultEl) {
          resultEl.style.color = '#34d399';
          resultEl.textContent = `✓ [SERANGAN DIGAGALKAN] Server menolak pemilihan ganda (HTTP 409 Conflict): "${data.error}"`;
        }
        showNotification('✓ Uji Anti-Double Voting Berhasil: Server menolak suara kedua!');
      } else {
        if (resultEl) {
          resultEl.style.color = '#ef4444';
          resultEl.textContent = `Peringatan: Response status ${res.status}`;
        }
      }
    } catch (err) {
      if (resultEl) resultEl.textContent = `Error: ${err.message}`;
    }
  });

  // Uji Serangan 2: Replay Packet Lama
  document.getElementById('btn-test-replay-vote')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('attack-test-result');
    if (!lastVotePacket) {
      showNotification('Belum ada paket vote yang pernah dikirimkan', true);
      return;
    }

    try {
      const res = await fetch('/api/vote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, ...lastVotePacket })
      });
      const data = await res.json();

      if (res.status === 409 || res.status === 401) {
        if (resultEl) {
          resultEl.style.color = '#34d399';
          resultEl.textContent = `✓ [SERANGAN DIGAGALKAN] Anti-Replay Berhasil: Packet sequence lama ditolak (HTTP ${res.status}): "${data.error}"`;
        }
        showNotification('✓ Uji Anti-Replay Berhasil: Paket lama ditolak!');
      } else {
        if (resultEl) {
          resultEl.style.color = '#ef4444';
          resultEl.textContent = `Peringatan: Response status ${res.status}`;
        }
      }
    } catch (err) {
      if (resultEl) resultEl.textContent = `Error: ${err.message}`;
    }
  });
});
