// Logika Sisi Klien untuk Panel Admin & Election Authority
import { CryptoLogPanel } from './logPanel.js';

const logPanel = new CryptoLogPanel('crypto-log-container');
logPanel.startAutoPoll(2000);

const demoPins = {
  V001: '111111',
  V002: '222222',
  V003: '333333',
  V004: '444444',
  V005: '555555'
};

function showNotification(message, isError = false) {
  let toast = document.getElementById('admin-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'admin-toast';
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

function getAdminToken() {
  return sessionStorage.getItem('adminToken') || '';
}

function setAdminToken(token) {
  if (token) {
    sessionStorage.setItem('adminToken', token);
  } else {
    sessionStorage.removeItem('adminToken');
  }
}

function checkAdminAuthView() {
  const token = getAdminToken();
  const guard = document.getElementById('admin-login-guard');
  const dashboard = document.getElementById('admin-dashboard-view');
  const logoutBtn = document.getElementById('btn-admin-logout');

  if (token) {
    if (guard) guard.style.display = 'none';
    if (dashboard) dashboard.style.display = 'grid';
    if (logoutBtn) logoutBtn.style.display = 'inline-flex';
    loadServerParams();
  } else {
    if (guard) guard.style.display = 'flex';
    if (dashboard) dashboard.style.display = 'none';
    if (logoutBtn) logoutBtn.style.display = 'none';
  }
}

function updateStateBadge(state) {
  const badge = document.getElementById('current-state-badge');
  const reopenBtn = document.getElementById('btn-reopen-voting');
  const openBtn = document.getElementById('btn-open-voting');

  if (badge) {
    badge.textContent = `Status: ${state}`;
    badge.className = `status-badge status-${state}`;
  }

  // Tampilkan tombol Buka Kembali saat status CLOSED
  if (reopenBtn && openBtn) {
    if (state === 'CLOSED') {
      reopenBtn.style.display = 'inline-flex';
      openBtn.style.display = 'none';
    } else {
      reopenBtn.style.display = 'none';
      openBtn.style.display = 'inline-flex';
    }
  }
}

function displayParams(params) {
  if (!params) return;
  const area = document.getElementById('params-display-area');
  const badge = document.getElementById('badge-param-status');

  if (area) area.style.display = 'block';
  if (badge) {
    badge.textContent = `${params.bits}-bit (${params.mode})`;
    badge.className = 'badge badge-ELGAMAL';
  }

  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val || '-';
  };

  setVal('val-p', params.p);
  setVal('val-q', params.q);
  setVal('val-g', params.g);
  setVal('val-h', params.h);
  setVal('val-ys', params.ys);
}

function renderVotersTable(voters) {
  const tbody = document.getElementById('voters-table-body');
  const countBadge = document.getElementById('voter-count-badge');
  if (!tbody) return;

  tbody.textContent = '';

  if (!voters || voters.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.textContent = 'Belum ada pemilih terdaftar.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    if (countBadge) countBadge.textContent = '0 Pemilih';
    return;
  }

  if (countBadge) countBadge.textContent = `${voters.length} Pemilih`;

  for (const v of voters) {
    const tr = document.createElement('tr');

    const tdId = document.createElement('td');
    tdId.style.fontWeight = '600';
    tdId.textContent = v.id;

    const tdVoted = document.createElement('td');
    const votedBadge = document.createElement('span');
    votedBadge.className = v.hasVoted ? 'badge badge-ELGAMAL' : 'badge badge-CHANNEL';
    votedBadge.textContent = v.hasVoted ? 'Sudah Memilih' : 'Belum Memilih';
    tdVoted.appendChild(votedBadge);

    const tdLock = document.createElement('td');
    const lockBadge = document.createElement('span');
    lockBadge.className = v.locked ? 'badge badge-ATTACK' : 'badge badge-DH';
    lockBadge.textContent = v.locked ? 'Terkunci (3x Gagal)' : 'Aktif';
    tdLock.appendChild(lockBadge);

    const tdPin = document.createElement('td');
    tdPin.className = 'mono';
    tdPin.style.color = '#38bdf8';
    tdPin.textContent = demoPins[v.id] ? `${demoPins[v.id]} (demo)` : '******';

    tr.appendChild(tdId);
    tr.appendChild(tdVoted);
    tr.appendChild(tdLock);
    tr.appendChild(tdPin);
    tbody.appendChild(tr);
  }
}

async function loadServerParams() {
  try {
    const res = await fetch('/api/params');
    if (!res.ok) return;
    const data = await res.json();
    updateStateBadge(data.state);
    if (data.params) {
      displayParams(data.params);
    }
    renderVotersTable(data.voters);
  } catch (err) {
    console.error('Gagal memuat status server:', err);
  }
}

// Inisialisasi event listener
document.addEventListener('DOMContentLoaded', () => {
  checkAdminAuthView();

  // 0. Login & Logout Panitia
  document.getElementById('btn-submit-admin-login')?.addEventListener('click', async () => {
    const tokenInput = document.getElementById('admin-login-token');
    const token = tokenInput?.value?.trim() || '';

    try {
      const res = await fetch('/api/admin/verify-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Token admin salah');

      setAdminToken(token);
      checkAdminAuthView();
      showNotification('✓ Berhasil masuk ke Portal Panitia Pemilihan!');
    } catch (err) {
      showNotification(`Gagal masuk: ${err.message}`, true);
    }
  });

  document.getElementById('btn-admin-logout')?.addEventListener('click', () => {
    setAdminToken('');
    checkAdminAuthView();
    showNotification('✓ Anda telah keluar dari sesi Panitia.');
  });

  // 1. Bangkitkan Parameter & Keypair EA
  document.getElementById('btn-generate-params')?.addEventListener('click', async () => {
    const mode = document.getElementById('select-mode')?.value || 'demo';
    const candInput = document.getElementById('input-custom-candidates')?.value || '';
    const candidates = candInput.split(',').map(s => s.trim()).filter(Boolean);
    const token = getAdminToken();
    const progressEl = document.getElementById('worker-progress');

    if (progressEl) progressEl.textContent = 'Membangkitkan parameter dan kunci EA...';

    try {
      const res = await fetch('/api/admin/setup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        },
        body: JSON.stringify({ mode, candidates: candidates.length > 0 ? candidates : undefined })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal membangkitkan parameter');

      displayParams(data.params);
      updateStateBadge(data.state);
      if (progressEl) progressEl.textContent = '✓ Parameter berhasil dibangkitkan!';
      setTimeout(() => { if (progressEl) progressEl.textContent = ''; }, 3000);
      logPanel.pollServerLogs();
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
      if (progressEl) progressEl.textContent = '';
    }
  });

  // 2a. Daftarkan Voter Default
  document.getElementById('btn-load-default-voters')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/voters', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        },
        body: JSON.stringify({})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal mendaftarkan voter');
      renderVotersTable(data.voters);
      logPanel.pollServerLogs();
      showNotification('✓ 5 Pemilih default (V001–V005) berhasil didaftarkan!');
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 2b. Tambah Voter Manual
  document.getElementById('btn-add-single-voter')?.addEventListener('click', async () => {
    const idInput = document.getElementById('new-voter-id');
    const pinInput = document.getElementById('new-voter-pin');
    const id = idInput?.value?.trim();
    const pin = pinInput?.value?.trim();

    if (!id || !pin) {
      showNotification('ID Pemilih dan PIN harus diisi', true);
      return;
    }

    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/voters', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        },
        body: JSON.stringify({ voters: [{ id, pin }] })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal menambahkan pemilih');

      demoPins[id] = pin;
      if (idInput) idInput.value = '';
      if (pinInput) pinInput.value = '';

      renderVotersTable(data.voters);
      logPanel.pollServerLogs();
      showNotification(`✓ Pemilih baru ${id} berhasil ditambahkan!`);
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 3a. Buka Pemungutan Suara
  const handleOpenVoting = async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/open', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal membuka pemungutan suara');
      updateStateBadge(data.state);
      logPanel.pollServerLogs();
      showNotification('✓ Pemungutan suara resmi dibuka! Status: VOTING');
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  };

  document.getElementById('btn-open-voting')?.addEventListener('click', handleOpenVoting);
  document.getElementById('btn-reopen-voting')?.addEventListener('click', handleOpenVoting);

  // 3b. Tutup Pemungutan Suara
  document.getElementById('btn-close-voting')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/close', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal menutup pemungutan suara');
      updateStateBadge(data.state);
      logPanel.pollServerLogs();
      showNotification('✓ Pemungutan suara ditutup! Status: CLOSED (Bisa dibuka kembali kapan saja).');
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 3c. Jalankan Tally Homomorfik & Dekripsi Total EA
  document.getElementById('btn-run-tally')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/tally', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal menjalankan tally');
      updateStateBadge(data.state);
      logPanel.pollServerLogs();

      const summaryArea = document.getElementById('tally-summary-area');
      if (summaryArea && data.results) {
        summaryArea.style.display = 'block';
        summaryArea.textContent = '';

        const card = document.createElement('div');
        card.className = 'card';
        card.style.background = 'rgba(16, 185, 129, 0.1)';
        card.style.borderColor = '#10b981';

        const h4 = document.createElement('h4');
        h4.style.color = '#34d399';
        h4.style.marginBottom = '0.5rem';
        h4.textContent = `🎉 Tally Homomorfik Selesai: ${data.results.V} Total Suara Masuk`;
        card.appendChild(h4);

        const ul = document.createElement('ul');
        ul.style.paddingLeft = '1.25rem';
        ul.style.fontSize = '0.9rem';

        for (const item of data.results.perCandidate) {
          const li = document.createElement('li');
          li.textContent = `${item.name}: ${item.T} Suara (Ditemukan dalam ${item.iterations} iterasi dlog)`;
          ul.appendChild(li);
        }
        card.appendChild(ul);

        const linkP = document.createElement('p');
        linkP.style.marginTop = '0.75rem';
        const a = document.createElement('a');
        a.href = '/results.html';
        a.className = 'btn btn-success btn-sm';
        a.textContent = '📊 Buka Halaman Hasil & Audit Lengkap →';
        linkP.appendChild(a);
        card.appendChild(linkP);

        summaryArea.appendChild(card);
      }
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 4. Muat Pemilu Siap Demo (1-Klik)
  document.getElementById('btn-seed-demo')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        },
        body: JSON.stringify({ demoReady: true, mode: 'demo' })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal seeding pemilu siap demo');
      updateStateBadge(data.state);
      displayParams(data.params);
      renderVotersTable(data.voters);
      logPanel.pollServerLogs();
      showNotification('✓ Pemilu Siap Demo berhasil dimuat! Parameter 32-bit siap, 5 voter terdaftar, status: VOTING.');
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 5. Simulasikan Suara V002–V005
  document.getElementById('btn-simulate-votes')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/simulate-votes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal simulasi suara');
      logPanel.pollServerLogs();
      loadServerParams();
      showNotification(`✓ ${data.simulated.length} suara otomatis berhasil dikirimkan ke Ballot Box! Total saat ini: ${data.totalBallots} ballot.`);
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });

  // 6. Reset Total
  document.getElementById('btn-reset-all')?.addEventListener('click', async () => {
    const token = getAdminToken();
    try {
      const res = await fetch('/api/admin/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-admin-token': token
        },
        body: JSON.stringify({ demoReady: false })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gagal reset');
      updateStateBadge(data.state);
      document.getElementById('params-display-area').style.display = 'none';
      document.getElementById('badge-param-status').textContent = 'Belum Ada';
      renderVotersTable([]);
      logPanel.clear();
      showNotification('✓ Pemilu berhasil direset total kembali ke SETUP.');
    } catch (err) {
      showNotification(`Error: ${err.message}`, true);
    }
  });
});
