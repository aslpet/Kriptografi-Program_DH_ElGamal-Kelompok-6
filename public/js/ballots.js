// Logika Sisi Klien untuk Halaman Ballot Box Publik
let allBallots = [];

function updateStateBadge(state) {
  const badge = document.getElementById('current-state-badge');
  if (badge) {
    badge.textContent = `Status: ${state}`;
    badge.className = `status-badge status-${state}`;
  }
}

function renderBallotsTable(ballots) {
  const tbody = document.getElementById('ballots-table-body');
  const countBadge = document.getElementById('ballot-count-badge');
  if (!tbody) return;

  tbody.textContent = '';

  if (!ballots || ballots.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.textContent = 'Kotak suara masih kosong.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    if (countBadge) countBadge.textContent = '0 Ballot';
    return;
  }

  if (countBadge) countBadge.textContent = `${ballots.length} Ballot`;

  ballots.forEach((b, idx) => {
    const tr = document.createElement('tr');

    const tdNum = document.createElement('td');
    tdNum.textContent = String(idx + 1);

    const tdTime = document.createElement('td');
    tdTime.textContent = b.castAt ? new Date(b.castAt).toLocaleTimeString() : '-';

    const tdReceipt = document.createElement('td');
    tdReceipt.style.color = '#38bdf8';
    tdReceipt.textContent = b.receipt;

    const tdCts = document.createElement('td');
    if (Array.isArray(b.cts)) {
      const parts = b.cts.map((c, i) => {
        const shortC1 = c.c1.length > 14 ? `${c.c1.slice(0, 6)}...${c.c1.slice(-6)}` : c.c1;
        const shortC2 = c.c2.length > 14 ? `${c.c2.slice(0, 6)}...${c.c2.slice(-6)}` : c.c2;
        return `K${i + 1}: (${shortC1}, ${shortC2})`;
      });
      tdCts.textContent = parts.join(' | ');
    } else {
      tdCts.textContent = '-';
    }

    tr.appendChild(tdNum);
    tr.appendChild(tdTime);
    tr.appendChild(tdReceipt);
    tr.appendChild(tdCts);
    tbody.appendChild(tr);
  });
}

function renderVoterParticipation(voters) {
  const tbody = document.getElementById('voter-participation-body');
  if (!tbody) return;

  tbody.textContent = '';

  if (!voters || voters.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.textContent = 'Belum ada data pemilih.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

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
    lockBadge.textContent = v.locked ? 'Terkunci' : 'Aktif';
    tdLock.appendChild(lockBadge);

    tr.appendChild(tdId);
    tr.appendChild(tdVoted);
    tr.appendChild(tdLock);
    tbody.appendChild(tr);
  }
}

async function loadBallotsData() {
  try {
    const [ballotsRes, paramsRes] = await Promise.all([
      fetch('/api/ballots'),
      fetch('/api/params')
    ]);

    if (ballotsRes.ok) {
      const data = await ballotsRes.json();
      allBallots = data.ballots || [];
      renderBallotsTable(allBallots);
    }

    if (paramsRes.ok) {
      const pData = await paramsRes.json();
      updateStateBadge(pData.state);
      renderVoterParticipation(pData.voters);
    }
  } catch (err) {
    console.error('Gagal memuat data ballot box:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadBallotsData();
  setInterval(loadBallotsData, 4000);

  // Pencarian Receipt
  document.getElementById('btn-search-receipt')?.addEventListener('click', () => {
    const input = document.getElementById('receipt-search-input');
    const resultEl = document.getElementById('receipt-search-result');
    const query = input?.value?.trim();

    if (!resultEl) return;
    if (!query) {
      resultEl.textContent = '';
      return;
    }

    const match = allBallots.find(b => b.receipt.toLowerCase() === query.toLowerCase());
    if (match) {
      resultEl.style.color = '#34d399';
      resultEl.textContent = `✓ DITEMUKAN: Suara dengan receipt ini tercatat pada ${new Date(match.castAt).toLocaleString()}`;
    } else {
      resultEl.style.color = '#ef4444';
      resultEl.textContent = '✗ TIDAK DITEMUKAN: Hash receipt ini tidak ada di kotak suara.';
    }
  });
});
