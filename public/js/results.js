// Logika Sisi Klien untuk Halaman Hasil Pemilu & Audit Homomorfik
import { CryptoLogPanel } from './logPanel.js';

const logPanel = new CryptoLogPanel('crypto-log-container');
logPanel.startAutoPoll(2000);

function updateStateBadge(state) {
  const badge = document.getElementById('current-state-badge');
  if (badge) {
    badge.textContent = `Status: ${state}`;
    badge.className = `status-badge status-${state}`;
  }
}

function renderVisualChart(perCandidate, totalVotes) {
  const container = document.getElementById('chart-container');
  if (!container) return;
  container.textContent = '';

  const colors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899'];

  perCandidate.forEach((cand, idx) => {
    const percent = totalVotes > 0 ? Math.round((cand.T / totalVotes) * 100) : 0;
    const color = colors[idx % colors.length];

    const itemWrapper = document.createElement('div');
    itemWrapper.style.display = 'flex';
    itemWrapper.style.flexDirection = 'column';
    itemWrapper.style.gap = '0.25rem';

    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.fontSize = '0.85rem';

    const nameSpan = document.createElement('span');
    nameSpan.style.fontWeight = '600';
    nameSpan.textContent = cand.name;

    const voteSpan = document.createElement('span');
    voteSpan.style.color = color;
    voteSpan.style.fontWeight = '700';
    voteSpan.textContent = `${cand.T} Suara (${percent}%)`;

    header.appendChild(nameSpan);
    header.appendChild(voteSpan);

    const track = document.createElement('div');
    track.style.width = '100%';
    track.style.height = '12px';
    track.style.backgroundColor = 'var(--bg-primary)';
    track.style.borderRadius = '6px';
    track.style.overflow = 'hidden';

    const bar = document.createElement('div');
    bar.style.width = `${percent}%`;
    bar.style.height = '100%';
    bar.style.backgroundColor = color;
    bar.style.transition = 'width 0.5s ease';

    track.appendChild(bar);
    itemWrapper.appendChild(header);
    itemWrapper.appendChild(track);
    container.appendChild(itemWrapper);
  });
}

function renderTallyTable(perCandidate) {
  const tbody = document.getElementById('tally-details-body');
  if (!tbody) return;
  tbody.textContent = '';

  if (!perCandidate || perCandidate.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.textContent = 'Belum ada data hasil penghitungan.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  perCandidate.forEach(cand => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.style.fontWeight = '600';
    tdName.style.fontFamily = 'var(--font-sans)';
    tdName.textContent = cand.name;

    const short = (s) => (s && s.length > 18 ? `${s.slice(0, 8)}...${s.slice(-8)}` : s || '-');

    const tdC1 = document.createElement('td');
    tdC1.textContent = short(cand.C1);

    const tdC2 = document.createElement('td');
    tdC2.textContent = short(cand.C2);

    const tdGT = document.createElement('td');
    tdGT.style.color = '#38bdf8';
    tdGT.textContent = short(cand.gT);

    const tdT = document.createElement('td');
    tdT.style.fontWeight = '700';
    tdT.style.color = '#34d399';
    tdT.textContent = String(cand.T);

    const tdIter = document.createElement('td');
    tdIter.style.color = 'var(--text-secondary)';
    tdIter.textContent = `${cand.iterations} iterasi`;

    tr.appendChild(tdName);
    tr.appendChild(tdC1);
    tr.appendChild(tdC2);
    tr.appendChild(tdGT);
    tr.appendChild(tdT);
    tr.appendChild(tdIter);
    tbody.appendChild(tr);
  });
}

async function loadResults() {
  try {
    const paramsRes = await fetch('/api/params');
    if (paramsRes.ok) {
      const pData = await paramsRes.json();
      updateStateBadge(pData.state);
    }

    const res = await fetch('/api/results');
    const badge = document.getElementById('consistency-badge');
    const totalEl = document.getElementById('total-v-val');

    if (!res.ok) {
      if (badge) {
        badge.textContent = 'Menunggu Penghitungan (Tally)';
        badge.className = 'badge badge-CHANNEL';
      }
      return;
    }

    const data = await res.json();
    if (!data.ok) return;

    if (totalEl) totalEl.textContent = String(data.V);

    if (badge) {
      if (data.consistent) {
        badge.textContent = '✓ Konsistensi Valid (Σ T = V)';
        badge.className = 'badge badge-ELGAMAL';
      } else {
        badge.textContent = '✗ Peringatan: Ketidakkonsistenan Suara';
        badge.className = 'badge badge-ATTACK';
      }
    }

    renderVisualChart(data.perCandidate, data.V);
    renderTallyTable(data.perCandidate);
  } catch (err) {
    console.error('Gagal memuat hasil:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadResults();
  setInterval(loadResults, 5000);
});
