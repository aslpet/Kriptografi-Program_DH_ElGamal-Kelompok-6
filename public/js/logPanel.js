// Komponen Panel Log Kriptografi Interaktif
// Menampilkan setiap tahapan matematika, rumus, dan variabel per tahap secara transparan dan aman

export class CryptoLogPanel {
  constructor(containerId = 'crypto-log-container') {
    this.container = document.getElementById(containerId);
    this.entries = [];
    this.showSecrets = false;
    this.fullNumbers = false;
    this.stepMode = false;
    this.pendingQueue = [];
    this.lastServerLogId = 0;

    if (this.container) {
      this.renderFramework();
      this.initEvents();
    }
  }

  renderFramework() {
    this.container.textContent = '';

    const panel = document.createElement('div');
    panel.className = 'log-panel-container';

    // Header
    const header = document.createElement('div');
    header.className = 'log-panel-header';

    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';

    const title = document.createElement('strong');
    title.style.fontSize = '0.95rem';
    title.style.display = 'flex';
    title.style.alignItems = 'center';
    title.style.gap = '0.4rem';
    title.textContent = '📜 Panel Log Kripto';

    const countBadge = document.createElement('span');
    countBadge.id = 'log-count-badge';
    countBadge.className = 'badge';
    countBadge.style.background = '#334155';
    countBadge.style.color = '#94a3b8';
    countBadge.textContent = '0 tahap';

    topRow.appendChild(title);
    topRow.appendChild(countBadge);

    // Controls
    const controls = document.createElement('div');
    controls.className = 'log-panel-controls';

    const makeCheckbox = (id, labelText) => {
      const label = document.createElement('label');
      label.style.fontSize = '0.75rem';
      label.style.display = 'flex';
      label.style.alignItems = 'center';
      label.style.gap = '0.25rem';
      label.style.cursor = 'pointer';

      const input = document.createElement('input');
      input.type = 'checkbox';
      input.id = id;

      label.appendChild(input);
      label.appendChild(document.createTextNode(' ' + labelText));
      return label;
    };

    controls.appendChild(makeCheckbox('chk-show-secrets', 'Mode Edukasi (Rahasia)'));
    controls.appendChild(makeCheckbox('chk-full-numbers', 'Angka Penuh'));
    controls.appendChild(makeCheckbox('chk-step-mode', 'Langkah per Langkah'));

    // Buttons
    const btnRow = document.createElement('div');
    btnRow.style.display = 'flex';
    btnRow.style.gap = '0.3rem';
    btnRow.style.marginTop = '0.2rem';

    const btnNext = document.createElement('button');
    btnNext.id = 'btn-next-step';
    btnNext.className = 'btn btn-primary btn-sm';
    btnNext.style.display = 'none';
    btnNext.style.flex = '1';
    btnNext.textContent = '▶ Langkah Berikutnya';

    const btnCopy = document.createElement('button');
    btnCopy.id = 'btn-copy-log';
    btnCopy.className = 'btn btn-secondary btn-sm';
    btnCopy.title = 'Salin seluruh log ke clipboard';
    btnCopy.textContent = '📋 Salin';

    const btnClear = document.createElement('button');
    btnClear.id = 'btn-clear-log';
    btnClear.className = 'btn btn-secondary btn-sm';
    btnClear.title = 'Bersihkan log';
    btnClear.textContent = '🗑️';

    btnRow.appendChild(btnNext);
    btnRow.appendChild(btnCopy);
    btnRow.appendChild(btnClear);

    header.appendChild(topRow);
    header.appendChild(controls);
    header.appendChild(btnRow);

    // List container
    const list = document.createElement('div');
    list.id = 'log-entries-list';
    list.className = 'log-entries';

    const placeholder = document.createElement('div');
    placeholder.style.color = 'var(--text-muted)';
    placeholder.style.textAlign = 'center';
    placeholder.style.marginTop = '2rem';
    placeholder.textContent = 'Belum ada aktivitas kriptografi. Mulai alur pada panel sebelah kiri.';
    list.appendChild(placeholder);

    panel.appendChild(header);
    panel.appendChild(list);
    this.container.appendChild(panel);
  }

  initEvents() {
    const chkSecrets = document.getElementById('chk-show-secrets');
    const chkFull = document.getElementById('chk-full-numbers');
    const chkStep = document.getElementById('chk-step-mode');
    const btnNext = document.getElementById('btn-next-step');
    const btnCopy = document.getElementById('btn-copy-log');
    const btnClear = document.getElementById('btn-clear-log');

    chkSecrets?.addEventListener('change', (e) => {
      this.showSecrets = e.target.checked;
      this.refreshDisplay();
    });

    chkFull?.addEventListener('change', (e) => {
      this.fullNumbers = e.target.checked;
      this.refreshDisplay();
    });

    chkStep?.addEventListener('change', (e) => {
      this.stepMode = e.target.checked;
      if (btnNext) btnNext.style.display = this.stepMode ? 'inline-flex' : 'none';
    });

    btnNext?.addEventListener('click', () => {
      this.processNextInQueue();
    });

    btnCopy?.addEventListener('click', () => {
      this.copyLogToClipboard();
    });

    btnClear?.addEventListener('click', () => {
      this.clear();
    });
  }

  formatValueString(key, val) {
    if (val === null || val === undefined) return '';
    const str = String(val);

    const isSecret = ['a', 'b', 'x', 'xs', 'k', 'K', 'encKey', 'macKey'].includes(key);
    if (isSecret && !this.showSecrets) {
      return '[DIRAHASIAKAN - Aktifkan Mode Edukasi]';
    }

    if (!this.fullNumbers && str.length > 24) {
      const half = 10;
      return `${str.slice(0, half)}...${str.slice(-half)} (${str.length} char)`;
    }

    return str;
  }

  addEntry(entry) {
    if (this.stepMode) {
      this.pendingQueue.push(entry);
      const btnNext = document.getElementById('btn-next-step');
      if (btnNext) btnNext.textContent = `▶ Langkah Berikutnya (${this.pendingQueue.length})`;
    } else {
      this.entries.push(entry);
      this.renderSingleEntry(entry);
    }
  }

  processNextInQueue() {
    if (this.pendingQueue.length > 0) {
      const entry = this.pendingQueue.shift();
      this.entries.push(entry);
      this.renderSingleEntry(entry);
      const btnNext = document.getElementById('btn-next-step');
      if (btnNext) {
        btnNext.textContent = this.pendingQueue.length > 0
          ? `▶ Langkah Berikutnya (${this.pendingQueue.length})`
          : '▶ Langkah Berikutnya';
      }
    }
  }

  renderSingleEntry(entry) {
    const list = document.getElementById('log-entries-list');
    if (!list) return;

    if (this.entries.length === 1 && list.firstChild && list.firstChild.style?.textAlign === 'center') {
      list.textContent = '';
    }

    const itemEl = document.createElement('div');
    itemEl.className = 'log-entry';

    // Header
    const headerEl = document.createElement('div');
    headerEl.className = 'log-entry-header';

    const badge = document.createElement('span');
    badge.className = `badge badge-${entry.algo || 'CHANNEL'}`;
    badge.textContent = entry.algo || 'SYSTEM';

    const stepEl = document.createElement('span');
    stepEl.style.fontWeight = '600';
    stepEl.style.flex = '1';
    stepEl.style.marginLeft = '0.3rem';
    stepEl.textContent = entry.step || '';

    const timeEl = document.createElement('span');
    timeEl.style.fontSize = '0.65rem';
    timeEl.style.color = 'var(--text-muted)';
    timeEl.textContent = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '';

    headerEl.appendChild(badge);
    headerEl.appendChild(stepEl);
    headerEl.appendChild(timeEl);
    itemEl.appendChild(headerEl);

    // Formula
    if (entry.formula) {
      const formulaEl = document.createElement('div');
      formulaEl.className = 'log-formula';
      formulaEl.textContent = entry.formula;
      itemEl.appendChild(formulaEl);
    }

    // Values
    if (entry.values && typeof entry.values === 'object') {
      const valuesEl = document.createElement('div');
      valuesEl.className = 'log-values';

      for (const [k, v] of Object.entries(entry.values)) {
        const valItem = document.createElement('div');
        valItem.className = 'val-item';

        const keySpan = document.createElement('span');
        keySpan.className = 'val-key';
        keySpan.textContent = `${k}:`;

        const valSpan = document.createElement('span');
        valSpan.textContent = ' ' + this.formatValueString(k, v);

        valItem.appendChild(keySpan);
        valItem.appendChild(valSpan);
        valuesEl.appendChild(valItem);
      }
      itemEl.appendChild(valuesEl);
    }

    // Summary
    if (entry.summary) {
      const summaryEl = document.createElement('div');
      summaryEl.style.fontSize = '0.75rem';
      summaryEl.style.color = '#94a3b8';
      summaryEl.style.marginTop = '0.2rem';
      summaryEl.textContent = entry.summary;
      itemEl.appendChild(summaryEl);
    }

    list.appendChild(itemEl);
    list.scrollTop = list.scrollHeight;

    const countBadge = document.getElementById('log-count-badge');
    if (countBadge) countBadge.textContent = `${this.entries.length} tahap`;
  }

  refreshDisplay() {
    const list = document.getElementById('log-entries-list');
    if (!list) return;
    list.textContent = '';
    if (this.entries.length === 0) {
      const placeholder = document.createElement('div');
      placeholder.style.color = 'var(--text-muted)';
      placeholder.style.textAlign = 'center';
      placeholder.style.marginTop = '2rem';
      placeholder.textContent = 'Belum ada aktivitas kriptografi. Mulai alur pada panel sebelah kiri.';
      list.appendChild(placeholder);
      return;
    }
    for (const entry of this.entries) {
      this.renderSingleEntry(entry);
    }
  }

  async pollServerLogs() {
    try {
      const res = await fetch(`/api/log?sinceId=${this.lastServerLogId}`);
      if (!res.ok) return;
      const logs = await res.json();
      if (Array.isArray(logs) && logs.length > 0) {
        for (const l of logs) {
          this.lastServerLogId = Math.max(this.lastServerLogId, l.id);
          this.addEntry(l);
        }
      }
    } catch {
      // Polling gagal, abaikan
    }
  }

  startAutoPoll(intervalMs = 2500) {
    this.pollServerLogs();
    setInterval(() => this.pollServerLogs(), intervalMs);
  }

  copyLogToClipboard() {
    const text = this.entries.map(e => {
      const vals = Object.entries(e.values || {})
        .map(([k, v]) => `  - ${k}: ${v}`)
        .join('\n');
      return `### [${e.actor}] [${e.algo}] ${e.step}\nRumus: ${e.formula || '-'}\nNilai:\n${vals}\nRingkasan: ${e.summary || '-'}\n`;
    }).join('\n---\n\n');

    navigator.clipboard.writeText(text).then(() => {
      const btnCopy = document.querySelector('#btn-copy-log');
      if (btnCopy) {
        const orig = btnCopy.textContent;
        btnCopy.textContent = '✓ Tersalin!';
        setTimeout(() => { btnCopy.textContent = orig; }, 2000);
      }
    });
  }

  clear() {
    this.entries = [];
    this.pendingQueue = [];
    this.refreshDisplay();
    const countBadge = document.getElementById('log-count-badge');
    if (countBadge) countBadge.textContent = '0 tahap';
  }
}
