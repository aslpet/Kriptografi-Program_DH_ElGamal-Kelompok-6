// Modul Pencatat Log Kriptografi Sisi Server untuk Tampilan Panel Edukasi
const MAX_LOGS = 500;
let logEntries = [];
let nextLogId = 1;

export function logStep(actor, algo, step, formula = '', values = {}, summary = '') {
  const entry = {
    id: nextLogId++,
    timestamp: new Date().toISOString(),
    actor, // 'SERVER' | 'EA' | 'BALLOT_BOX'
    algo,  // 'DH' | 'ELGAMAL' | 'CHANNEL' | 'SYSTEM'
    step,
    formula,
    values,
    summary
  };
  logEntries.push(entry);
  if (logEntries.length > MAX_LOGS) {
    logEntries.shift();
  }
  return entry;
}

export function getLogs(sinceId = 0) {
  const idNum = parseInt(sinceId, 10) || 0;
  return logEntries.filter(e => e.id > idNum);
}

export function clearLogs() {
  logEntries = [];
  nextLogId = 1;
}
