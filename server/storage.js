// Modul Persistensi Opsional dan Seeding Data Siap Demo
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupElection, getPublicParams, resetAuthority } from './authority.js';
import { registerVoters, getVoterPublicList, resetVoters } from './voters.js';
import { resetBallotBox, getBallots } from './ballotbox.js';
import { resetSessions } from './session.js';
import { clearLogs } from './logger.js';
import { getState, transitionTo, resetState, STATES } from './electionState.js';
import { CONFIG } from '../config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STATE_FILE = path.resolve(__dirname, '../state.json');

export function seedDemoReadyState(mode = 'demo') {
  resetState();
  resetAuthority();
  resetVoters();
  resetBallotBox();
  resetSessions();
  clearLogs();

  // 1. Setup Pemilu
  const publicParams = setupElection({ mode, candidates: CONFIG.DEFAULT_CANDIDATES });
  transitionTo(STATES.REGISTRATION);

  // 2. Daftarkan 5 Voter Default
  registerVoters(CONFIG.DEFAULT_VOTERS);

  // 3. Buka Voting
  transitionTo(STATES.VOTING);

  return {
    ok: true,
    state: getState(),
    params: publicParams,
    voters: getVoterPublicList(),
    defaultVotersInfo: CONFIG.DEFAULT_VOTERS
  };
}

export function saveStateToJson() {
  const data = {
    timestamp: new Date().toISOString(),
    state: getState(),
    params: getPublicParams(),
    voters: getVoterPublicList(),
    ballots: getBallots()
  };
  fs.writeFileSync(STATE_FILE, JSON.stringify(data, null, 2), 'utf8');
  return { ok: true, path: STATE_FILE };
}

export function loadStateFromJson() {
  if (!fs.existsSync(STATE_FILE)) return null;
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
