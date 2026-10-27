// Mesin Keadaan Pemilu (Election State Machine)
// Transisi resmi: SETUP -> REGISTRATION -> VOTING -> CLOSED -> TALLIED

export const STATES = {
  SETUP: 'SETUP',
  REGISTRATION: 'REGISTRATION',
  VOTING: 'VOTING',
  CLOSED: 'CLOSED',
  TALLIED: 'TALLIED'
};

const VALID_TRANSITIONS = {
  SETUP: ['REGISTRATION', 'VOTING', 'SETUP'],
  REGISTRATION: ['VOTING', 'SETUP'],
  VOTING: ['CLOSED', 'REGISTRATION', 'SETUP'],
  CLOSED: ['VOTING', 'TALLIED', 'SETUP'],
  TALLIED: ['VOTING', 'CLOSED', 'SETUP']
};

let currentState = STATES.SETUP;

export function getState() {
  return currentState;
}

export function canTransition(targetState) {
  if (currentState === targetState) return true;
  const allowed = VALID_TRANSITIONS[currentState] || [];
  return allowed.includes(targetState);
}

export function transitionTo(targetState) {
  if (currentState === targetState) {
    return { prevState: currentState, currentState };
  }
  if (!VALID_TRANSITIONS[currentState]?.includes(targetState)) {
    throw new Error(`Transisi status tidak diizinkan: dari '${currentState}' ke '${targetState}'`);
  }
  const prevState = currentState;
  currentState = targetState;
  return { prevState, currentState };
}

export function requireState(allowedStates) {
  const list = Array.isArray(allowedStates) ? allowedStates : [allowedStates];
  if (!list.includes(currentState)) {
    const err = new Error(`Aksi ditolak: status saat ini '${currentState}', dibutuhkan salah satu dari [${list.join(', ')}]`);
    err.status = 403;
    throw err;
  }
}

export function resetState() {
  currentState = STATES.SETUP;
  return currentState;
}
