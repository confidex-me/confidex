let worker;
let pending;
let startupTimer;
let workingTimer;
let vaultLock;
let checking = false;
let routing = false;
let revision = 0;
let commandSequence = 0;
let notify;

function stop(output) {
  if (!worker) return;
  worker.terminate();
  worker = undefined;
  clearTimeout(startupTimer);
  clearInterval(workingTimer);
  workingTimer = undefined;
  vaultLock = undefined;
  revision++;
  const request = pending;
  pending = undefined;
  if (output && request) request.resolve(output);
  else request?.reject(new Error('Confidex session closed'));
  notify?.();
}

function start() {
  const current = new Worker(chrome.runtime.getURL('session-worker.js'), {type: 'module'});
  worker = current;
  startupTimer = setTimeout(stop, 20000);
  current.onmessage = ({data}) => {
    if (worker !== current) return;
    if (typeof data?.ready === 'string' && !workingTimer) {
      clearTimeout(startupTimer);
      vaultLock = data.ready;
      workingTimer = setInterval(checkWorker, 5000);
      return;
    }
    if (!(data instanceof Uint8Array) || !pending) {
      stop(data?.retired);
      return;
    }
    const request = pending;
    pending = undefined;
    request.resolve(data);
  };
  current.onerror = current.onmessageerror = () => {
    if (worker === current) stop();
  };
}

async function probe(current, form) {
  const {port1, port2} = new MessageChannel();
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('Confidex session unavailable')), 3000);
      port1.onmessage = ({data}) => resolve(data === true && current === worker);
      current.postMessage({kind: 'Probe', form}, [port2]);
    });
  } finally {
    clearTimeout(timer);
    port1.close();
    port2.close();
  }
}

async function checkWorker() {
  const current = worker;
  if (!current || !vaultLock || checking) return;
  const request = pending;
  const sequence = commandSequence;
  checking = true;
  try {
    if (request) {
      // The browser can observe the ownership lock while WASM blocks the
      // worker's event loop. A held lock does not require a worker reply.
      const state = await navigator.locks.query().catch(() => undefined);
      if (!state || state.held.some(lock => lock.name === vaultLock)
          || current !== worker || pending !== request) return;
    }
    // An orderly exit may already have queued its terminal reply. Give the
    // host time to receive it before rejecting a command whose owner is gone.
    if (await probe(current).catch(() => false)) return;
    if (request) {
      if (current === worker && pending === request) stop();
    } else {
      stopIfIdle(current, sequence);
    }
  } finally {
    checking = false;
  }
}

function stopIfIdle(current, sequence) {
  // A command can begin while a probe is in flight and block the event loop
  // during key derivation. A failed probe can retire only an idle worker.
  if (current === worker && !pending && sequence === commandSequence) stop();
}

function userActivity(event) {
  if (event.isTrusted && worker) worker.postMessage({kind: 'Activity'});
}

function visibilityChanged() {
  if (!document.hidden) void checkWorker();
}

function receiveForm(message, sender, reply) {
  if (message?.kind !== 'ConfidexRoutedForm' || message.version !== 1
      || sender.id !== chrome.runtime.id || sender.tab
      || sender.url !== chrome.runtime.getURL('background.js')) return;
  const current = worker;
  if (!current || routing) {
    reply(false);
    return;
  }
  routing = true;
  const sequence = commandSequence;
  const idle = !pending;
  const form = {context: JSON.stringify(message.context), report: JSON.stringify(message.report)};
  probe(current, form).then(reply, () => {
    if (idle) stopIfIdle(current, sequence);
    reply(false);
  }).finally(() => { routing = false; });
  return true;
}

const activityEvents = ['pointerdown', 'keydown', 'wheel'];

export function observeSession(callback) {
  notify = callback;
  chrome.runtime.onMessage.addListener(receiveForm);
  for (const event of activityEvents) addEventListener(event, userActivity, {capture: true, passive: true});
  document.addEventListener('visibilitychange', visibilityChanged);
  addEventListener('pagehide', disposeSession, {once: true});
}

export function disposeSession() {
  notify = undefined;
  stop();
  removeEventListener('pagehide', disposeSession);
  chrome.runtime.onMessage.removeListener(receiveForm);
  for (const event of activityEvents) removeEventListener(event, userActivity, true);
  document.removeEventListener('visibilitychange', visibilityChanged);
}

export function cancelSession() {
  stop();
}

export function sessionRevision() {
  return revision;
}

export function exchange(input) {
  return new Promise((resolve, reject) => {
    if (pending) {
      input.fill(0);
      reject(new Error('Confidex session request already pending'));
      return;
    }
    try {
      if (!worker) start();
      commandSequence++;
      pending = {resolve, reject};
      worker.postMessage(input, [input.buffer]);
    } catch (error) {
      input.fill(0);
      stop();
      reject(error);
    }
  });
}
