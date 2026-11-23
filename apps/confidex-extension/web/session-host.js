let worker;
let owner;
let pending;
let startupTimer;
let workingTimer;
let vaultLock;
let checking = false;
let syncing = false;
let routing = false;
let revision = 0;
let syncRevision = 0;
let workSequence = 0;
let notify;
let sitePolicy = {kind: 'SitePolicy', allowed: false, exceptions: '{}'};
let policySequence = 0;
const sitePermission = {origins: ['https://*/*']};

function tellBackground(kind, data) {
  void chrome.runtime.sendMessage({kind, version: 1, ...data}).catch(() => {});
}

function applyPolicy(allowed, exceptions) {
  sitePolicy = {kind: 'SitePolicy', allowed, exceptions};
  worker?.postMessage(sitePolicy);
}

function refreshPolicy() {
  const sequence = ++policySequence;
  Promise.all([chrome.permissions.contains(sitePermission), chrome.storage.local.get('siteExceptions')])
    .then(([allowed, prefs]) => {
      if (sequence === policySequence) applyPolicy(allowed, JSON.stringify(prefs.siteExceptions ?? {}));
    }, () => {
      if (sequence === policySequence) applyPolicy(false, '{}');
    });
}

function revokePolicy() {
  applyPolicy(false, sitePolicy.exceptions);
  refreshPolicy();
}

function policyChanged(changes, area) {
  if (area === 'local' && changes.siteExceptions) {
    ++policySequence;
    applyPolicy(sitePolicy.allowed, JSON.stringify(changes.siteExceptions.newValue ?? {}));
    refreshPolicy();
  }
}

function stop(output) {
  if (!worker) return;
  worker.terminate();
  worker = undefined;
  owner = undefined;
  clearTimeout(startupTimer);
  clearInterval(workingTimer);
  workingTimer = undefined;
  vaultLock = undefined;
  syncing = false;
  tellBackground('ConfidexCaptureState', {open: false});
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
  owner = crypto.randomUUID();
  startupTimer = setTimeout(stop, 20000);
  current.onmessage = ({data}) => {
    if (worker !== current) return;
    if (typeof data?.ready === 'string' && !workingTimer) {
      clearTimeout(startupTimer);
      vaultLock = data.ready;
      workingTimer = setInterval(checkWorker, 5000);
      return;
    }
    if (data?.captureOpen === true) {
      tellBackground('ConfidexCaptureState', {open: true});
      return;
    }
    if (Array.isArray(data?.saveBadges)) {
      tellBackground('ConfidexSaveBadges', {tabs: data.saveBadges});
      return;
    }
    if (typeof data?.syncing === 'boolean') {
      syncing = data.syncing;
      if (syncing) workSequence++;
      if (data.changed === true) {
        syncRevision++;
        notify?.();
      }
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
  current.postMessage(sitePolicy);
}

async function askWorker(current, message) {
  const {port1, port2} = new MessageChannel();
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('Confidex session unavailable')), 3000);
      port1.onmessage = ({data}) => resolve(current === worker ? data : false);
      current.postMessage(message, [port2]);
    });
  } finally {
    clearTimeout(timer);
    port1.close();
    port2.close();
  }
}

async function probe(current, form, operation) {
  return await askWorker(current, {kind: 'Probe', form, operation}) === true;
}

async function checkWorker() {
  const current = worker;
  if (!current || !vaultLock || checking) return;
  const request = pending;
  const sequence = workSequence;
  checking = true;
  try {
    if (request || syncing) {
      // The browser can observe the ownership lock while WASM blocks the
      // worker's event loop. A held lock does not require a worker reply.
      const state = await navigator.locks.query().catch(() => undefined);
      if (!state || state.held.some(lock => lock.name === vaultLock)
          || current !== worker || workSequence !== sequence || pending !== request) return;
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
  // A command or automatic sync can begin while a probe is in flight.
  // Retire only if the work seen when the probe started is still current.
  if (current === worker && !pending && sequence === workSequence) stop();
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
  const sequence = workSequence;
  const idle = !pending && !syncing;
  const form = {context: JSON.stringify(message.context), report: JSON.stringify(message.report)};
  probe(current, form).then(reply, () => {
    if (idle) stopIfIdle(current, sequence);
    reply(false);
  }).finally(() => { routing = false; });
  return true;
}

function receiveSite(message, sender, reply) {
  if (message?.version !== 1 || sender.id !== chrome.runtime.id || sender.tab
      || sender.url !== chrome.runtime.getURL('background.js')) return;
  const current = worker;
  const generation = owner;
  switch (message.kind) {
    case 'ConfidexReadBadges':
      if (!current) {
        reply([]);
        return;
      }
      askWorker(current, {kind: 'ReadBadges'}).then(reply, () => reply([]));
      return true;
    case 'ConfidexListSaves':
      if (!current || generation !== message.owner) {
        reply('Locked');
        return;
      }
      askWorker(current, {kind: 'ListSaves', tab: message.tab})
        .then(result => reply(result || 'Locked'), () => reply('Locked'));
      return true;
    case 'ConfidexSiteClosed':
      current?.postMessage({kind: 'SiteClosed', tabId: message.tabId});
      reply(Boolean(current));
      return;
    case 'ConfidexSiteNavigation':
      current?.postMessage({kind: 'SiteNavigation', tabId: message.tabId, origin: message.origin});
      reply(true);
      return;
    case 'ConfidexSiteCheck':
      if (!current || (message.owner && message.owner !== generation)) {
        reply(false);
        return;
      }
      probe(current, undefined, message.operation)
        .then(live => reply(live ? generation : false), () => reply(false));
      return true;
    case 'ConfidexCapturePlan':
    case 'ConfidexSiteCapture': {
      const capture = message.kind === 'ConfidexSiteCapture';
      if (!current || !sitePolicy.allowed || (capture && message.owner !== generation)) {
        reply(false);
        return;
      }
      const context = JSON.stringify(message.context);
      const payload = capture
        ? {report: JSON.stringify(message.report)}
        : {snapshot: JSON.stringify(message.snapshot)};
      askWorker(current, {kind: 'Capture', context, ...payload})
        .then(result => reply(!capture && result ? {owner: generation, ...result} : result),
          () => reply(false));
      return true;
    }
    case 'ConfidexSiteCommand':
    case 'ConfidexSaveCommand': {
      if (!current || generation !== message.owner) {
        reply({status: 'Locked'});
        return;
      }
      if (pending) {
        reply({status: 'Busy'});
        return;
      }
      const bytes = new TextEncoder().encode(JSON.stringify(message.request));
      exchange(bytes, message.kind === 'ConfidexSiteCommand' ? 'Site' : 'Save').then(output => {
        try {
          if (current !== worker) {
            reply({status: 'Locked'});
            return;
          }
          const response = new TextDecoder().decode(output);
          if (message.kind === 'ConfidexSaveCommand' && response.startsWith('{"Saved":')) {
            syncRevision++;
            notify?.();
          }
          reply({response});
        } finally {
          output.fill(0);
        }
      }, () => reply({status: 'Locked'}));
      return true;
    }
  }
}

const activityEvents = ['pointerdown', 'keydown', 'wheel'];

export function observeSession(callback) {
  notify = callback;
  chrome.runtime.onMessage.addListener(receiveForm);
  chrome.runtime.onMessage.addListener(receiveSite);
  chrome.permissions.onAdded.addListener(refreshPolicy);
  chrome.permissions.onRemoved.addListener(revokePolicy);
  chrome.storage.onChanged.addListener(policyChanged);
  refreshPolicy();
  for (const event of activityEvents) addEventListener(event, userActivity, {capture: true, passive: true});
  document.addEventListener('visibilitychange', visibilityChanged);
  addEventListener('pagehide', disposeSession, {once: true});
}

export function disposeSession() {
  notify = undefined;
  stop();
  removeEventListener('pagehide', disposeSession);
  chrome.runtime.onMessage.removeListener(receiveForm);
  chrome.runtime.onMessage.removeListener(receiveSite);
  chrome.permissions.onAdded.removeListener(refreshPolicy);
  chrome.permissions.onRemoved.removeListener(revokePolicy);
  chrome.storage.onChanged.removeListener(policyChanged);
  for (const event of activityEvents) removeEventListener(event, userActivity, true);
  document.removeEventListener('visibilitychange', visibilityChanged);
}

export function cancelSession() {
  stop();
}

export function sessionRevision() {
  return revision;
}

export function syncStatusRevision() {
  return syncRevision;
}

export function exchange(input, route) {
  return new Promise((resolve, reject) => {
    if (pending) {
      input.fill(0);
      reject(new Error('Confidex session request already pending'));
      return;
    }
    try {
      if (!worker) {
        if (route) throw new Error('Confidex session closed');
        start();
      }
      workSequence++;
      pending = {resolve, reject};
      worker.postMessage(route ? {kind: route, input} : input, [input.buffer]);
    } catch (error) {
      input.fill(0);
      stop();
      reject(error);
    }
  });
}
