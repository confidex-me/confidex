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

let sitePolicy = {kind: 'SitePolicy', allowed: false, exceptions: '{}'};
let policySequence = 0;

function tellBackground(kind, data) {
  void chrome.runtime.sendMessage({kind, version: 1, ...data}).catch(() => {});
}

function applyPolicy(allowed, exceptions) {
  sitePolicy = {kind: 'SitePolicy', allowed, exceptions};
  worker?.postMessage(sitePolicy);
}

function refreshPolicy() {
  const sequence = ++policySequence;
  chrome.runtime.sendMessage({kind: 'VaultPolicy'}).then(policy => {
    if (sequence === policySequence) applyPolicy(policy?.allowed === true, JSON.stringify(policy?.exceptions ?? {}));
  }, () => {
    if (sequence === policySequence) applyPolicy(false, '{}');
  });
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
  request?.finish();
  if (output && request) request.resolve(output);
  else request?.reject(new Error('Confidex session closed'));
  notifyViews();
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
        notifyViews();
      }
      return;
    }
    if (!(data instanceof Uint8Array) || !pending) {
      stop(data?.retired);
      return;
    }
    const request = pending;
    pending = undefined;
    request.finish();
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
            notifyViews();
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
      let finish;
      const done = new Promise(complete => { finish = complete; });
      pending = {resolve, reject, done, finish};
      worker.postMessage(route ? {kind: route, input} : input, [input.buffer]);
    } catch (error) {
      input.fill(0);
      stop();
      reject(error);
    }
  });
}

chrome.runtime.onMessage.addListener(receiveForm);
chrome.runtime.onMessage.addListener(receiveSite);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('background.js')) return;
  if (message.kind === 'VaultPolicyChanged') {
    applyPolicy(false, '{}');
    refreshPolicy();
    reply(true);
  }
});
const views = new Set();
function notifyViews() {
  for (const port of views) port.postMessage({revision, syncRevision});
}
chrome.runtime.onConnect.addListener(port => {
  if (port.name !== 'vault-ui' || port.sender?.url !== chrome.runtime.getURL('popup.html')
      || port.sender.id !== chrome.runtime.id || port.sender.frameId > 0 || port.sender.tab?.incognito) return;
  views.add(port);
  port.postMessage({initial: true, revision, syncRevision});
  port.onDisconnect.addListener(() => views.delete(port));
  port.onMessage.addListener(async message => {
    if (message.kind === 'Activity') worker?.postMessage(message);
    if (message.kind === 'Lock') stop();
    if (message.kind !== 'Exchange') return;
    const generation = revision;
    try {
      // A reopened popup may request status while the preceding view is finishing a write.
      while (pending && generation === revision && views.has(port)) await pending.done;
      if (!views.has(port)) return;
      if (generation !== revision) throw new Error('Session closed');
      const output = await exchange(new TextEncoder().encode(message.input));
      if (views.has(port)) port.postMessage({result: new TextDecoder().decode(output)});
      output.fill(0);
    } catch {
      if (views.has(port)) port.postMessage({failed: true});
    }
  });
});
refreshPolicy();
