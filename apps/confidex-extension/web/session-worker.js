import init, {Session, SessionLease} from './engine/engine.js';

let lease;
let session;
let busy = false;
let queued;
let expiry;
let syncTimer;

function openSession() {
  return new Promise((resolve, reject) => {
    navigator.locks.request('confidex-vault-session', {ifAvailable: true}, async lock => {
      if (!lock) throw new Error('A Confidex vault session is already running');
      await init();
      lease = new SessionLease();
      resolve(new Session(lease));
      self.postMessage({ready: lock.name});
      // The worker holds ownership until termination.
      await new Promise(() => {});
    }).catch(reject);
  });
}

function retire(output) {
  clearTimeout(expiry);
  clearTimeout(syncTimer);
  queued?.input.fill(0);
  queued = undefined;
  // The worker can run Rust destructors when the Engine has no active borrow.
  if (!busy) {
    session?.free();
    session = undefined;
  }
  if (output) self.postMessage({retired: output}, [output.buffer]);
  else self.postMessage(null);
  self.close();
}

function scheduleExpiry() {
  clearTimeout(expiry);
  const remaining = lease.remaining();
  if (remaining === 0) retire();
  if (remaining > 0) expiry = setTimeout(scheduleExpiry, remaining);
  return remaining !== 0;
}

function resume() {
  if (queued) {
    const {input, site} = queued;
    queued = undefined;
    void execute(input, site);
    return;
  }
  const delay = session.sync_delay();
  if (delay >= 0) syncTimer = setTimeout(sync, delay);
}

async function sync() {
  busy = true;
  self.postMessage({syncing: true});
  try {
    const changed = await session.sync_automatically();
    busy = false;
    if (lease.remaining() === 0) {
      retire();
      return;
    }
    self.postMessage({syncing: false, changed});
    resume();
  } catch {
    busy = false;
    retire();
  }
}

async function execute(input, site = false) {
  clearTimeout(syncTimer);
  busy = true;
  try {
    session ??= await openSession();
    const response = await (site ? session.execute_site(input) : session.execute(input));
    busy = false;
    if (lease.remaining() === 0) {
      if (lease.was_locked()) retire(response);
      else {
        response.fill(0);
        retire();
      }
    } else {
      self.postMessage(response, [response.buffer]);
      if (scheduleExpiry()) resume();
    }
  } catch {
    busy = false;
    input.fill(0);
    retire();
  }
}

self.onmessage = ({data, ports}) => {
  const site = data?.kind === 'Site' && data.input instanceof Uint8Array;
  const input = site ? data.input : data;
  if (!(input instanceof Uint8Array)) {
    if (data?.kind === 'Activity' && lease) {
      lease.activity();
      scheduleExpiry();
    } else if (data?.kind === 'Probe' && ports.length === 1) {
      const [port] = ports;
      const remaining = lease?.remaining();
      let alive = remaining !== undefined && remaining !== 0;
      if (data.form) alive = remaining > 0 && lease.accept_form(data.form.context, data.form.report);
      if (typeof data.operation === 'string') alive = lease?.site_live(data.operation) === true;
      port.postMessage(alive);
      port.close();
      if (remaining === 0) retire();
    } else if (data?.kind === 'SiteReset' && lease) {
      lease.site_reset();
    } else if (data?.kind === 'SiteNavigation' && lease) {
      lease.site_navigation(data.tabId, data.origin ?? undefined);
    }
    return;
  }
  if (!busy) void execute(input, site);
  else if (!queued) queued = {input, site};
  else {
    input.fill(0);
    retire();
  }
};
