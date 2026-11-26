import init, {Session, SessionLease} from './engine/engine.js';

let lease;
let session;
let busy = false;
let queued;
let expiry;
let syncTimer;
let captureTimer;
let reviewNeeded = false;
let capturePolicy = {allowed: false, exceptions: '{}'};
let unlocked = false;
let badges;

function openSession() {
  return new Promise((resolve, reject) => {
    navigator.locks.request('confidex-vault-session', {ifAvailable: true}, async lock => {
      if (!lock) throw new Error('A Confidex vault session is already running');
      await init();
      lease = new SessionLease();
      lease.site_policy(capturePolicy.allowed, capturePolicy.exceptions);
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
  clearTimeout(captureTimer);
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

function retireIfExpired() {
  // A Lock command still needs to deliver its terminal reply.
  if (lease?.remaining() === 0 && (!busy || !lease.was_locked())) retire();
}

function scheduleExpiry() {
  clearTimeout(expiry);
  const remaining = lease.remaining();
  if (remaining === 0) retireIfExpired();
  if (remaining > 0) expiry = setTimeout(scheduleExpiry, remaining);
  if (remaining > 0 && !unlocked) {
    unlocked = true;
    self.postMessage({captureOpen: true});
  }
  return remaining !== 0;
}

function refreshBadges() {
  clearTimeout(captureTimer);
  const remaining = lease.capture_expiry();
  const current = lease.save_badges();
  if (current !== badges) {
    badges = current;
    self.postMessage({saveBadges: JSON.parse(current)});
  }
  if (remaining >= 0) captureTimer = setTimeout(refreshBadges, remaining);
}

function resume() {
  clearTimeout(syncTimer);
  if (queued) {
    const {input, route} = queued;
    queued = undefined;
    void execute(input, route);
    return;
  }
  if (reviewNeeded) {
    void reviewCapture();
    return;
  }
  const delay = session.sync_delay();
  if (delay >= 0) syncTimer = setTimeout(sync, delay);
}

async function reviewCapture() {
  busy = true;
  reviewNeeded = false;
  try {
    const more = await session.review_capture();
    reviewNeeded ||= more;
    busy = false;
    if (scheduleExpiry()) {
      refreshBadges();
      resume();
    }
  } catch {
    busy = false;
    retire();
  }
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

async function execute(input, route) {
  clearTimeout(syncTimer);
  busy = true;
  try {
    session ??= await openSession();
    const response = await (route === 'Site' ? session.execute_site(input)
      : route === 'Save' ? session.execute_save(input) : session.execute(input));
    busy = false;
    if (lease.remaining() === 0) {
      if (lease.was_locked()) retire(response);
      else {
        response.fill(0);
        retire();
      }
    } else {
      self.postMessage(response, [response.buffer]);
      if (route === 'Save') refreshBadges();
      if (scheduleExpiry()) resume();
    }
  } catch {
    busy = false;
    input.fill(0);
    retire();
  }
}

self.onmessage = ({data, ports}) => {
  const route = data?.kind === 'Site' || data?.kind === 'Save' ? data.kind : undefined;
  const input = route ? data.input : data;
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
      retireIfExpired();
    } else if (data?.kind === 'SitePolicy') {
      capturePolicy = data;
      if (lease?.site_policy(data.allowed, data.exceptions)) refreshBadges();
    } else if (data?.kind === 'SiteNavigation' && lease) {
      lease.site_navigation(data.tabId, data.origin ?? undefined);
    } else if (data?.kind === 'SiteClosed' && lease) {
      lease.site_closed(data.tabId);
      refreshBadges();
    } else if (data?.kind === 'ReadBadges' && ports.length === 1) {
      const [port] = ports;
      port.postMessage(lease?.remaining() > 0 ? JSON.parse(lease.save_badges()) : []);
      port.close();
    } else if (data?.kind === 'ListSaves' && ports.length === 1) {
      const [port] = ports;
      const offers = lease?.list_saves(data.tab ?? undefined);
      port.postMessage(offers ? JSON.parse(offers) : 'Locked');
      port.close();
      retireIfExpired();
    } else if (data?.kind === 'Capture' && ports.length === 1) {
      const [port] = ports;
      let result = false;
      if (data.report) {
        result = lease?.accept_capture(data.context, data.report) === true;
        if (result) {
          reviewNeeded = true;
          refreshBadges();
          if (!busy) resume();
        }
      } else if (data.snapshot) {
        const plan = lease?.capture_plan(data.context, data.snapshot);
        if (plan) result = JSON.parse(plan);
      }
      port.postMessage(result);
      port.close();
      if (!result) retireIfExpired();
    }
    return;
  }
  if (!busy) void execute(input, route);
  else if (!queued) queued = {input, route};
  else {
    input.fill(0);
    retire();
  }
};
