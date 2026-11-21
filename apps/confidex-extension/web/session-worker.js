import init, {Session, SessionLease} from './engine/engine.js';

let lease;
let session;
let busy = false;
let expiry;

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
  // An idle Engine can run its Rust destructors. In-flight calls can still
  // borrow it, so close the worker to cancel them.
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
}

self.onmessage = async ({data, ports}) => {
  if (!(data instanceof Uint8Array)) {
    if (data?.kind === 'Activity' && lease) {
      lease.activity();
      scheduleExpiry();
    } else if (data?.kind === 'Probe' && ports.length === 1) {
      const [port] = ports;
      const remaining = lease?.remaining();
      port.postMessage(data.form
        ? remaining > 0 && lease.accept_form(data.form.context, data.form.report)
        : remaining !== undefined && remaining !== 0);
      port.close();
      if (remaining === 0) retire();
    }
    return;
  }
  if (busy) {
    data.fill(0);
    retire();
    return;
  }
  busy = true;
  try {
    session ??= await openSession();
    const response = await session.execute(data);
    busy = false;
    if (lease.remaining() === 0) {
      if (lease.was_locked()) retire(response);
      else {
        response.fill(0);
        retire();
      }
    } else {
      self.postMessage(response, [response.buffer]);
      scheduleExpiry();
    }
  } catch {
    data.fill(0);
    retire();
  } finally {
    busy = false;
  }
};
