import init, { Session } from './engine/engine.js';

function openSession() {
  return new Promise((resolve, reject) => {
    navigator.locks.request('confidex-vault-session', {ifAvailable: true}, async lock => {
      if (!lock) throw new Error('A Confidex vault session is already running');
      await init();
      resolve(new Session());
      // The worker holds ownership until its document terminates it.
      await new Promise(() => {});
    }).catch(reject);
  });
}

let session;
let busy = false;
self.onmessage = async ({data}) => {
  if (!(data instanceof Uint8Array)) return;
  if (busy) {
    data.fill(0);
    return;
  }
  busy = true;
  try {
    const service = await (session ??= openSession());
    const response = await service.execute(data);
    self.postMessage(response, [response.buffer]);
  } catch {
    data.fill(0);
    self.postMessage(null);
  } finally {
    busy = false;
  }
};
