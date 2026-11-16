import init, { Session } from './engine/engine.js';

const session = init().then(() => new Session());
let busy = false;
self.onmessage = async ({data}) => {
  if (!(data instanceof Uint8Array)) return;
  if (busy) {
    data.fill(0);
    return;
  }
  busy = true;
  try {
    const service = await session;
    const response = await service.execute(data);
    self.postMessage(response, [response.buffer]);
  } catch {
    data.fill(0);
    self.postMessage(null);
  } finally {
    busy = false;
  }
};
