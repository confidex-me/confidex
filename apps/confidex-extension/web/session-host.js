let worker;
let pending;

function stop() {
  worker?.terminate();
  worker = undefined;
  pending?.reject(new Error('Confidex session closed'));
  pending = undefined;
}

function start() {
  worker = new Worker(chrome.runtime.getURL('session-worker.js'), {type: 'module'});
  worker.onmessage = ({data}) => {
    if (!(data instanceof Uint8Array)) {
      stop();
      return;
    }
    const request = pending;
    pending = undefined;
    request?.resolve(data);
  };
  worker.onerror = stop;
  worker.onmessageerror = stop;
}

addEventListener('pagehide', stop);

export function exchange(input) {
  return new Promise((resolve, reject) => {
    if (pending) {
      input.fill(0);
      reject(new Error('Confidex session request already pending'));
      return;
    }
    try {
      if (!worker) start();
      pending = {resolve, reject};
      worker.postMessage(input, [input.buffer]);
    } catch (error) {
      input.fill(0);
      pending = undefined;
      reject(error);
    }
  });
}
