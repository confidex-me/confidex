const DB = 'confidex-device-secrets-v1';
const STORE = 'entries';
function fail(code) { throw code; }
function mapError(error) {
    if (typeof error === 'string') return error;
    switch (error?.name) {
        case 'NotAllowedError': case 'AbortError': return 'Canceled';
        case 'SecurityError': return 'AccessDenied';
        case 'NotSupportedError': return 'Unsupported';
        case 'QuotaExceededError': return 'Limit';
        default: return 'Storage';
    }
}
async function database() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE);
        request.onerror = () => reject('Storage');
        request.onblocked = () => reject('Storage');
        request.onsuccess = () => resolve(request.result);
    });
}
export async function entry(operation, namespace, id, bytes) {
    let db;
    try {
        db = await database();
        return await new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE, operation === 'read' ? 'readonly' : 'readwrite');
            const store = transaction.objectStore(STORE);
            const key = `${namespace}/${id}`;
            let result;
            let request;
            switch (operation) {
                case 'read': request = store.get(key); break;
                case 'write': request = store.put(bytes, key); break;
                case 'remove': request = store.delete(key); break;
                default: fail('InvalidData');
            }
            request.onsuccess = () => { result = request.result; };
            transaction.oncomplete = () => {
                if (operation !== 'read' || result === undefined) return resolve(null);
                if (!(result instanceof Uint8Array) || result.length > 16384) return reject('InvalidData');
                resolve(result);
            };
            transaction.onabort = () => reject(mapError(transaction.error));
            transaction.onerror = () => reject(mapError(transaction.error));
        });
    } catch (error) { throw mapError(error); }
    finally { db?.close(); }
}
const inWorker = typeof document === 'undefined';
function requestHost(operation, args) {
    return new Promise((resolve, reject) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = ({data}) => {
            channel.port1.close();
            if (data.error) reject(data.error);
            else resolve(data.value);
        };
        postMessage({confidexPasskey: operation, args}, [channel.port2]);
    });
}
export function attachPasskeyHost(worker) {
    worker.addEventListener('message', async event => {
        const operation = event.data?.confidexPasskey;
        if (operation !== 'create' && operation !== 'get') return;
        event.stopImmediatePropagation();
        const port = event.ports[0];
        if (!port) return;
        try {
            const value = await (operation === 'create'
                ? createPrf(...event.data.args)
                : getPrf(...event.data.args));
            const transfer = Array.isArray(value) ? value.map(bytes => bytes.buffer) : [value.buffer];
            port.postMessage({value}, transfer);
        } catch (error) {
            port.postMessage({error: mapError(error)});
        } finally {
            port.close();
        }
    }, {capture: true});
}
export async function capabilities() {
    if (!globalThis.isSecureContext || (!inWorker && !navigator.credentials)) fail('Unsupported');
}
function prfBytes(value) {
    if (value instanceof ArrayBuffer && value.byteLength === 32) return new Uint8Array(value);
    if (ArrayBuffer.isView(value) && value.byteLength === 32) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
    }
    if (Array.isArray(value) && value.length === 32) {
        // Some passkey providers return an array of bytes.
        for (const byte of value) {
            if (!Number.isInteger(byte) || byte < 0 || byte > 255) return null;
        }
        return Uint8Array.from(value);
    }
    return null;
}
async function evaluate(id, binding, verified) {
    const credential = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id, type: 'public-key' }],
        userVerification: verified ? 'required' : 'preferred',
        extensions: { prf: { eval: { first: binding } } },
        timeout: 60000,
    } });
    if (!credential) fail('Canceled');
    const returnedId = new Uint8Array(credential.rawId);
    if (returnedId.length !== id.length || !id.every((byte, index) => byte === returnedId[index])) {
        fail('InvalidData');
    }
    const value = prfBytes(credential.getClientExtensionResults().prf?.results?.first);
    if (!value) fail('Unsupported');
    return value;
}
export async function createPrf(namespace, binding, verified) {
    if (inWorker) return requestHost('create', [namespace, binding, verified]);
    try {
        if (!globalThis.PublicKeyCredential || !navigator.credentials?.create) fail('Unsupported');
        const credential = await navigator.credentials.create({ publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: 'Confidex' },
            user: { id: crypto.getRandomValues(new Uint8Array(32)), name: namespace, displayName: 'Confidex local key' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: { residentKey: 'required', userVerification: verified ? 'required' : 'preferred' },
            attestation: 'none', extensions: { prf: {} }, timeout: 60000,
        } });
        if (!credential) fail('Canceled');
        const prf = credential.getClientExtensionResults().prf;
        const id = new Uint8Array(credential.rawId);
        if (id.length === 0 || id.length > 1024) fail('InvalidData');
        if (prf?.enabled === false) fail('Unsupported');
        // Get the key the same way for storage and for later access.
        return [id, await evaluate(id, binding, verified)];
    } catch (error) { throw mapError(error); }
}
export async function getPrf(id, binding, verified) {
    if (inWorker) return requestHost('get', [id, binding, verified]);
    try { return await evaluate(id, binding, verified); }
    catch (error) { throw mapError(error); }
}
