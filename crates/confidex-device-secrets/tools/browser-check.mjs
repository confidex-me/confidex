import assert from 'node:assert/strict';
import {readFile, readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';

const [chrome, directory] = process.argv.slice(2);
assert(chrome && directory, 'provide Chrome and the wasm-bindgen output directory');
const assets = {'/': '<!doctype html><title>Device secrets backend checks</title>'};
async function load(path, prefix = '') {
    for (const file of await readdir(path, {withFileTypes: true})) {
        const relative = `${prefix}/${file.name}`;
        if (file.isDirectory()) await load(join(path, file.name), relative);
        else assets[relative] = await readFile(join(path, file.name));
    }
}
await load(directory);
const result = await runBrowser(chrome, assets, async ({command, evaluate, url}) => {
    const local = url.replace('127.0.0.1', 'localhost');
    await command('Page.navigate', {url: local});
    for (let attempt = 0; attempt < 100; attempt++) {
        await delay(50);
        if (await evaluate('location.href + ":" + document.readyState') === `${local}:complete`) break;
        assert(attempt < 99, 'localhost navigation timed out');
    }
    const enabled = await command('WebAuthn.enable', {enableUI: false});
    assert(!enabled.error, JSON.stringify(enabled));
    const authenticator = await command('WebAuthn.addVirtualAuthenticator', {options: {
        protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
        hasResidentKey: true, hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
    }});
    assert(!authenticator.error, JSON.stringify(authenticator));
    const checked = await evaluate(`(async () => {
        const backend = await import('/confidex_device_secrets.js');
        await backend.default();
        return await backend.browser_check();
    })()`);
    assert.match(checked, /pass$/);
    await command('Page.navigate', {url: 'about:blank'});
    await delay(100);
    await command('Page.navigate', {url: local});
    for (let attempt = 0; attempt < 100; attempt++) {
        await delay(50);
        if (await evaluate('location.href + ":" + document.readyState') === `${local}:complete`) break;
        assert(attempt < 99, 'page reload timed out');
    }
    const reopened = await evaluate(`(async () => {
        const backend = await import('/confidex_device_secrets.js');
        await backend.default();
        return await backend.browser_finish();
    })()`);
    assert.match(reopened, /pass$/);
    return {checked, reopened, authenticator: 'CDP virtual authenticator; no physical hardware claim'};
});
console.log(JSON.stringify(result, null, 2));
