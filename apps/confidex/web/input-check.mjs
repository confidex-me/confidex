import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome, bundle] = process.argv.slice(2);
assert(chrome && bundle, 'Provide Chrome and the WASM bundle');
const result = await runBrowser(chrome, await assets(bundle), async ({command, evaluate}) => {
  const rpc = async (method, params = {}) => {
    const response = await command(method, params);
    assert(!response.error, JSON.stringify(response));
    return response.result;
  };
  const until = async predicate => {
    const deadline = Date.now() + 30000;
    for (;;) {
      const state = await evaluate('window.confidex?.snapshot()');
      if (state && predicate(state)) return state;
      assert(Date.now() < deadline, JSON.stringify(state));
      await delay(50);
    }
  };
  const mouse = async id => {
    const [x, y] = (await until(state => state.hits[id])).hits[id];
    for (const type of ['mousePressed', 'mouseReleased']) {
      await rpc('Input.dispatchMouseEvent', {type, x, y, button: 'left', clickCount: 1});
    }
    await delay(100);
  };
  await until(state => state.screen === 'catalog' && !state.busy);
  await mouse('create');
  await until(state => state.screen === 'create');
  await rpc('Emulation.setTouchEmulationEnabled', {enabled: true, maxTouchPoints: 2});
  await evaluate(`(() => {
    const canvas = document.getElementById('app');
    canvas.focus = () => {};
    canvas.addEventListener('focus', () => canvas.blur());
    window.touchResults = [];
    window.touchStarts = [];
    document.addEventListener('touchstart', event => {
      touchStarts.push({native: event.target instanceof HTMLInputElement, prevented: event.defaultPrevented});
    });
    document.addEventListener('touchend', event => {
      touchResults.push({focused: document.activeElement instanceof HTMLInputElement,
        native: event.target instanceof HTMLInputElement,
        active: navigator.userActivation.isActive, prevented: event.defaultPrevented});
    });
    window.createdRequest = null;
    const originalPost = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (data, ...args) {
      try {
        const request = JSON.parse(new TextDecoder().decode(data));
        if (request.command.Create) {
          window.createdRequest = request.command.Create;
          return;
        }
      } catch {}
      return originalPost.call(this, data, ...args);
    };
  })()`);
  const tap = async id => {
    const [x, y] = (await until(state => state.hits[id])).hits[id];
    await rpc('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [{x, y, id: 1}]});
    await rpc('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
    await delay(150);
    const focus = await evaluate('touchResults.at(-1)');
    const nativeFocus = focus.native && await evaluate('document.activeElement instanceof HTMLInputElement');
    assert((focus.focused || nativeFocus) && focus.active, `${id}: ${JSON.stringify(focus)}`);
  };
  const dismiss = () => evaluate('document.activeElement.blur()');
  const paste = async (text, payload) => {
    await evaluate(`(() => {
      const input = document.activeElement;
      if (!(input instanceof HTMLInputElement)) throw new Error('No input focus');
      const data = ${payload ? JSON.stringify(text) : 'null'};
      input.dispatchEvent(new InputEvent('beforeinput', {bubbles: true, cancelable: true,
        inputType: 'insertFromPaste', data}));
      input.setRangeText(${JSON.stringify(text)}, input.selectionStart, input.selectionEnd, 'end');
      input.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertFromPaste', data}));
    })()`);
    await delay(150);
  };

  await dismiss();
  await tap('name');
  assert.equal(await evaluate('matchMedia("(any-pointer: coarse)").matches'), true);
  const nativeTarget = await evaluate(`(() => {
    const [x, y] = confidex.snapshot().hits.name;
    const input = document.activeElement;
    const event = new MouseEvent('contextmenu', {bubbles: true, cancelable: true});
    input.dispatchEvent(event);
    return {target: document.elementFromPoint(x, y) === input,
      width: input.getBoundingClientRect().width, menuAllowed: !event.defaultPrevented,
      opacity: Number(getComputedStyle(input).opacity),
      style: input.style.cssText, point: [x, y], bounds: input.getBoundingClientRect().toJSON()};
  })()`);
  assert(nativeTarget.target && nativeTarget.width > 100 && nativeTarget.menuAllowed
    && nativeTarget.opacity > 0, JSON.stringify(nativeTarget));
  await rpc('Input.insertText', {text: 'seed'});
  await delay(150);
  await evaluate(`(() => {
    window.holdValueWrites = 0;
    window.holdBlurs = 0;
    window.holding = true;
    const input = document.activeElement;
    const value = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() { return value.get.call(this); },
      set(text) { if (holding) holdValueWrites++; value.set.call(this, text); },
    });
    input.addEventListener('blur', () => { if (holding) holdBlurs++; });
  })()`);
  const [holdX, holdY] = (await until(state => state.hits.name)).hits.name;
  await rpc('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [{x: holdX, y: holdY, id: 1}]});
  await delay(700);
  await rpc('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
  const hold = await evaluate('touchStarts.at(-1)');
  assert(hold.native && !hold.prevented, JSON.stringify(hold));
  await delay(100);
  const stableHold = await evaluate(`(() => {
    window.holding = false;
    return {writes: holdValueWrites, blurs: holdBlurs, value: document.activeElement.value};
  })()`);
  assert.deepEqual(stableHold, {writes: 0, blurs: 0, value: 'seed'});
  await paste('🌴', false);
  await rpc('Input.insertText', {text: 'tail'});
  assert.equal(await evaluate(`(() => {
    const data = new DataTransfer(); data.setData('text/plain', ' clipboard');
    const event = new ClipboardEvent('paste', {bubbles: true, cancelable: true, clipboardData: data});
    document.activeElement.dispatchEvent(event);
    return event.defaultPrevented;
  })()`), true);
  await delay(150);
  const caret = await evaluate(`(() => {
    const rect = document.activeElement.getBoundingClientRect();
    return {x: rect.left + 3, y: rect.top + rect.height / 2, id: 1};
  })()`);
  await rpc('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [caret]});
  await rpc('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
  await paste('pre ', true);

  await dismiss();
  await tap('password');
  assert.equal(await evaluate('document.activeElement.type'), 'password');
  await paste('public-fixture-password', true);
  await dismiss();
  await tap('repeat');
  await paste('public-fixture-password', false);
  await mouse('submit');
  const deadline = Date.now() + 5000;
  let created;
  while (!(created = await evaluate('window.createdRequest'))) {
    assert(Date.now() < deadline, JSON.stringify(await evaluate('confidex.snapshot()')));
    await delay(50);
  }
  assert.equal(created.name, 'pre seed🌴tail clipboard');
  assert.equal(created.password, 'public-fixture-password');
  return {singleTap: true, reopenAfterDismissal: true, nativePasteTarget: true,
    longPressAllowed: true, nativeHoldStable: true, keyboardPaste: true, clipboardPasteOnce: true, unicode: true,
    caretAfterRetap: true, passwordPaste: true};
}, {windowSize: [390, 1050], viewport: [390, 1050]});
console.log(JSON.stringify(result));
