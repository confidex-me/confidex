(() => {
  if (globalThis.confidexChannel) return;
  globalThis.confidexChannel = true;

  const MAX_ELEMENTS = 12000;
  const MAX_FORMS = 24;
  const MAX_MUTATIONS = 4096;
  const MAX_FIELDS = 32;
  const KINDS = new Set(['text', 'email', 'tel', 'password']);
  const attribute = (element, name) => Element.prototype.getAttribute.call(element, name);
  const rootOf = element => Node.prototype.getRootNode.call(element);
  // Form controls can shadow named properties on their HTMLFormElement owner.
  const actionOf = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'action').get;
  const methodOf = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'method').get;
  const shadowOf = Object.getOwnPropertyDescriptor(Element.prototype, 'shadowRoot').get;
  const parentOf = Object.getOwnPropertyDescriptor(Node.prototype, 'parentElement').get;
  const slotOf = Object.getOwnPropertyDescriptor(Element.prototype, 'assignedSlot').get;
  const inputValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  const watched = new WeakMap();
  const ids = new WeakMap();
  const versions = new WeakMap();
  const observed = new WeakSet();
  const operations = new Map();
  let nextId = 0;
  let page = 0;
  let url;
  let capturePermit;
  let captureEpoch = 0;
  let captureTimer;
  let planning = false;
  let nextProbe = 0;
  let replanning = false;

  function id(node) {
    if (!ids.has(node)) ids.set(node, ++nextId);
    return ids.get(node);
  }

  function invalidate(records) {
    if (records.length && capturePermit) scheduleCapturePlan();
    let remaining = MAX_MUTATIONS;
    for (const record of records) {
      remaining -= 1 + record.removedNodes.length;
      if (remaining < 0) {
        changedPage();
        return;
      }
      const owner = watched.get(record.target);
      if (owner) versions.set(owner, (versions.get(owner) ?? 0) + 1);
      if (record.type === 'childList') {
        for (const node of record.removedNodes) {
          const removed = watched.get(node);
          if (removed) versions.set(removed, (versions.get(removed) ?? 0) + 1);
        }
      }
    }
  }

  const observer = new MutationObserver(invalidate);
  function observe(root) {
    if (observed.has(root)) return;
    observed.add(root);
    if (root !== document) root.addEventListener('submit', captureSubmit, true);
    observer.observe(root, {
      subtree: true, childList: true, attributes: true,
      attributeFilter: ['type', 'name', 'id', 'autocomplete', 'aria-label', 'aria-labelledby',
        'form', 'action', 'formaction', 'method', 'formmethod', 'hidden', 'disabled', 'readonly', 'inert', 'href', 'for'],
    });
  }

  function changedPage() {
    page++;
    url = location.href;
    operations.clear();
    if (capturePermit) {
      capturePermit.forms.clear();
      scheduleCapturePlan();
    }
  }

  addEventListener('pageshow', event => { if (event.persisted) changedPage(); });
  addEventListener('pagehide', changedPage);
  addEventListener('hashchange', changedPage);
  addEventListener('popstate', changedPage);

  function collect(root, result) {
    const roots = [root];
    for (const current of roots) {
      observe(current);
      const walker = document.createTreeWalker(current, NodeFilter.SHOW_ELEMENT);
      for (let node; (node = walker.nextNode()); ) {
        if (--result.budget < 0) return false;
        const shadow = shadowOf.call(node);
        if (shadow) roots.push(shadow);
        if (node instanceof HTMLInputElement) {
          if (KINDS.has(node.type)) result.inputs.push(node);
          else if (node.type === 'submit' || node.type === 'image') result.submitters.push(node);
        } else if (node instanceof HTMLButtonElement && node.type === 'submit') {
          result.submitters.push(node);
        }
      }
    }
    return true;
  }

  function visible(input) {
    if (!input.isConnected || input.readOnly || input.matches(':disabled')) return false;
    if (!Array.from(input.getClientRects()).some(rect => rect.width > 0 && rect.height > 0)) return false;
    for (let node = input; node; node = slotOf.call(node) ?? parentOf.call(node) ?? rootOf(node).host) {
      if (attribute(node, 'hidden') !== null || attribute(node, 'inert') !== null) return false;
      const style = getComputedStyle(node);
      if (style.visibility !== 'visible' || style.opacity === '0' || style.contentVisibility === 'hidden') return false;
    }
    return true;
  }

  function label(node) {
    const aria = attribute(node, 'aria-label');
    const references = (attribute(node, 'aria-labelledby') ?? '').slice(0, 256).split(/\s+/);
    const related = references.slice(0, 4).map(key => key
      ? rootOf(node).getElementById(key)?.textContent.slice(0, 80) ?? ''
      : '').join(' ').trim();
    return aria || related || '';
  }

  function route(value, base) {
    try {
      const action = new URL(value, base);
      return action.protocol === 'https:' && !action.username && !action.password
        ? action.origin : '';
    } catch {
      return '';
    }
  }

  function inspect() {
    if (url !== location.href) changedPage();
    invalidate(observer.takeRecords());
    const elements = {inputs: [], submitters: [], budget: MAX_ELEMENTS};
    const groups = new Map();
    const nodes = new Map();
    if (!collect(document, elements)) return {page, forms: [], nodes};
    const submitActions = new Map();
    const getSubmitters = new Set();
    for (const button of elements.submitters) {
      const owner = button.form;
      if (!owner) continue;
      watched.set(button, owner);
      if (button.matches(':disabled')) continue;
      if (button.hasAttribute('formmethod') && !['post', 'dialog'].includes(button.formMethod)) {
        getSubmitters.add(owner);
      }
      if (button.hasAttribute('formaction')) {
        const destinations = submitActions.get(owner) ?? new Set();
        destinations.add(route(button.getAttribute('formaction') || location.href, document.baseURI));
        submitActions.set(owner, destinations);
      }
    }
    for (const input of elements.inputs) {
      const owner = input.form ?? input.getRootNode();
      watched.set(input, owner);
      if (!visible(input)) continue;
      let form = groups.get(owner);
      if (!form) {
        if (groups.size === MAX_FORMS) return {page, forms: [], nodes};
        const htmlForm = owner instanceof HTMLFormElement;
        const action = htmlForm ? actionOf.call(owner) : location.href;
        const destinations = new Set([route(action, location.href), ...(submitActions.get(owner) ?? [])]);
        form = {
          id: id(owner), stamp: versions.get(owner) ?? 0,
          label: (htmlForm ? (label(owner) || attribute(owner, 'name') || attribute(owner, 'id') || '') : '').slice(0, 128),
          destinations: [...destinations],
          submitsWithGet: htmlForm && (methodOf.call(owner) === 'get' || getSubmitters.has(owner)),
          fields: [],
        };
        if (owner instanceof HTMLFormElement) watched.set(owner, owner);
        groups.set(owner, form);
      }
      const labels = Array.from(input.labels ?? []).slice(0, 4).map(node => node.textContent.slice(0, 80));
      const field = {
        id: id(input), kind: input.type,
        autocomplete: autocomplete(input),
        hint: [input.name, input.id, label(input), ...labels].map(text => text.slice(0, 32)).join(' ').slice(0, 128),
      };
      if (form.fields.length <= MAX_FIELDS) form.fields.push(field);
      nodes.set(field.id, input);
    }
    return {page, forms: [...groups.values()].filter(form =>
      form.fields.length <= MAX_FIELDS && form.destinations.length <= 16), nodes};
  }

  function autocomplete(input) {
    const value = (attribute(input, 'autocomplete') ?? '').trim().toLowerCase();
    if (value.length <= 32) return value;
    // Keep complete trailing tokens. A truncated token must stay unsupported.
    const trailing = value.slice(-32);
    if (/[\t\n\f\r ]/.test(value.at(-33))) return trailing;
    const boundary = trailing.search(/[\t\n\f\r ]/);
    return boundary < 0 ? '?' : '?' + trailing.slice(boundary);
  }

  function setValue(input, value) {
    inputValue.set.call(input, value);
  }

  function resetCapture() {
    captureEpoch++;
    capturePermit = undefined;
    nextProbe = 0;
    clearTimeout(captureTimer);
    captureTimer = undefined;
  }

  function scheduleCapturePlan() {
    if (captureTimer) return;
    captureTimer = setTimeout(() => {
      captureTimer = undefined;
      void prepareCapture();
    }, 100);
  }

  async function requestPlan(snapshot) {
    return chrome.runtime.sendMessage({kind: 'CapturePlan', version: 1, snapshot}).catch(() => false);
  }

  async function prepareCapture() {
    if (document.hidden || document.prerendering || globalThis.origin !== location.origin
        || location.protocol !== 'https:') return;
    if (planning) {
      replanning = true;
      return;
    }
    const started = Date.now();
    if (capturePermit && !currentPermit(started)) capturePermit = undefined;
    if (!capturePermit && started < nextProbe) return;
    planning = true;
    const epoch = captureEpoch;
    try {
      if (!capturePermit) {
        nextProbe = started + 1000;
        const permit = await requestPlan(null);
        if (epoch !== captureEpoch || !permit?.owner || !permit.remaining) return;
        capturePermit = {since: started, deadline: started + permit.remaining, owner: permit.owner,
          revision: permit.revision, forms: new Map()};
      }
      const {page, forms} = inspect();
      const snapshot = {page, forms};
      const current = capturePermit;
      if (JSON.stringify(snapshot) === current.snapshot) return;
      const updated = await requestPlan(snapshot);
      if (epoch !== captureEpoch || current !== capturePermit) return;
      if (!updated?.owner || !updated.remaining) {
        resetCapture();
        return;
      }
      const planned = new Map();
      for (const field of updated.fields) {
        const form = forms.find(form => form.id === field.form);
        if (form) planned.set(form.id, {metadata: JSON.stringify(form), field});
      }
      capturePermit = {since: started, deadline: started + updated.remaining, owner: updated.owner,
        revision: updated.revision, page, forms: planned, snapshot: JSON.stringify(snapshot)};
    } finally {
      planning = false;
      if (replanning) {
        replanning = false;
        scheduleCapturePlan();
      }
    }
  }

  function currentPermit(now) {
    return capturePermit && capturePermit.since <= now && now < capturePermit.deadline;
  }

  function capture(owner) {
    const permit = capturePermit;
    if (!currentPermit(Date.now()) || !owner || document.prerendering) return;
    const {page, forms, nodes} = inspect();
    const formId = ids.get(owner);
    const plan = permit.forms.get(formId);
    const form = forms.find(form => form.id === formId);
    if (!plan || page !== permit.page || !form || plan.metadata !== JSON.stringify(form)) {
      scheduleCapturePlan();
      return;
    }
    const values = {};
    for (const [role, field] of Object.entries(plan.field)) {
      if (role === 'form') continue;
      const node = field === null ? null : nodes.get(field);
      if (field !== null && (!node || !visible(node))) return;
      const value = node ? inputValue.get.call(node) : null;
      if (value !== null && value.length > 4096) return;
      values[role] = value;
    }
    void chrome.runtime.sendMessage({kind: 'CaptureCandidate', version: 1,
      owner: permit.owner, revision: permit.revision, snapshot: {page, forms: [form]}, values})
      .catch(() => {});
  }

  function captureSubmit(event) {
    if (event.isTrusted && event.target instanceof HTMLFormElement) capture(event.target);
  }

  function captureClick(event) {
    if (!event.isTrusted || !capturePermit || event.button !== 0) return;
    const button = event.composedPath().find(node => node instanceof HTMLButtonElement
      || (node instanceof HTMLInputElement && ['button', 'submit', 'image'].includes(node.type))
      || (node instanceof HTMLElement && attribute(node, 'role') === 'button'));
    if (!button || button.matches(':disabled,[aria-disabled=true]') || !visible(button)) return;
    const hint = [attribute(button, 'aria-label'), attribute(button, 'name'),
      attribute(button, 'id'), attribute(button, 'value'), button.textContent]
      .map(text => text?.slice(0, 128) ?? '').join(' ').toLowerCase();
    if (!/\b(log\s?in|log\s?on|sign\s?in|sign\s?up|register|next|continue|change\s+password|reset\s+password|save\s+password)\b|войти|зарегистрироваться|далее|продолжить|пароль/.test(hint)) return;
    const owner = button.form ?? button.closest('form') ?? rootOf(button);
    if (owner instanceof HTMLFormElement && ['submit', 'image'].includes(button.type)
        && !button.formNoValidate && !owner.hasAttribute('novalidate')
        && Element.prototype.matches.call(owner, ':invalid')) return;
    capture(owner);
  }

  document.addEventListener('submit', captureSubmit, true);
  document.addEventListener('click', captureClick, true);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void prepareCapture(); });
  addEventListener('pageshow', () => { void prepareCapture(); });
  for (const event of ['focusin', 'pointerdown']) {
    document.addEventListener(event, event => {
      if (event.isTrusted) void prepareCapture();
    }, true);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { void prepareCapture(); }, {once: true});
  }
  void prepareCapture();

  function matchingForm(operation, formId, origin) {
    const snapshot = operations.get(operation);
    if (!snapshot || document.prerendering || location.origin !== origin) return;
    const fresh = inspect();
    const form = fresh.forms.find(form => form.id === formId);
    if (fresh.page === snapshot.page && form &&
        form.destinations.every(destination => destination === origin) &&
        JSON.stringify(form) === snapshot.form) return {form, nodes: fresh.nodes};
  }

  function fill(message) {
    const fresh = matchingForm(message.operation, message.fields.form, message.origin);
    operations.delete(message.operation);
    if (!fresh || (message.fields.password !== null && fresh.form.submitsWithGet)) return false;
    const {username, password} = message.login;
    const entries = [[message.fields.username, username], [message.fields.password, password]]
      .filter(([, value]) => value !== null);
    if (!entries.length || entries.some(([id, value]) => typeof value !== 'string' || value.length > 4096
        || !fresh.form.fields.some(field => field.id === id))) return false;
    const fields = entries.map(([id, value]) => [fresh.nodes.get(id), value]);
    // Assign both fields before events can run site code and replace the form.
    for (const [input, value] of fields) setValue(input, value);
    for (const [input] of fields) {
      input.dispatchEvent(new Event('input', {bubbles: true, composed: true}));
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }
    return true;
  }

  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id || sender.tab
        || sender.url !== chrome.runtime.getURL('background.js') || message?.version !== 1) return;
    if (message.kind === 'ConfidexDocumentCheck') return void reply(true);
    if (message.kind === 'ConfidexCaptureReset') {
      resetCapture();
      void prepareCapture();
      return void reply(true);
    }
    if (document.prerendering || message.origin !== location.origin
        || location.protocol !== 'https:') return void reply(false);

    if (message.kind === 'ConfidexInspect' || message.kind === 'ConfidexPreflight') {
      const {page, forms} = inspect();
      if (message.kind === 'ConfidexPreflight') {
        const form = forms.find(form => form.id === message.form);
        if (!form) return void reply(false);
        operations.clear();
        operations.set(message.operation, {page, form: JSON.stringify(form)});
      }
      reply({page, forms});
    } else if (message.kind === 'ConfidexValidateFill') {
      reply(Boolean(matchingForm(message.operation, message.form, message.origin)));
    } else if (message.kind === 'ConfidexFill') {
      reply(fill(message));
    }
  });
})();
