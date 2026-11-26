(() => {
  if (globalThis.confidexChannel) return;
  globalThis.confidexChannel = true;

  const MAX_ELEMENTS = 12000;
  const MAX_FORMS = 24;
  const MAX_MUTATIONS = 4096;
  const MAX_FIELDS = 32;
  const KINDS = new Set(['text', 'email', 'tel', 'password']);
  const BUTTON_TYPES = new Set(['button', 'submit', 'image', 'reset']);
  const SPA_ACTIONS = new Set([
    'log in', 'login', 'log on', 'logon', 'sign in', 'signin', 'sign up', 'signup',
    'register', 'create account', 'create an account', 'change password', 'reset password', 'save password',
    'войти', 'войти в аккаунт', 'вход', 'зарегистрироваться', 'регистрация', 'создать аккаунт',
    'изменить пароль', 'сменить пароль', 'сбросить пароль', 'сохранить пароль',
  ]);
  const SPA_NEXT_STEP = new Set(['next', 'continue', 'далее', 'продолжить']);
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
  let inline;
  let inlineSelection;
  let autoEnabled = false;
  let autoUsed = false;
  let autoTimer, autoSnapshot;
  let autoRequest;
  let settingRevision = 0;

  async function refreshAutoSetting() {
    const revision = ++settingRevision;
    autoEnabled = false;
    const enabled = await chrome.runtime.sendMessage({kind: 'AutoFillSetting', version: 1}).catch(() => false);
    if (revision !== settingRevision) return;
    autoEnabled = enabled === true;
    autoSnapshot = undefined;
    if (autoEnabled) {
      observe(document);
      scheduleAuto();
    }
  }

  function scheduleAuto() {
    if (!autoEnabled || autoUsed || autoTimer || document.hidden || !document.hasFocus()) return;
    autoTimer = setTimeout(() => {
      autoTimer = undefined;
      if (!inline && !inlineSelection) void tryAutoFill();
    }, 120);
  }

  function tryAutoFill() {
    if (autoRequest) return autoRequest;
    if (!canAutoFill()) return;
    const {page, forms} = inspect();
    if (!forms.length) { autoSnapshot = undefined; return; }
    const signature = JSON.stringify({page, forms});
    if (signature === autoSnapshot) return;
    autoSnapshot = signature;
    autoRequest = chrome.runtime.sendMessage({kind: 'AutoFillOnOpen', version: 1})
      .catch(() => false)
      .finally(() => {
        autoRequest = undefined;
        scheduleAuto();
      });
    return autoRequest;
  }

  function canAutoFill() {
    return autoEnabled && !autoUsed && !document.hidden && !document.prerendering && document.hasFocus();
  }

  function emptyTargets(target, nodes) {
    return [target.username, target.password].filter(id => id != null).every(id => {
      const field = nodes.get(id);
      return field && visible(field) && inputValue.get.call(field) === '';
    });
  }
  let captureTimer;
  let planning = false;
  let nextProbe = 0;
  let replanning = false;

  function id(node) {
    if (!ids.has(node)) ids.set(node, ++nextId);
    return ids.get(node);
  }

  function invalidate(records) {
    if (records.length) scheduleAuto();
    if (records.length && inline?.position) inline.position();
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
    // Listen at the root that owns the form, including non-composed submits.
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
    const form = event.target;
    if (event.isTrusted && form instanceof HTMLFormElement && rootOf(form) === event.currentTarget) {
      capture(form);
    }
  }

  function captureClick(event) {
    if (!event.isTrusted || !currentPermit(Date.now()) || event.button !== 0) return;
    const path = event.composedPath();
    const native = path.find(node => node instanceof HTMLButtonElement
      || (node instanceof HTMLInputElement && BUTTON_TYPES.has(node.type)));
    // Form submitters are handled by the submit listener after native validation.
    if (native?.type === 'reset' || (native?.form && native.type !== 'button')) return;
    const button = native ?? path.find(node => node instanceof HTMLElement && attribute(node, 'role') === 'button');
    if (!button || button.matches(':disabled,[aria-disabled=true],[aria-pressed]') || !visible(button)) return;
    const text = label(button) || (button instanceof HTMLInputElement ? attribute(button, 'value') : button.textContent);
    if (!text || text.length > 128) return;
    const action = text.toLowerCase().trim().replace(/[\s-]+/g, ' ');
    const owner = button.form ?? button.closest('form') ?? rootOf(button);
    if (SPA_ACTIONS.has(action)) {
      capture(owner);
    } else if (SPA_NEXT_STEP.has(action)) {
      const fields = capturePermit.forms.get(ids.get(owner))?.field;
      if (fields?.username != null && fields.password === null) capture(owner);
    }
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

  addEventListener('focus', scheduleAuto);
  document.addEventListener('visibilitychange', scheduleAuto);
  void refreshAutoSetting();

  function dismissInline() {
    if (!inline) return;
    inline.host?.remove();
    clearTimeout(inline.expiry);
    inline = undefined;
  }

  function activeInput() {
    let node = document.activeElement;
    while (node?.shadowRoot?.activeElement) node = node.shadowRoot.activeElement;
    return node;
  }

  function inlineCall(action) {
    return chrome.runtime.sendMessage({kind: 'ConfidexInline', version: 1, action}).catch(() => false);
  }

  async function showInline(field, after = null) {
    dismissInline();
    inlineSelection = undefined;
    if (!document.hasFocus() || !visible(field)) return;
    const view = {field};
    inline = view;
    if (autoEnabled && !after) {
      await tryAutoFill();
      if (inline !== view) return;
    }
    const result = await inlineCall({Discover: {after}});
    if (inline !== view) return;
    const site = result?.Site;
    const fieldId = ids.get(field);
    const choice = site?.forms.find(({target}) => target.username === fieldId || target.password === fieldId);
    if (!choice || activeInput() !== field || !visible(field)) return dismissInline();
    const rows = site.matches.rows.filter(row => choice.target.password !== null || row.username);
    if (!rows.length && !site.matches.next) return dismissInline();
    if (site.preferred) {
      const index = rows.findIndex(row => JSON.stringify(row.target) === JSON.stringify(site.preferred));
      if (index > 0) rows.unshift(rows.splice(index, 1)[0]);
    }

    const host = document.createElement('div');
    const root = host.attachShadow({mode: 'closed'});
    view.host = host;
    view.root = root;
    const style = new CSSStyleSheet();
    style.replaceSync(`
      :host { all:initial!important; position:fixed!important; inset:0 auto auto 0!important;
        width:0!important;height:0!important;overflow:visible!important;z-index:2147483647!important;
        opacity:1!important;visibility:visible!important;transform:none!important;pointer-events:none!important }
      button,.list { box-sizing:border-box; font:14px/1.35 system-ui,sans-serif; pointer-events:auto; }
      button { cursor:pointer; border:0; text-align:start; }
      button:focus-visible { outline:2px solid #e4ba61; outline-offset:-2px; }
      .icon { position:fixed; display:grid;place-items:center;border-radius:6px;
        background:#e4ba61;color:#201707;padding:2px; }
      .list { position:fixed; overflow:auto; padding:4px; background:#18191c;
        color:#f5f4ef;border:1px solid #494a50;border-radius:8px;box-shadow:0 6px 22px #0004; }
      .list[hidden] { display:none; }
      .list button { display:block;width:100%;padding:8px 12px;border-radius:5px;background:transparent;color:inherit; }
      .list button:hover,.list button:focus { background:#303135; }
      strong,small { display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
      small { color:#cecdd0;font-size:13px; }
    `);
    root.adoptedStyleSheets = [style];
    const icon = document.createElement('button');
    icon.type = 'button';
    icon.className = 'icon';
    icon.ariaLabel = 'Confidex · ' + site.labels.fill;
    icon.title = icon.ariaLabel;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '18');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', 'M13 9a5 5 0 1 1-10 0 5 5 0 0 1 10 0Zm-1.5 3.5L20 21l2-2-2-2-1.5 1.5');
    path.setAttribute('fill','none');
    path.setAttribute('stroke','currentColor');
    path.setAttribute('stroke-width','2');
    svg.append(path);
    icon.append(svg);
    const list = document.createElement('div');
    list.className = 'list';
    const multiple = after !== null || rows.length !== 1 || Boolean(site.matches.next);
    list.hidden = !multiple;
    function choose(row) {
      if (inline !== view || !visible(field) || !document.hasFocus()) return;
      dismissInline();
      const selection = {operation: site.operation, field};
      inlineSelection = selection;
      void inlineCall({Fill: {operation: site.operation, form: choice.target.form, target: row.target}}).finally(() => {
        if (inlineSelection === selection) inlineSelection = undefined;
      });
    }
    icon.addEventListener('click', event => {
      if (!event.isTrusted) return;
      if (!multiple) choose(rows[0]);
      else { list.hidden = !list.hidden; position(); }
    });
    for (const row of rows) {
      const button = document.createElement('button');
      button.type = 'button';
      const title = document.createElement('strong');
      title.textContent = row.title || site.labels.untitled;
      const name = document.createElement('small');
      name.textContent = row.username;
      button.append(title, name);
      button.addEventListener('click', event => { if (event.isTrusted) choose(row); });
      list.append(button);
    }
    if (site.matches.next) {
      const more = document.createElement('button');
      more.type = 'button';
      more.textContent = site.labels.more;
      more.addEventListener('click', event => {
        if (!event.isTrusted) return;
        field.focus({preventScroll:true});
        void showInline(field, site.matches.next);
      });
      list.append(more);
    }
    root.addEventListener('mousedown', event => {
      if (event.button === 0) event.preventDefault();
    });
    root.addEventListener('keydown', event => {
      if (!event.isTrusted || event.key !== 'Enter' || event.isComposing || event.repeat) return;
      const index = Array.prototype.indexOf.call(list.children, root.activeElement);
      if (index < 0 || !rows[index]) return;
      event.preventDefault();
      event.stopPropagation();
      choose(rows[index]);
    });
    root.append(icon, list);
    document.documentElement.append(host);

    function position() {
      if (inline !== view) return;
      const r = field.getBoundingClientRect();
      if (!visible(field) || r.bottom <= 0 || r.top >= innerHeight || r.width < 36 || r.height < 18) {
        dismissInline();
        return;
      }
      const size = Math.min(28, r.height - 4);
      Object.assign(icon.style, {left:(r.right-size-4)+'px',top:(r.top+(r.height-size)/2)+'px',width:size+'px',height:size+'px'});
      const width = Math.min(Math.max(220,r.width),420,innerWidth-8);
      const below = innerHeight - r.bottom - 6;
      const above = r.top - 6;
      const up = below < 120 && above > below;
      Object.assign(list.style, {width:width+'px',left:Math.max(4,Math.min(r.left,innerWidth-width-4))+'px',
        maxHeight:Math.max(0,Math.min(280,up ? above : below))+'px',
        top:up ? 'auto' : (r.bottom+3)+'px', bottom:up ? (innerHeight-r.top+3)+'px' : 'auto'});
    }
    view.position = position;
    position();
    view.expiry = setTimeout(() => { if (inline === view) dismissInline(); }, 89000);
    view.arrow = direction => {
      if (!multiple) { icon.focus({preventScroll:true}); return; }
      list.hidden = false;
      position();
      const buttons = [...list.children];
      const index = buttons.indexOf(root.activeElement);
      buttons[index < 0 ? (direction > 0 ? 0 : buttons.length-1)
        : (index+direction+buttons.length)%buttons.length].focus({preventScroll:true});
    };
  }

  document.addEventListener('focusin', event => {
    if (!event.isTrusted) return;
    const field = event.composedPath()[0];
    if (inline?.host && event.composedPath().includes(inline.host)) return;
    if (inline?.field === field) return;
    dismissInline();
    if (field instanceof HTMLInputElement && KINDS.has(field.type)) void showInline(field);
  }, true);
  document.addEventListener('focusout', () => {
    const view = inline;
    setTimeout(() => {
      if (view && inline === view && activeInput() !== view.field && activeInput() !== view.host) dismissInline();
    }, 0);
  }, true);
  document.addEventListener('keydown', event => {
    if (!inline || !event.isTrusted || event.isComposing
        || !event.composedPath().some(node => node === inline.field || node === inline.host)) return;
    if (event.key === 'Escape') {
      const {field,host} = inline;
      if (host && activeInput() === host) field.focus({preventScroll:true});
      dismissInline();
    } else if (inline.arrow && ['ArrowDown','ArrowUp'].includes(event.key)) {
      inline.arrow(event.key === 'ArrowDown' ? 1 : -1);
    } else return;
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
  document.addEventListener('input', event => {
    if (event.isTrusted && event.composedPath()[0] instanceof HTMLInputElement) autoUsed = true;
    inlineSelection = undefined; dismissInline(); }, true);
  document.addEventListener('pointerdown', event => {
    if (!event.isTrusted) return;
    inlineSelection = undefined;
    if (inline && !event.composedPath().some(node => node === inline.host || node === inline.field)) dismissInline();
  }, true);
  document.addEventListener('visibilitychange', () => { if (document.hidden) dismissInline(); });
  addEventListener('blur', dismissInline);
  addEventListener('pagehide', dismissInline);
  addEventListener('resize', () => inline?.position?.());
  document.addEventListener('scroll', () => inline?.position?.(), true);

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
    if (message.automatic && (!canAutoFill() || !emptyTargets(message.automatic, fresh.nodes))) return false;
    autoUsed = true;
    dismissInline();
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
      inlineSelection = undefined;
      dismissInline();
      resetCapture();
      void prepareCapture();
      void refreshAutoSetting();
      return void reply(true);
    }
    if (document.prerendering || message.origin !== location.origin
        || location.protocol !== 'https:') return void reply(false);

    if (message.inline && (inlineSelection?.operation !== message.operation || !document.hasFocus()
        || !visible(inlineSelection.field))) return void reply(false);

    if (message.kind === 'ConfidexInlineInspect') {
      if (!inline || !document.hasFocus() || activeInput() !== inline.field) return void reply(false);
      const {page, forms} = inspect();
      return void reply({snapshot: {page, forms}, field: ids.get(inline.field)});
    }
    if (message.kind === 'ConfidexInspect' || message.kind === 'ConfidexPreflight') {
      const {page, forms, nodes} = inspect();
      if (message.kind === 'ConfidexPreflight') {
        if (message.automatic && (!canAutoFill() || !emptyTargets(message.automatic, nodes))) return void reply(false);
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
