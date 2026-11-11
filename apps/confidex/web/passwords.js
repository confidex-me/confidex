import {evaluatePassword} from '/password-host.js';
export const runPasswordWork = bytes => evaluatePassword(bytes, '/app.js');
