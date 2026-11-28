// The demo's HTTPS names and how this machine's Node code reaches them. The browser and the containers resolve *.demo.localhost
// themselves (to the proxy); Node on Windows doesn't, so its requests are sent to loopback with the name kept for TLS.
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

export const PORT = 43443;
const url = name => `https://${name}.demo.localhost:${PORT}`;
export const BANK = url('bank'), ISSUER = url('issuer'), VERIFIER = url('verifier'), AUTHSTACK = url('authstack');
/** The demo bank's AuthStack environment, and so its tenant on the shared issuer and verifier. */
export const ENVIRONMENT = 'demo-bank';
export const BANK_ISSUER = `${ISSUER}/t/bank`, BANK_VERIFIER = `${VERIFIER}/t/bank`;
export const ORIGINS = [BANK, ISSUER, VERIFIER, AUTHSTACK];
/** The certificate authority the demo's proxy made, trusted for the demo's names only. */
export const PROXY_ROOT = resolve(import.meta.dirname, 'runtime/caddy/caddy/pki/authorities/local/root.crt');

/** Like fetch, for a demo address: no redirects are followed. */
export function demoFetch(address, {method = 'GET', headers = {}, body, timeout = 15000} = {}) {
  const target = new URL(address);
  if (!ORIGINS.includes(target.origin)) return Promise.reject(Error('Non-demo destination'));
  return new Promise((done, failed) => {
    const request = https.request(target, {
      method, headers: body === undefined ? headers : {...headers, 'Content-Length': Buffer.byteLength(body)},
      ca: readFileSync(PROXY_ROOT), servername: target.hostname,
      lookup: (_host, options, callback) => options?.all ? callback(null, [{address: '127.0.0.1', family: 4}]) : callback(null, '127.0.0.1', 4),
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        done({status: response.statusCode, ok: response.statusCode >= 200 && response.statusCode < 300,
          text: async () => text, json: async () => JSON.parse(text)});
      });
    });
    request.setTimeout(timeout, () => request.destroy(Error('Timed out: ' + address)));
    request.on('error', failed);
    request.end(body);
  });
}
