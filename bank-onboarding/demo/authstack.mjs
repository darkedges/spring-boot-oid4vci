// A stand-in for AuthStack, for the isolated demo only. It does the three things the demo's bank, issuer and verifier ask of it:
// a client-credentials token for the bank's worker, the environment's signing keys, and who the demo's console administrator is
// (for setting up the tenants). One environment, one worker, one administrator; keys are made at start-up and kept in memory.
import http from 'node:http';
import {generateKeyPairSync, createSign, randomUUID, timingSafeEqual} from 'node:crypto';

const env = name => process.env[name] || (() => { throw Error(name + ' is required'); })();
const base = env('PUBLIC_URL'), environment = env('ENVIRONMENT_ID');
const clientId = env('WORKER_CLIENT_ID'), clientSecret = env('WORKER_CLIENT_SECRET'), adminToken = env('ADMIN_TOKEN');
const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
const kid = randomUUID();
const jwks = {keys: [{...publicKey.export({format: 'jwk'}), kid, use: 'sig', alg: 'RS256'}]};
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const same = (a, b) => Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function token() {
  const now = Math.floor(Date.now() / 1000);
  const head = encode({alg: 'RS256', kid, typ: 'JWT'});
  const claims = encode({iss: `${base}/${environment}/as`, client_id: clientId, environmentId: environment, type: 'client_credentials', iat: now, exp: now + 3600});
  return `${head}.${claims}.${createSign('RSA-SHA256').update(`${head}.${claims}`).sign(privateKey, 'base64url')}`;
}

function isWorker(authorization = '') {
  const [scheme, value = ''] = authorization.split(' ');
  if (scheme !== 'Basic') return false;
  const [id, secret = ''] = Buffer.from(value, 'base64').toString().split(':').map(part => decodeURIComponent(part));
  return same(id, clientId) && same(secret, clientSecret);
}

http.createServer(async (request, response) => {
  const reply = (status, body) => response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}).end(JSON.stringify(body));
  const path = new URL(request.url, base).pathname;
  let body = '';
  for await (const chunk of request) { body += chunk; if (body.length > 10000) return reply(413, {error: 'too_large'}); }
  if (path === `/${environment}/as/jwks` && request.method === 'GET') return reply(200, jwks);
  if (path === `/${environment}/as/token` && request.method === 'POST') {
    if (!isWorker(request.headers.authorization)) return reply(401, {error: 'invalid_client'});
    if (new URLSearchParams(body).get('grant_type') !== 'client_credentials') return reply(400, {error: 'unsupported_grant_type'});
    return reply(200, {access_token: token(), token_type: 'Bearer', expires_in: 3600});
  }
  if (path === '/api/auth/me' && request.method === 'GET') {
    if (!same(request.headers.authorization || '', `Bearer ${adminToken}`)) return reply(401, {error: 'unauthorized'});
    return reply(200, {user: {id: 'demo-admin', email: 'admin@risk-e.example.test', role: 'ADMIN'}, environments: [{id: environment, name: 'Risk E Bank Demo'}]});
  }
  reply(404, {error: 'not_found'});
}).listen(8000, () => console.log('Demo AuthStack stand-in listening'));
