// Sets the demo bank up as a tenant of the demo's shared issuer and verifier, through their admin APIs, as an administrator would in
// the AuthStack console. The settings mirror the ones the live bank pastes there (AuthStack's terraform/risk-e-bank). The services
// keep tenants in memory, so this runs after every start.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {BANK, ISSUER, VERIFIER, BANK_ISSUER, ENVIRONMENT, demoFetch} from './hosts.mjs';

const STAFF_VCT = '/vct/BankStaffCredential';

export function issuerSettings(clientId) {
  return {
    credentialConfigurationsSupported: {
      BankStaffCredential: {
        format: 'dc+sd-jwt', vct: STAFF_VCT, scope: 'BankStaffCredential',
        claims: ['staff_id', 'bank_id', 'given_name', 'family_name', 'department'].map(c => ({path: [c]})),
        proof_types_supported: {jwt: {proof_signing_alg_values_supported: ['ES256']}}, cryptographic_binding_methods_supported: ['jwk'],
      },
    },
    proofing: {enabled: false},
    tenantApi: {clients: [clientId]},
    issuanceHook: {url: `${BANK}/api/issuer-hook/v1`},
  };
}

export function verifierSettings(clientId, passportKey, legacyBankKey) {
  const query = (id, vctValues, claims) => ({credentials: [{id, format: 'dc+sd-jwt', meta: {vct_values: vctValues}, claims: claims.map(c => ({path: [c]}))}]});
  return {
    registrations: {
      passport: {
        responseMode: 'direct_post', requestParameters: ['passport_check_after'],
        dcqlQuery: query('passport', [`${ISSUER}/vct/PassportCredential`],
          ['given_name', 'family_name', 'birth_date', 'expiry_date', 'assurance_level', 'evidence', 'proofed_at']),
      },
      'staff-sign-in': {
        responseMode: 'direct_post',
        dcqlQuery: query('staff', [`${BANK_ISSUER}${STAFF_VCT}`, `${BANK}${STAFF_VCT}`], ['staff_id', 'bank_id']),
      },
    },
    trustedIssuers: [
      {issuer: ISSUER, jwks: {keys: [passportKey]}},
      {issuer: BANK_ISSUER, jwksUri: `${BANK_ISSUER}/jwks`},
      {issuer: BANK, jwks: {keys: [legacyBankKey]}},
    ],
    tenantApi: {clients: [clientId]},
  };
}

export async function seed({adminToken, clientId}) {
  const key = name => JSON.parse(readFileSync(resolve(import.meta.dirname, `runtime/keys/${name}-public.jwk`), 'utf8'));
  for (const [service, settings] of [[ISSUER, issuerSettings(clientId)], [VERIFIER, verifierSettings(clientId, key('passport'), key('bank'))]]) {
    const response = await demoFetch(`${service}/admin/api/tenants/${ENVIRONMENT}`, {
      method: 'PUT', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}`},
      body: JSON.stringify({slug: 'bank', enabled: true, settings}),
    });
    if (!response.ok) throw Error(`Could not set up the demo bank on ${service}: ${response.status} ${await response.text()}`);
    console.log(`Demo bank set up on ${service}`);
  }
}
