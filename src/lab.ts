import { createHmac, randomBytes, createHash } from 'node:crypto';

/**
 * A sealed lab that demonstrates why WebAuthn is phishing-resistant and TOTP
 * is not.
 *
 * THE DIFFERENTIATOR LIVES HERE.
 *
 * Every WebAuthn demo shows a passkey working. Almost none shows WHY it is
 * different from the MFA the organisation already has, and that difference is
 * the only part worth knowing: a relayed TOTP code is indistinguishable from a
 * legitimate one, because the code is a function of (shared secret, time) and
 * nothing else. It carries no information about WHERE it was typed.
 *
 * A WebAuthn assertion signs `clientDataJSON`, which contains the ORIGIN the
 * browser was actually talking to. The relying party compares that origin to
 * its own. An attacker relaying from https://bank.example.evil can forward the
 * challenge and the response, but it cannot make the browser assert an origin
 * it was not on - so the signature it relays is a signature over the WRONG
 * origin, and the check fails.
 *
 * SCOPE AND SAFETY
 * ----------------
 * Everything here is in-process. The "relay" is a function that passes values
 * between two other objects in the same program, against a virtual
 * authenticator this file also defines. There is no network client, no
 * capability against any third party, and nothing here works outside this
 * module. It is a demonstration of a defensive control.
 */

export const LEGITIMATE_ORIGIN = 'https://bank.example';
export const ATTACKER_ORIGIN = 'https://bank.example.evil';

// ---------------------------------------------------------------------------
// TOTP: a code derived from a shared secret and the clock. Nothing else.
// ---------------------------------------------------------------------------

export class TotpAuthenticator {
  private readonly secret: Buffer;
  constructor(secret: Buffer) {
    this.secret = secret;
  }

  /**
   * Note what this function does NOT take: the origin. It cannot bind the
   * code to a site, because it has no idea which site asked.
   */
  code(timeStepSeconds: number): string {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(timeStepSeconds));
    const digest = createHmac('sha1', this.secret).update(counter).digest();
    const offset = digest[digest.length - 1]! & 0x0f;
    const binary =
      ((digest[offset]! & 0x7f) << 24) |
      ((digest[offset + 1]! & 0xff) << 16) |
      ((digest[offset + 2]! & 0xff) << 8) |
      (digest[offset + 3]! & 0xff);
    return String(binary % 1_000_000).padStart(6, '0');
  }
}

export class TotpRelyingParty {
  private readonly secret: Buffer;
  private used = new Set<string>();
  constructor(secret: Buffer) {
    this.secret = secret;
  }

  /**
   * Verify a code. The signature of this method is the whole problem: there is
   * nowhere to put an origin, because the code does not commit to one.
   */
  verify(code: string, timeStepSeconds: number): boolean {
    const auth = new TotpAuthenticator(this.secret);
    for (const drift of [-1, 0, 1]) {
      if (auth.code(timeStepSeconds + drift) === code) {
        // Replay protection helps against reuse, not against a real-time relay:
        // the attacker submits first.
        const key = `${code}:${timeStepSeconds + drift}`;
        if (this.used.has(key)) return false;
        this.used.add(key);
        return true;
      }
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// WebAuthn: the assertion signs the origin the browser was on.
// ---------------------------------------------------------------------------

export interface ClientData {
  readonly type: 'webauthn.get' | 'webauthn.create';
  readonly challenge: string;
  /** Supplied by the BROWSER, not by the page. This is the load-bearing field. */
  readonly origin: string;
  readonly crossOrigin: boolean;
}

export interface Assertion {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly authenticatorData: { rpIdHash: string; signCount: number };
  readonly signature: string;
}

export interface Credential {
  readonly id: string;
  readonly rpId: string;
  readonly privateKey: Buffer;
  signCount: number;
}

function rpIdHash(rpId: string): string {
  return createHash('sha256').update(rpId).digest('hex');
}

/**
 * A virtual authenticator (equivalent to SoftWebAuthn in the real lab).
 *
 * The critical behaviour: `get` refuses to sign for an rpId that does not
 * match the origin the browser reports. A real authenticator enforces this
 * because the browser only ever passes it the origin of the page in the
 * address bar - which is the part an attacker cannot forge.
 */
export class VirtualAuthenticator {
  private credentials = new Map<string, Credential>();

  create(rpId: string, origin: string): Credential | null {
    if (!originMatchesRpId(origin, rpId)) return null;
    const cred: Credential = {
      id: randomBytes(8).toString('hex'), rpId,
      privateKey: randomBytes(32), signCount: 0,
    };
    this.credentials.set(cred.id, cred);
    return cred;
  }

  get(credentialId: string, challenge: string, origin: string): Assertion | null {
    const cred = this.credentials.get(credentialId);
    if (!cred) return null;
    // The authenticator itself will not sign for a mismatched origin.
    if (!originMatchesRpId(origin, cred.rpId)) return null;

    const clientData: ClientData = {
      type: 'webauthn.get', challenge, origin, crossOrigin: false,
    };
    const clientDataJSON = JSON.stringify(clientData);
    cred.signCount += 1;
    const authenticatorData = {
      rpIdHash: rpIdHash(cred.rpId), signCount: cred.signCount,
    };

    // The signature covers the authenticator data AND a hash of the client
    // data - so it commits to the origin.
    const payload =
      JSON.stringify(authenticatorData) +
      createHash('sha256').update(clientDataJSON).digest('hex');
    const signature = createHmac('sha256', cred.privateKey)
      .update(payload).digest('hex');

    return { credentialId, clientDataJSON, authenticatorData, signature };
  }

  /** Used only to model a cloned authenticator in the counter test. */
  rewindCounter(credentialId: string, to: number): void {
    const c = this.credentials.get(credentialId);
    if (c) c.signCount = to;
  }

  publicKeyOf(credentialId: string): Buffer | undefined {
    // HMAC is symmetric; the RP stores the same key material. A real
    // implementation stores a public key. The verification SHAPE is identical
    // and the origin check is unaffected.
    return this.credentials.get(credentialId)?.privateKey;
  }
}

export function originMatchesRpId(origin: string, rpId: string): boolean {
  let host: string;
  try {
    const url = new URL(origin);
    if (url.protocol !== 'https:') return false;
    host = url.hostname;
  } catch {
    return false;
  }
  // Exact match, or a subdomain of the rpId. Crucially, `bank.example.evil`
  // is NOT a subdomain of `bank.example` - a naive `endsWith` check would say
  // it is, and that single bug reintroduces phishability.
  return host === rpId || host.endsWith(`.${rpId}`);
}

export type WebAuthnFailure =
  | 'UNKNOWN_CREDENTIAL'
  | 'ORIGIN_MISMATCH'
  | 'RPID_MISMATCH'
  | 'CHALLENGE_MISMATCH'
  | 'BAD_SIGNATURE'
  | 'CLONED_AUTHENTICATOR';

export class WebAuthnRelyingParty {
  readonly rpId: string;
  readonly expectedOrigin: string;
  private keys = new Map<string, Buffer>();
  private counters = new Map<string, number>();
  private challenges = new Set<string>();

  constructor(rpId: string, expectedOrigin: string) {
    this.rpId = rpId;
    this.expectedOrigin = expectedOrigin;
  }

  register(credentialId: string, key: Buffer): void {
    this.keys.set(credentialId, key);
    this.counters.set(credentialId, 0);
  }

  newChallenge(): string {
    const c = randomBytes(16).toString('hex');
    this.challenges.add(c);
    return c;
  }

  verify(assertion: Assertion): WebAuthnFailure | null {
    const key = this.keys.get(assertion.credentialId);
    if (!key) return 'UNKNOWN_CREDENTIAL';

    const clientData = JSON.parse(assertion.clientDataJSON) as ClientData;

    // THE CHECK. The origin the browser reported is signed into the assertion,
    // and it must equal the origin this relying party is served from.
    if (clientData.origin !== this.expectedOrigin) return 'ORIGIN_MISMATCH';
    if (assertion.authenticatorData.rpIdHash !== rpIdHash(this.rpId)) {
      return 'RPID_MISMATCH';
    }
    if (!this.challenges.delete(clientData.challenge)) return 'CHALLENGE_MISMATCH';

    const payload =
      JSON.stringify(assertion.authenticatorData) +
      createHash('sha256').update(assertion.clientDataJSON).digest('hex');
    const expected = createHmac('sha256', key).update(payload).digest('hex');
    if (expected !== assertion.signature) return 'BAD_SIGNATURE';

    const seen = this.counters.get(assertion.credentialId) ?? 0;
    if (assertion.authenticatorData.signCount <= seen) {
      return 'CLONED_AUTHENTICATOR';
    }
    this.counters.set(assertion.credentialId, assertion.authenticatorData.signCount);
    return null;
  }
}
