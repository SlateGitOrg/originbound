import {
  ATTACKER_ORIGIN, LEGITIMATE_ORIGIN, TotpAuthenticator, TotpRelyingParty,
  VirtualAuthenticator, WebAuthnRelyingParty, type WebAuthnFailure,
} from './lab.ts';

/**
 * The relay, confined to this process.
 *
 * A phishing site proxies a login in real time: it shows the victim a page that
 * looks like the bank, forwards whatever the victim provides to the real bank,
 * and forwards the bank's responses back. This is the attack that defeats every
 * shared-secret second factor - TOTP, SMS, push approval - because in each case
 * the thing the victim produces is valid wherever it is presented.
 *
 * Both functions below run the SAME attack. Only the factor differs.
 */

export interface RelayOutcome {
  readonly factor: 'TOTP' | 'WebAuthn';
  readonly relaySucceeded: boolean;
  readonly rejectedBecause: WebAuthnFailure | 'CODE_REJECTED' | null;
  /** The field that made the difference, for the annotated trace. */
  readonly decidingField: string | null;
  readonly trace: readonly string[];
}

export function relayTotp(timeStep: number): RelayOutcome {
  const secret = Buffer.from('shared-secret-between-user-and-bank');
  const victim = new TotpAuthenticator(secret);
  const bank = new TotpRelyingParty(secret);
  const trace: string[] = [];

  trace.push(`victim believes they are on ${ATTACKER_ORIGIN}`);
  const code = victim.code(timeStep);
  trace.push(`victim reads code ${code} from their authenticator app`);
  trace.push(`victim types ${code} into the attacker's page`);
  trace.push(`attacker forwards ${code} to ${LEGITIMATE_ORIGIN}`);

  const accepted = bank.verify(code, timeStep);
  trace.push(
    accepted
      ? `${LEGITIMATE_ORIGIN} ACCEPTS - the code is valid, and it carries no ` +
        'information about where it was typed'
      : `${LEGITIMATE_ORIGIN} rejects the code`,
  );

  return {
    factor: 'TOTP',
    relaySucceeded: accepted,
    rejectedBecause: accepted ? null : 'CODE_REJECTED',
    decidingField: null,
    trace,
  };
}

export function relayWebAuthn(): RelayOutcome {
  const authenticator = new VirtualAuthenticator();
  const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
  const trace: string[] = [];

  const cred = authenticator.create('bank.example', LEGITIMATE_ORIGIN)!;
  bank.register(cred.id, authenticator.publicKeyOf(cred.id)!);
  trace.push(`victim previously registered credential ${cred.id} with ` +
             `rpId=bank.example`);

  const challenge = bank.newChallenge();
  trace.push(`attacker requests a login at ${LEGITIMATE_ORIGIN}, receives ` +
             `challenge ${challenge.slice(0, 12)}...`);
  trace.push(`attacker relays that challenge to the victim on ${ATTACKER_ORIGIN}`);

  // The browser passes the authenticator the origin of the page in the
  // address bar. The attacker cannot change that; it is the one input they do
  // not control.
  const assertion = authenticator.get(cred.id, challenge, ATTACKER_ORIGIN);
  if (!assertion) {
    trace.push('the authenticator REFUSES to sign: the origin does not match ' +
               'the credential\'s rpId');
    return {
      factor: 'WebAuthn', relaySucceeded: false,
      rejectedBecause: 'ORIGIN_MISMATCH',
      decidingField: 'clientDataJSON.origin (authenticator refused to sign)',
      trace,
    };
  }

  trace.push('victim approves; the authenticator signs an assertion');
  trace.push(`attacker relays the assertion to ${LEGITIMATE_ORIGIN}`);
  const failure = bank.verify(assertion);
  trace.push(
    failure === null
      ? `${LEGITIMATE_ORIGIN} ACCEPTS`
      : `${LEGITIMATE_ORIGIN} REJECTS: ${failure}`,
  );

  return {
    factor: 'WebAuthn',
    relaySucceeded: failure === null,
    rejectedBecause: failure,
    decidingField: 'clientDataJSON.origin',
    trace,
  };
}

/**
 * The same ceremony WITHOUT a relay, to prove the WebAuthn path works at all.
 * A control that rejects everything is not phishing-resistant, it is broken.
 */
export function legitimateWebAuthn(): RelayOutcome {
  const authenticator = new VirtualAuthenticator();
  const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
  const cred = authenticator.create('bank.example', LEGITIMATE_ORIGIN)!;
  bank.register(cred.id, authenticator.publicKeyOf(cred.id)!);

  const challenge = bank.newChallenge();
  const assertion = authenticator.get(cred.id, challenge, LEGITIMATE_ORIGIN)!;
  const failure = bank.verify(assertion);

  return {
    factor: 'WebAuthn',
    relaySucceeded: failure === null,
    rejectedBecause: failure,
    decidingField: 'clientDataJSON.origin',
    trace: [`victim is genuinely on ${LEGITIMATE_ORIGIN}`,
            failure === null ? 'ACCEPTED' : `REJECTED: ${failure}`],
  };
}

/** The annotated protocol trace: what the two factors actually commit to. */
export function protocolComparison(): Array<{
  factor: string; commitsTo: string[]; relayable: boolean;
}> {
  return [
    {
      factor: 'TOTP',
      commitsTo: ['shared secret', 'current time step'],
      relayable: true,
    },
    {
      factor: 'WebAuthn',
      commitsTo: ['credential private key', 'server challenge',
                  'rpIdHash', 'clientDataJSON.origin', 'signature counter'],
      relayable: false,
    },
  ];
}
