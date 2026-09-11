import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  ATTACKER_ORIGIN, LEGITIMATE_ORIGIN, VirtualAuthenticator,
  WebAuthnRelyingParty, originMatchesRpId,
} from '../src/lab.ts';
import {
  relayTotp, relayWebAuthn, legitimateWebAuthn, protocolComparison,
} from '../src/relay.ts';

describe('THE COMPARISON: the same relay, two factors', () => {
  test('the relay SUCCEEDS against TOTP', () => {
    // This half is what gives the other half its meaning. A lab where the
    // attack fails against everything proves nothing about WebAuthn.
    const r = relayTotp(58_000_000);
    assert.equal(r.relaySucceeded, true,
      'if the relay cannot beat TOTP, the lab is not modelling the attack');
  });

  test('the relay FAILS against WebAuthn', () => {
    const r = relayWebAuthn();
    assert.equal(r.relaySucceeded, false);
    assert.equal(r.rejectedBecause, 'ORIGIN_MISMATCH');
  });

  test('the deciding field is named', () => {
    const r = relayWebAuthn();
    assert.match(r.decidingField!, /clientDataJSON\.origin/);
  });

  test('WebAuthn still works when there is no relay', () => {
    // Without this, "rejects the relay" is satisfied by a control that
    // rejects everything.
    const r = legitimateWebAuthn();
    assert.equal(r.relaySucceeded, true, r.rejectedBecause ?? '');
    assert.equal(r.rejectedBecause, null);
  });

  test('the traces read as an explanation, not just a verdict', () => {
    assert.ok(relayTotp(58_000_000).trace.some((l) => /carries no information/.test(l)));
    assert.ok(relayWebAuthn().trace.some((l) => /REFUSES to sign|REJECTS/.test(l)));
  });
});

describe('origin binding, checked directly', () => {
  test('an assertion from the attacker origin is rejected by the RP', () => {
    const auth = new VirtualAuthenticator();
    const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    bank.register(cred.id, auth.publicKeyOf(cred.id)!);

    const challenge = bank.newChallenge();
    const good = auth.get(cred.id, challenge, LEGITIMATE_ORIGIN)!;
    // Forge the origin in the signed payload: the signature no longer matches.
    const tampered = {
      ...good,
      clientDataJSON: good.clientDataJSON.replace(
        LEGITIMATE_ORIGIN, ATTACKER_ORIGIN),
    };
    assert.equal(bank.verify(tampered), 'ORIGIN_MISMATCH');
  });

  test('editing the origin after signing breaks the signature too', () => {
    const auth = new VirtualAuthenticator();
    const bank = new WebAuthnRelyingParty('bank.example', ATTACKER_ORIGIN);
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    bank.register(cred.id, auth.publicKeyOf(cred.id)!);
    const challenge = bank.newChallenge();
    const good = auth.get(cred.id, challenge, LEGITIMATE_ORIGIN)!;
    const tampered = {
      ...good,
      clientDataJSON: good.clientDataJSON.replace(
        LEGITIMATE_ORIGIN, ATTACKER_ORIGIN),
    };
    // Origin now matches this (attacker-run) RP, so the next check is reached.
    assert.equal(bank.verify(tampered), 'BAD_SIGNATURE');
  });

  test('a challenge cannot be replayed', () => {
    const auth = new VirtualAuthenticator();
    const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    bank.register(cred.id, auth.publicKeyOf(cred.id)!);
    const challenge = bank.newChallenge();
    const a = auth.get(cred.id, challenge, LEGITIMATE_ORIGIN)!;
    assert.equal(bank.verify(a), null);
    assert.equal(bank.verify(a), 'CHALLENGE_MISMATCH');
  });

  test('a cloned authenticator is detected by the signature counter', () => {
    const auth = new VirtualAuthenticator();
    const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    bank.register(cred.id, auth.publicKeyOf(cred.id)!);

    for (let i = 0; i < 3; i++) {
      const c = bank.newChallenge();
      assert.equal(bank.verify(auth.get(cred.id, c, LEGITIMATE_ORIGIN)!), null);
    }
    auth.rewindCounter(cred.id, 0); // a clone starts from an older count
    const c = bank.newChallenge();
    assert.equal(
      bank.verify(auth.get(cred.id, c, LEGITIMATE_ORIGIN)!),
      'CLONED_AUTHENTICATOR');
  });

  test('an unknown credential is rejected', () => {
    const auth = new VirtualAuthenticator();
    const bank = new WebAuthnRelyingParty('bank.example', LEGITIMATE_ORIGIN);
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    const c = bank.newChallenge();
    assert.equal(bank.verify(auth.get(cred.id, c, LEGITIMATE_ORIGIN)!),
      'UNKNOWN_CREDENTIAL');
  });
});

describe('THE BUG THAT REINTRODUCES PHISHABILITY', () => {
  test('bank.example.evil is NOT a subdomain of bank.example', () => {
    // A naive `host.endsWith(rpId)` check accepts it, and the entire
    // guarantee evaporates. This is a real implementation mistake.
    assert.equal(originMatchesRpId('https://bank.example.evil', 'bank.example'),
      false);
    assert.equal('bank.example.evil'.endsWith('bank.example'), false);
    assert.equal('evilbank.example'.endsWith('bank.example'), true,
      'and this is why a bare endsWith is wrong');
    assert.equal(originMatchesRpId('https://evilbank.example', 'bank.example'),
      false);
  });

  test('a genuine subdomain IS accepted', () => {
    assert.equal(originMatchesRpId('https://login.bank.example', 'bank.example'),
      true);
    assert.equal(originMatchesRpId('https://bank.example', 'bank.example'), true);
  });

  test('http is rejected outright', () => {
    assert.equal(originMatchesRpId('http://bank.example', 'bank.example'), false);
  });

  test('a malformed origin is rejected rather than crashing', () => {
    assert.equal(originMatchesRpId('not a url', 'bank.example'), false);
    assert.equal(originMatchesRpId('', 'bank.example'), false);
  });

  test('the authenticator refuses to sign for a mismatched origin', () => {
    const auth = new VirtualAuthenticator();
    const cred = auth.create('bank.example', LEGITIMATE_ORIGIN)!;
    assert.equal(auth.get(cred.id, 'challenge', ATTACKER_ORIGIN), null,
      'defence in depth: the authenticator declines before the RP ever sees it');
  });

  test('registration from a mismatched origin is refused', () => {
    const auth = new VirtualAuthenticator();
    assert.equal(auth.create('bank.example', ATTACKER_ORIGIN), null);
  });
});

describe('what each factor commits to', () => {
  test('TOTP commits to nothing about location', () => {
    const totp = protocolComparison().find((p) => p.factor === 'TOTP')!;
    assert.ok(!totp.commitsTo.some((f) => /origin|rpId/i.test(f)));
    assert.equal(totp.relayable, true);
  });

  test('WebAuthn commits to the origin and the rpId', () => {
    const wa = protocolComparison().find((p) => p.factor === 'WebAuthn')!;
    assert.ok(wa.commitsTo.some((f) => /origin/.test(f)));
    assert.ok(wa.commitsTo.some((f) => /rpIdHash/.test(f)));
    assert.equal(wa.relayable, false);
  });
});
