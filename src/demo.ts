/**
 * The 60-second artefact: the same relay, side by side. Run: `npm run demo`
 */
import { relayTotp, relayWebAuthn, legitimateWebAuthn, protocolComparison }
  from './relay.ts';

console.log('\n  ORIGINBOUND - why "we have MFA" is not the same as ' +
            'phishing-resistant');
console.log('  ' + '='.repeat(70));
console.log('  Sealed lab: a virtual authenticator and two in-process relying');
console.log('  parties. The "relay" passes values between objects in this');
console.log('  program. Nothing here reaches any network.\n');

const totp = relayTotp(58_000_000);
console.log('  ATTACK 1 - relay a TOTP code');
console.log('  ' + '-'.repeat(70));
for (const line of totp.trace) console.log(`    ${line}`);
console.log(`\n    RESULT: relay ${totp.relaySucceeded ? 'SUCCEEDED' : 'failed'}` +
            ' - the attacker is now logged in as the victim.\n');

const wa = relayWebAuthn();
console.log('  ATTACK 2 - the identical relay, against WebAuthn');
console.log('  ' + '-'.repeat(70));
for (const line of wa.trace) console.log(`    ${line}`);
console.log(`\n    RESULT: relay ${wa.relaySucceeded ? 'SUCCEEDED' : 'FAILED'}` +
            ` (${wa.rejectedBecause})`);
console.log(`    deciding field: ${wa.decidingField}\n`);

const ok = legitimateWebAuthn();
console.log('  CONTROL - the same WebAuthn ceremony with no relay');
console.log('  ' + '-'.repeat(70));
for (const line of ok.trace) console.log(`    ${line}`);
console.log(`    RESULT: ${ok.relaySucceeded ? 'ACCEPTED' : 'rejected'}` +
            ' - the control is not simply refusing everything.\n');

console.log('  WHAT EACH FACTOR SIGNS');
console.log('  ' + '-'.repeat(70));
for (const p of protocolComparison()) {
  console.log(`    ${p.factor}`);
  for (const f of p.commitsTo) console.log(`      - ${f}`);
  console.log(`      relayable: ${p.relayable ? 'YES' : 'no'}\n`);
}

console.log('  A TOTP code is a function of (secret, time). It is valid');
console.log('  wherever it is presented, so a real-time relay is enough.');
console.log('  A WebAuthn assertion signs the origin the BROWSER was on -');
console.log('  the one input the attacker cannot control.\n');
