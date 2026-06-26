// server.js
//
// A real, working FIDO2 / WebAuthn relying party (RP) server.
// It uses your OS's built-in "platform authenticator" (Windows Hello,
// Touch ID, Android biometrics) and requires "user verification" on every
// registration and login - which is what makes your device prompt for a
// PIN or biometric instead of just detecting the device's presence.
//
// Storage here is in-memory (a plain JS object) purely for demo purposes.
// Restarting the server wipes all registered users. Swap `db` below for a
// real database (Postgres, SQLite, etc.) in any real deployment.

import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Relying Party (RP) identity
// ---------------------------------------------------------------------------
// rpID must be the domain the site is served from (no scheme, no port).
// "localhost" is treated as a secure context by every browser, so this
// works over plain http:// for local testing. The moment you deploy this
// anywhere else, rpID becomes your real domain (e.g. "example.com") and the
// site MUST be served over HTTPS - WebAuthn refuses to run otherwise.
const PORT = 3000;
const rpName = 'FIDO2 PIN Demo';
const rpID = 'localhost';
const origin = `http://${rpID}:${PORT}`;

// ---------------------------------------------------------------------------
// "Database" - in-memory for this demo
// ---------------------------------------------------------------------------
// users: username -> { id: Buffer, username, credentials: WebAuthnCredential[] }
// WebAuthnCredential = { id, publicKey, counter, transports }
const users = new Map();

// challenges: username -> the random challenge string we most recently sent,
// so we can confirm the signed response actually matches what we asked for.
const challenges = new Map();

function getOrCreateUser(username) {
  if (!users.has(username)) {
    users.set(username, {
      id: crypto.randomBytes(32), // stable random handle, never reused across users
      username,
      credentials: [],
    });
  }
  return users.get(username);
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// 1) REGISTRATION - step 1: server hands the browser a challenge
// ---------------------------------------------------------------------------
app.get('/register/options', async (req, res) => {
  const username = String(req.query.username || '').trim();
  if (!username) return res.status(400).json({ error: 'username is required' });

  const user = getOrCreateUser(username);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.username,
    userID: user.id,
    attestationType: 'none', // we don't need to verify *which brand* of authenticator was used
    // Don't let someone register the same authenticator twice for this user
    excludeCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      transports: cred.transports,
    })),
    authenticatorSelection: {
      // 'platform' forces use of the device's BUILT-IN authenticator
      // (Windows Hello, Touch ID, Android fingerprint) rather than an
      // external USB/NFC security key.
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      // THIS is the setting that forces a PIN/biometric prompt rather than
      // just "is a human touching the device".
      userVerification: 'required',
    },
  });

  // Remember the challenge so /register/verify can check the signed
  // response actually answers THIS challenge, not a replayed old one.
  challenges.set(username, options.challenge);

  res.json(options);
});

// ---------------------------------------------------------------------------
// 2) REGISTRATION - step 2: verify what the authenticator signed back
// ---------------------------------------------------------------------------
app.post('/register/verify', async (req, res) => {
  const { username, attestationResponse } = req.body;
  const user = users.get(username);
  const expectedChallenge = challenges.get(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ verified: false, error: 'No registration in progress for this user' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true, // reject the result if the device skipped PIN/biometric
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ verified: false, error: 'Could not verify registration' });
    }

    // This is the only thing we ever store: a PUBLIC key. The matching
    // private key never left the user's device and never will.
    user.credentials.push(verification.registrationInfo.credential);
    challenges.delete(username);

    res.json({ verified: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 3) LOGIN - step 1: server hands the browser a fresh challenge
// ---------------------------------------------------------------------------
app.get('/login/options', async (req, res) => {
  const username = String(req.query.username || '').trim();
  const user = users.get(username);

  if (!user || user.credentials.length === 0) {
    return res.status(404).json({ error: 'No registered credentials for this user' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    // Only the authenticators this user already registered are allowed in
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      transports: cred.transports,
    })),
    userVerification: 'required', // again: force PIN/biometric, not just presence
  });

  challenges.set(username, options.challenge);
  res.json(options);
});

// ---------------------------------------------------------------------------
// 4) LOGIN - step 2: verify the signature against the stored public key
// ---------------------------------------------------------------------------
app.post('/login/verify', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const user = users.get(username);
  const expectedChallenge = challenges.get(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ verified: false, error: 'No login in progress for this user' });
  }

  const credential = user.credentials.find((c) => c.id === assertionResponse.id);
  if (!credential) {
    return res.status(400).json({ verified: false, error: 'Unknown credential' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential,
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(400).json({ verified: false, error: 'Signature did not verify' });
    }

    // Anti-cloning check: the authenticator's usage counter must always
    // move forward. If it didn't, this credential may have been cloned.
    credential.counter = verification.authenticationInfo.newCounter;
    challenges.delete(username);

    res.json({ verified: true, username });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`FIDO2 PIN demo running at ${origin}`);
});
