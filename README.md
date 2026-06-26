# FIDO2 Passwordless Authentication Demo

This repository contains a small Node.js and Express demo that implements a real WebAuthn/FIDO2 passwordless sign-in flow. It uses your device's built-in authenticator, such as Windows Hello, Touch ID, or Android biometrics, and requires user verification so registration and login prompt for a PIN or biometric.

## Features

- Real WebAuthn registration and login flow
- Platform authenticator enforcement
- Required user verification for PIN/biometric prompts
- Simple browser-based demo UI

## Prerequisites

- Node.js 18 or newer
- A browser and device that support WebAuthn platform authenticators
- For local testing, use localhost, which browsers treat as a secure context

## Installation

```bash
npm install
```

## Run the app

```bash
npm start
```

Then open http://localhost:3000 in your browser.

## How it works

1. Enter a username and register a new device.
2. Your operating system prompts for a PIN or biometric.
3. The browser creates a WebAuthn credential backed by your device's secure hardware.
4. On the next login, the server verifies the signature using the stored public key.

## Project structure

- server.js – Express server and WebAuthn endpoints
- public/ – frontend HTML, CSS, and JavaScript
- package.json – app metadata and dependencies

## Notes

- This demo stores users and credentials in memory, so restarting the server clears all registrations.
- For production use, replace the in-memory store with a real database and serve the app over HTTPS with a real domain.

## License

This project is licensed under the MIT License.
