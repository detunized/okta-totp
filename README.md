# Okta TOTP

Registers a new Okta Verify device from the enrollment QR code and shows the TOTP secret, so Okta codes can live in 1Password or any other authenticator app instead of Okta Verify.

**https://okta-totp.detunized.workers.dev/**

## How it works

- Paste the QR code image or the `oktaverify://` URL from the Okta enrollment page
- The Worker sends the same device registration request the Okta Verify Android app sends, asking for the TOTP method only
- Okta responds with the shared secret, which you copy into your authenticator app

The Worker forwards the request to your Okta server and stores nothing.

## Development

```
npm install
npm run dev
npm run deploy
```
