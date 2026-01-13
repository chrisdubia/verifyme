Verify Me - Trust Layer MVP (Media Authenticity)

What this is
- A small Next.js app that lets you:
  1) create an identity (passkey if supported, or dev login)
  2) enroll a device signing key (ECDSA P-256)
  3) sign a photo or video by hashing it and signing the hash
  4) verify that media later by checking hash match + signature validity
  5) preview deploy test

Important limitations (v1)
- This proves integrity since signing and who signed it.
- It does NOT prove the photo or video is “real camera capture” or that it was not edited before signing.
  (That requires deeper capture provenance / attestation standards like C2PA.)

Local setup (macOS)
1) Install Node 18 (recommended for macOS 10.15):
   - easiest: nvm (or use the Node 18 installer)

2) In this folder:
   - copy .env.example to .env
   - set a JWT_SECRET

3) Install dependencies:
   npm install

4) Initialize the SQLite database:
   npx prisma migrate dev --name init

5) Run:
   npm run dev

Then open:
http://localhost:3000

Passkeys on older Macs
- If passkeys fail on macOS 10.15, click "Dev login (if passkeys fail)" to test everything else.

Deploy
- Deploy to Vercel for a public https URL.  WebAuthn works best on https.
