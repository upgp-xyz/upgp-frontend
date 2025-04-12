# 🔐 upgp

**upgp** is a public, open-source gateway for securely uploading and delivering encrypted files using PGP.  
Designed to be minimal, powerful, and privacy-respecting.

> 🔗 **Try it live at [upgp.xyz](https://upgp.xyz)**

---

## ✨ Features

- 🧠 Smart file detection (SSL keys, PGP files, generic uploads)
- 🔐 Optional client-side encryption with PGP
- 📄 Drag-and-drop or direct upload interface
- 🪪 Register your public key to get a personal endpoint (e.g., `upgp.xyz/bill`)
- 🚀 Forward encrypted data to your server via webhook (only if verified)
- ✅ All uploads are signed, and server-side metadata is PGP-verified
- 🔀 SHA-256 checksums provided for raw and encrypted uploads
- ✍️ Signed response returned from server to confirm upload and identity
- ⚖️ Clear distinction between public and server-key behavior
- 🧪 Fully open source and self-hostable frontend

---

## 🍆 Example Use

Bill wants others to securely send him files. He:

1. Registers his PGP public key with `upgp`
2. Gets a public drop zone at `upgp.xyz/bill`
3. Sends that link to anyone
4. Files are encrypted with his key
5. Payloads are signed and routed to his webhook if configured

---

## 🛠 Getting Started

To run the frontend locally:

```bash
cd frontend
npm install
npm run dev
```

Then open your browser to: [http://localhost:5173](http://localhost:5173)

---

### 📤 Upload Flow

1. Drag and drop or select a file
2. The app detects file type:
   - 🔒 SSL Private Key → payload will be encrypted before POST
   - 📄 PGP Message → payload assumed encrypted
   - 🛡️ Generic file → sent over HTTPS
3. SHA-256 checksum shown for:
   - Raw file
   - Encrypted output (with GPG one-liner shown)
4. File is encrypted for the selected user's public key
5. Payload is PGP signed and sent to their `/upload` route
6. If encrypted for the server, the message must be signed and will be verified
7. Server confirms and responds with a signed receipt

---

### ⚖️ Current API Routes

| Route                | Method | Description                                 |
|---------------------|--------|---------------------------------------------|
| `/register`         | GET    | Returns a page with public server key       |
| `/register/upload`  | POST   | Accepts a signed+encrypted PGP public key   |
| `/:id`              | GET    | Personalized drop zone page for `id`        |
| `/:id/upload`       | POST   | Accepts signed+encrypted payloads           |
| `/:id/json`         | GET    | JSON representation of `id`'s public config |
| `/:id/key`          | GET    | Returns public key of recipient             |

---

## 📃 Project Structure

```
/frontend       → Vite + React frontend for file upload and encryption
/gateway.mjs    → Private backend (Node.js + Express + Firestore)
```

---

## 🌪️ Changelog

### 1.0.0 — Initial Public Release
- Fully functional PGP frontend with support for:
  - Registration of public keys
  - Upload with file detection
  - Signature verification
  - JSON signed metadata
  - Custom routing via encrypted payloads
- Server validates metadata with server-signed `data`
- Client decrypts signed message for confirmation
- Public repo split from private gateway backend

---

## 🌮 Try It Live

Want to test it out?

**→ [Register your public key here](https://upgp.xyz/register)**  
Once registered, you’ll receive a personalized upload URL like `https://upgp.xyz/yourname`.

You can also register manually via terminal:

```bash
# Download the server's public key
curl https://upgp.xyz/key -o upgp.asc

# Export your own public key
gpg --armor --export you@example.com > pubkey.asc

# Encrypt your key using upgp's public key
gpg --encrypt --armor --recipient-file upgp.asc pubkey.asc > encrypted.asc

# Upload the encrypted key
curl -X POST https://upgp.xyz/register/upload \
  -H "Content-Type: application/json" \
  -d '{"content":"'"$(cat encrypted.asc | sed ':a;N;$!ba;s/\n/\\n/g')"'}'
```

---

## 🧑‍💻 Contributing

Want to help build secure tools for the internet? PRs and issues welcome!

---

## 🔓 License

MIT — free for personal, academic, or commercial use.

---

## 🌍 Live Project

- Website: [https://upgp.xyz](https://upgp.xyz)
- GitHub: [https://github.com/upgp-xyz/upgp-frontend](https://github.com/upgp-xyz/upgp-frontend)