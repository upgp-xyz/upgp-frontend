import React from 'react';

const Docs = ({ postUrl, payloadUrl }) => (
  <div className="docs">
    <h2>📘 How to use this app</h2>
    <ul>
      <li>Upload a file (drag-and-drop or file picker)</li>
      <li>The app will detect file type (PGP, SSH, SSL, Cert, etc.)</li>
      <li>Verifies signed payloads using OpenPGP</li>
      <li>Shows SHA-256 checksum and relevant commands</li>
      <li>You can copy or download the inspected result</li>
    </ul>
    <h3>📤 How to encrypt and POST to this server:</h3>
    <pre className="example-snippet">{`
# Encrypt and sign a JSON payload to post to the server:

cat payload.json | \\
  gpg --armor --sign --default-key YOUR_KEY_ID > signed.asc

curl -X POST \\
  -F "file=@signed.asc" \\
  ${postUrl}
    `}</pre>
    <h3>🧪 JSON Payload Example:</h3>
    <pre className="example-snippet">{`
{
  "payload": {
    "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
    "url": "${payloadUrl}",
    "timestamp": "2025-04-12T00:00:00Z"
  },
  "signature": "-----BEGIN PGP SIGNATURE-----..."
}
    `}</pre>
  </div>
);

export default Docs;
