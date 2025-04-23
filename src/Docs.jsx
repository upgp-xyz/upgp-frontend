import React from 'react';

const Docs = ({ postUrl, payloadUrl }) => (
  <div className="docs">
    <h2>📘 How to use this app</h2>
    <ul>
      <li>Upload a file (drag-and-drop or file picker)</li>
      <li>Verifies signed payloads using OpenPGP</li>
      <li>Shows SHA-256 checksum and relevant commands</li>
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
{"url":"https://example.com/encrypted"}
`}</pre>
    <h3>🔏 Signed Message Example:</h3>
    <pre className="example-snippet">{`
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

{"url":"https://example.com/encrypted"}
-----BEGIN PGP SIGNATURE-----

iQFDBAEBCgAtFiEEIZOTPInGbbtOLmbMo1/eVgbTFhMFAmf5xLYPHHRlc3QyQHVw
...
=ymWB
-----END PGP SIGNATURE-----
    `}</pre>
  </div>
);

export default Docs;
