import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [publicKey, setPublicKey] = useState(null);
  const [checksum, setChecksum] = useState(null);
  const [showDetails, setShowDetails] = useState(false);
  const [showDocs, setShowDocs] = useState(false);
  const [commandSnippets, setCommandSnippets] = useState(null);
  const [successNotification, setSuccessNotification] = useState('');
  
  const ORIGIN = window.location.origin.replace(/\/$/, '');
  const PATHNAME = window.location.pathname.replace(/^\/|\/$/g, '');
  const CURRENT_PATH = PATHNAME ? `/${PATHNAME}` : '';
  const DEFAULT_UPLOAD_URL = `${ORIGIN}${CURRENT_PATH}/upload`;
  const FULL_URL = `${ORIGIN}${CURRENT_PATH}`.replace(/^https?:\/\//, '').replace(/^www\./, '');

  const isSSLPrivateKey = (text) => (
    text.includes('-----BEGIN PRIVATE KEY-----') ||
    text.includes('-----BEGIN RSA PRIVATE KEY-----') ||
    text.includes('-----BEGIN EC PRIVATE KEY-----')
  );

  const isPGPFile = (text) => (
    text.includes('-----BEGIN PGP MESSAGE-----') ||
    text.includes('-----BEGIN PGP SIGNED MESSAGE-----') ||
    text.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----') ||
    text.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')
  );

  const verifyPayloadSignature = async (signedPayload) => {
    try {
      const openpgp = await import('openpgp');
      const { payload, signature } = signedPayload;

      const publicKey = await openpgp.readKey({ armoredKey: payload.data });
      const cleartext = await openpgp.readCleartextMessage({ cleartextMessage: signature });

      const verificationResult = await openpgp.verify({
        message: cleartext,
        verificationKeys: publicKey,
      });

      const { verified } = verificationResult.signatures[0];
      await verified; // Throws if invalid

      const parsed = JSON.parse(cleartext.getText());
      if (JSON.stringify(payload) !== JSON.stringify(parsed)) {
        throw new Error('Payload mismatch after verification.');
      }

      return true;
    } catch (error) {
      console.warn('⚠️ Client-side payload signature verification failed:', error);
      return false;
    }
  };

  const analyzeFile = async (file) => {
    const text = await file.text();
    const buffer = await file.arrayBuffer();

    const rawHashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const rawHashArray = Array.from(new Uint8Array(rawHashBuffer));
    const rawChecksum = rawHashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    setChecksum(rawChecksum);

    let detectedType = 'generic';
    if (isSSLPrivateKey(text)) detectedType = 'privateKey';
    else if (isPGPFile(text)) detectedType = 'pgp';

    setMessage('🛡️ Payload will be encrypted before POST.');
    setSelectedFile(file);

    if (window.__UPGP_DATA__?.payload?.data) {
      const openpgp = await import('openpgp');
      const publicKey = await openpgp.readKey({ armoredKey: window.__UPGP_DATA__.payload.data });
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text }),
        encryptionKeys: publicKey,
      });

      const encryptedBuffer = new TextEncoder().encode(encrypted);
      const encryptedHashBuffer = await crypto.subtle.digest('SHA-256', encryptedBuffer);
      const encryptedHashArray = Array.from(new Uint8Array(encryptedHashBuffer));
      const encryptedChecksum = encryptedHashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

      setChecksum((prev) => ({ raw: rawChecksum, encrypted: encryptedChecksum }));

      const filename = file.name || 'file.txt';
      setCommandSnippets({
        raw: `cat ${filename} | sha256sum`,
        encrypted: `gpg --encrypt --armor --recipient-file upgp.asc ${filename} > encrypted.asc && sha256sum encrypted.asc`,
        upload: `curl -X POST https://upgp.xyz/register/upload \\\n  -H "Content-Type: application/json" \\\n  -d '{"content":"'"$(cat encrypted.asc | sed ':a;N;$!ba;s/\n/\\n/g')"'}'`
      });
    }
  };

  const submitFile = async () => {
    if (!selectedFile) return;
  
    try {
      let keyData = window.__UPGP_DATA__ || {};
      if (!keyData.data) {
        const keyRes = await fetch(`${ORIGIN}${CURRENT_PATH}/json`);
        const keyText = await keyRes.text();
        try {
          keyData = JSON.parse(keyText);
        } catch {
          keyData = { data: keyText.trim() };
        }
      }
  
      const publicKeyArmored = keyData.data;
      const uploadUrl = keyData.url || DEFAULT_UPLOAD_URL;
  
      const openpgp = await import('openpgp');
      const fileText = await selectedFile.text();
  
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: fileText }),
        encryptionKeys: await openpgp.readKey({ armoredKey: publicKeyArmored }),
      });
  
      const res = await fetch(uploadUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: encrypted }),
      });
  
      const responseText = await res.text();
  
      try {
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  
        let signed = responseText;
        try {
          const maybeJSON = JSON.parse(responseText);
          if (maybeJSON?.signed) signed = maybeJSON.signed;
        } catch {}
        
        const cleartextMessage = await openpgp.readCleartextMessage({
          cleartextMessage: signed,
        });
  
        const verified = await openpgp.verify({
          message: cleartextMessage,
          verificationKeys: publicKey,
        });
  
        const { verified: verificationResult } = verified.signatures[0];
        await verificationResult;
  
        const signedText = cleartextMessage.getText();
        setSelectedFile(null);
        
        let displayHTML = '';
        let fullLink = null;
        
        try {
          const parsed = JSON.parse(signedText);
        
          if (parsed.message) {
            displayHTML += `<strong>${parsed.message}</strong><br><br>`;
          }

          if (parsed.id) {
            displayHTML += `ID: ${parsed.id}<br>`;
            displayHTML += `Root: ${window.location.origin}${parsed.root}<br>`;
            displayHTML += `Upload: ${window.location.origin}${parsed.upload}<br>`;
            displayHTML += `Key: ${window.location.origin}${parsed.key}<br>`;
            displayHTML += `JSON: ${window.location.origin}${parsed.json}<br>`;
            fullLink = `${window.location.origin}${parsed.root}`;
          }
        } catch (err) {
          console.warn('Failed to parse signed JSON response:', err);
          displayHTML = signedText.replace(/\n/g, '<br>').replace(/  /g, '&nbsp;&nbsp;');
        }
        
        setSuccessNotification(
          `${displayHTML}<br><br>✅ Your public key has been stored and verified.<br><br>${
            fullLink ? `👉 <a href="${fullLink}" target="_blank">${fullLink}</a>` : ''
          }`
        );
      } catch (e) {
        if (responseText.includes('-----BEGIN PGP SIGNED MESSAGE-----')) {
          setSuccessNotification('❓ Unknown: Cleartext PGP message received but could not verify signature.');
        } else {
          setSuccessNotification('❌ Negative: No valid signature or verification failed.');
        }
      }
    } catch (err) {
      console.error('Error during submit:', err);
      setSuccessNotification('❌ An error occurred while uploading.');
    }
  };
  
  useEffect(() => {
    (async () => {
      try {
        const keyData = window.__UPGP_DATA__ || {};
        const verified = await verifyPayloadSignature(keyData);
        if (verified && keyData.payload?.data) {
          setPublicKey(keyData.payload.data.trim());
        } else {
          console.warn('⛔ Invalid or unverifiable payload.');
        }
      } catch (err) {
        console.warn('Could not verify injected key:', err);
      }
    })();
  }, []);

  const handleFileChange = async (event) => {
    const file = event.target.files[0];
    if (file) await analyzeFile(file);
  };

  useEffect(() => {
    let dragCounter = 0;
    const handleDragEnter = (e) => { e.preventDefault(); dragCounter++; setIsDragging(true); };
    const handleDragLeave = (e) => { e.preventDefault(); dragCounter--; if (dragCounter === 0) setIsDragging(false); };
    const handleDragOver = (e) => e.preventDefault();
    const handleDrop = (e) => {
      e.preventDefault(); setIsDragging(false); dragCounter = 0;
      const file = e.dataTransfer.files[0];
      if (file) analyzeFile(file);
    };
    window.addEventListener('dragenter', handleDragEnter);
    window.addEventListener('dragleave', handleDragLeave);
    window.addEventListener('dragover', handleDragOver);
    window.addEventListener('drop', handleDrop);
    return () => {
      window.removeEventListener('dragenter', handleDragEnter);
      window.removeEventListener('dragleave', handleDragLeave);
      window.removeEventListener('dragover', handleDragOver);
      window.removeEventListener('drop', handleDrop);
    };
  }, []);

  const renderDocs = () => (
    <div className="docs-section">
      <p>Use the endpoints below to programmatically register and upload encrypted payloads:</p>
      <pre className="code-block">{`GET https://${FULL_URL}/key
GET https://${FULL_URL}/json
POST https://${FULL_URL}/upload`}</pre>
  
      <h3>🔐 Example: Encrypt and Upload</h3>
      <pre className="code-block">{`curl -s https://${FULL_URL}/key > pub.asc && \\
echo '{"url":"https://example.com/callback"}' | \\
gpg --encrypt --armor --recipient-file pub.asc | \\
curl -X POST -H "Content-Type: application/json" --data @- https://${FULL_URL}/upload`}</pre>
  
      <h3>📥 Payload Example</h3>
      <pre className="code-block">{`-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

{"url":"https://example.com/upload-callback"}
-----BEGIN PGP SIGNATURE-----

iQFDBAEBCgAtFiEEIZOTPInGbbtOLmbMo1/eVgbTFhMFAmf5xLYPHHRlc3QyQHVw
...
BowIRrdJLbtit+OHsyCPENM1WWoXk3qT/+DlZnb2jmHdkm+JDUY=
=ymWB
-----END PGP SIGNATURE-----
`}</pre>
    </div>
  );  

  return (   
    <div className={`upload-form ${isDragging ? 'dragging' : ''}`}>
      {successNotification && (
        <div className="success-banner">
          <div
            className="success-notification"
            dangerouslySetInnerHTML={{ __html: successNotification }}
          />
          <button onClick={() => setSuccessNotification('')} className="dismiss-btn">✖</button>
        </div>
      )}
      {!isDragging && (
        <>
          <h1>{FULL_URL}</h1>
          <>
            <p>Select or drop a file to begin</p>
            <div className="file-input-wrapper">
              <input
                type="file"
                id="file-upload"
                accept=".pem,.crt,.cer,.asc,.txt"
                onChange={handleFileChange}
              />
              {selectedFile && (
                <div className="file-name">📄 Selected: {selectedFile.name}</div>
              )}
            </div>

            {message && <div className="status-message">{message}</div>}

            {selectedFile && !message.includes('✅ Encryption and Upload successful') && (
              <div className="disclaimer">
                ⚠️ <strong>Review before submitting.</strong> Click the{' '}
                <span className="submit-hint">green button</span> to send.
              </div>
            )}

            {selectedFile && (
              <button className="submit-button" onClick={submitFile}>
                ✅ Submit File
              </button>
            )}

            {selectedFile && (
              <button className="details-toggle" onClick={() => setShowDetails(!showDetails)}>
                {showDetails ? '🔽 Hide Encryption Info' : '🔍 Show Encryption Info'}
              </button>
            )}

            {/* 🔽 Break into new line */}
            <div className="api-docs-wrapper">
              <button
                className="api-docs-button"
                onClick={() => setShowDocs(!showDocs)}
                style={{ marginTop: '1rem' }}
              >
                {showDocs ? '🔽 Hide API Documentation' : '📘 View API Documentation'}
              </button>
            </div>
          </>
          {showDocs && renderDocs()}
          {showDetails && (
            <div className="encryption-details">
              {publicKey && (<div className="info-block"><div className="label">📬 Public Key</div><pre className="code-block">{publicKey}</pre></div>)}
              {checksum && typeof checksum === 'object' && (
                <>
                  <div className="info-block">
                    <div className="label">📦 SHA-256 of File</div>
                    <pre className="code-inline">{checksum.raw}</pre>
                  </div>
                  <div className="info-block">
                    <div className="label">🔐 SHA-256 of Encrypted Output</div>
                    <pre className="code-inline">{checksum.encrypted}</pre>
                  </div>
                  <div className="info-block">
                    <div className="label">🔍 Verify Raw File Locally</div>
                    <pre className="code-block">{commandSnippets.raw}</pre>
                  </div>
                  <div className="info-block">
                    <div className="label">🔐 Encrypt & Verify</div>
                    <pre className="code-block">{commandSnippets.encrypted}</pre>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}
      {isDragging && <div className="drag-overlay">📄 Drop file to upload</div>}
    </div>
  );
}

export default App;
