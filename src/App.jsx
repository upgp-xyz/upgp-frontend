import React, { useState, useEffect, Suspense, lazy } from 'react';
import './App.css';
import { verifyPayloadSignature } from './utils/pgpVerify';
import { HeaderWithAnimatedXYZ } from './HeaderWithAnimatedXYZ';
import { SERVER_PUBLIC_KEY } from './config.js';
import { verifySignedMessageWithDriftCheck } from './utils/verifySignedMessage';

const Docs = lazy(() => import('./Docs'));

function App() {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [successNotification, setSuccessNotification] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [message, setMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileTag, setFileTag] = useState(null);
  const [showDocs, setShowDocs] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [showResponse, setShowResponse] = useState(false);
  const [checksum, setChecksum] = useState(null);
  const [commandSnippets, setCommandSnippets] = useState(null);
  const [upgpDATA, setupgpDATA] = useState('');
  const [publicKey, setPublicKey] = useState('');

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

  const isX509Cert = (text) => (
    text.includes('-----BEGIN CERTIFICATE-----') ||
    text.includes('-----BEGIN X509 CERTIFICATE-----')
  );
  
  const isSSHKey = (text) => (
    text.startsWith('ssh-rsa ') ||
    text.startsWith('ssh-ed25519 ') ||
    text.startsWith('ecdsa-sha2-nistp') ||
    text.includes('-----BEGIN OPENSSH PRIVATE KEY-----')
  );
  
  const isJWT = (text) => (
    /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(text.trim())
  );
  
  const isBase64Encoded = (text) => {
    const trimmed = text.trim().replace(/\s+/g, '');
    return /^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length % 4 === 0;
  };
  
  const isPEMFormat = (text) => (
    text.includes('-----BEGIN ') && text.includes('-----END ')
  );
  
  
  useEffect(() => {
    (async () => {
      try {
        const keyData = window.__UPGP_DATA__ || {};
        const verified = await verifyPayloadSignature(keyData, (result) => {
          setupgpDATA(result);
          if (result?.publicKey) {
            setPublicKey(result.publicKey);
          }
        });
  
        if (!verified) {
          console.warn('⛔ Invalid or unverifiable payload.');
        }
      } catch (err) {
        console.warn('Could not verify injected key:', err);
      }
    })();
  }, []);

  const analyzeFile = async (file) => {
    try {
      const text = await file.text();
      const buffer = await file.arrayBuffer();
  
      const rawHashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const rawHashArray = Array.from(new Uint8Array(rawHashBuffer));
      const rawChecksum = rawHashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      setChecksum(rawChecksum);
  
      if (typeof text === 'string') {
        if (isSSLPrivateKey(text)) {
          setCommandSnippets(`# SSL PRIVATE KEY\nopenssl rsa -in your.key -check`);
          setFileTag('SSL Key');
        } else if (isPGPFile(text)) {
          setCommandSnippets(`# PGP FILE\ngpg --verify file.asc`);
          setFileTag('PGP File');
        } else if (isX509Cert(text)) {
          setCommandSnippets(`# X.509 CERTIFICATE\nopenssl x509 -in cert.crt -text -noout`);
          setFileTag('X.509 Cert');
        } else if (isSSHKey(text)) {
          setCommandSnippets(`# SSH PUBLIC KEY\nssh-keygen -lf yourkey.pub`);
          setFileTag('SSH Key');
        } else if (isJWT(text)) {
          setCommandSnippets(`# JWT Token\njwt decode <your-token-here>`);
          setFileTag('JWT');
        } else if (isBase64Encoded(text)) {
          setCommandSnippets(`# Base64 Encoded Content\nbase64 -d yourfile > decoded.out`);
          setFileTag('Base64');
        } else if (isPEMFormat(text)) {
          setCommandSnippets(`# Generic PEM File\nopenssl asn1parse -in yourfile.pem`);
          setFileTag('PEM Format');
        } else {
          setCommandSnippets(`# Unknown file type\nfile your-upload`);
          setFileTag('Unknown');
        }
      }
  
      setMessage('🛡️ Payload will be encrypted before POST.');
      setSelectedFile(file);
  
      if (upgpDATA?.payload?.data) {
        const openpgp = await import('openpgp');
        const publicKey = await openpgp.readKey({ armoredKey: upgpDATA.payload.data });
  
        const encrypted = await openpgp.encrypt({
          message: await openpgp.createMessage({ text: typeof text === 'string' ? text : '' }),
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
    } catch (error) {
      console.error('Error analyzing file:', error);
      setMessage('❌ Failed to analyze the file.');
    }
  };  

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

  const handleUpload = async () => {
    if (!selectedFile || !publicKey) return;
    setUploading(true);
  
    try {
      const openpgp = await import('openpgp');
      const fileText = await selectedFile.text();
  
      let uploadUrl = DEFAULT_UPLOAD_URL;
  
      // ✅ NEW: Parse and verify upload config from signed server payload
      const signed = window.__UPGP_DATA__?.signature;
      if (signed) {
        try {
          const message = await verifySignedMessageWithDriftCheck({
            openpgp,
            signed,
            serverPublicKeyArmored: SERVER_PUBLIC_KEY,
          });
      
          const configPayload = JSON.parse(message.getText());
          if (configPayload?.config?.startsWith('http')) {
            uploadUrl = configPayload.config;
          }
        } catch (e) {
          console.warn('⚠️ Failed to verify upload config. Falling back to default.', e);
        }
      }
  
      const encryptionKeys = await openpgp.readKey({ armoredKey: publicKey });
  
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: fileText }),
        encryptionKeys,
      });
  
      const res = await fetch(uploadUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: encrypted }),
      });
  
      const responseText = await res.text();
      setMessage(responseText);
  
      // Handle signed response
      try {
        const parsedText = JSON.parse(responseText);
      
        const message = await verifySignedMessageWithDriftCheck({
          openpgp,
          signed: parsedText.signed,
          serverPublicKeyArmored: SERVER_PUBLIC_KEY,
        });
      
        const signedText = message.getText();
        setFiles([]);
      
        let displayHTML = '';
        let fullLink = null;
      
        try {
          const parsed = JSON.parse(signedText);
      
          if (parsed.message) {
            displayHTML += `<strong>${parsed.message}</strong><br><br>`;
          }
      
          if (parsed.id && !parsed.signed) {
            fullLink = `${window.location.origin}${parsed.root}`;
            displayHTML += `ID: ${parsed.id}<br>`;
            displayHTML += `Upload: ${window.location.origin}${parsed.upload}<br>`;
            displayHTML += `Key: ${window.location.origin}${parsed.key}<br>`;
            displayHTML += `👉 <a href="${fullLink}" target="_blank">${fullLink}</a><br>`;
            displayHTML += `Continue to your private registration page to complete setup.<br>`;
            displayHTML += `This page is just for you — it records your encrypted information.<br>`;
            displayHTML += `📌 Save this URL and remember your ID! You’ll need it to return.<br>`;
          }
        } catch {
          displayHTML = signedText.replace(/\n/g, '<br>').replace(/  /g, '&nbsp;&nbsp;');
        }
      
        setSuccessNotification(displayHTML);
      } catch (err) {
        if (responseText.includes('-----BEGIN PGP SIGNED MESSAGE-----')) {
          setSuccessNotification('❓ Unknown: Cleartext PGP message received but could not verify signature.');
        } else {
          setSuccessNotification('❌ Negative: No valid signature or verification failed.');
        }
      }      
    } catch (err) {
      console.error('Error during submit:', err);
      setSuccessNotification('❌ An error occurred while uploading.');
    } finally {
      setUploading(false);
    }
  };  

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const downloadText = (filename, text) => {
    const blob = new Blob([text], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
  };

  const getTagIcon = (tag) => {
    switch (tag) {
      case 'PGP File': return '🔐';
      case 'SSL Key': return '🔑';
      case 'X.509 Cert': return '📜';
      case 'SSH Key': return '🧷';
      case 'JWT': return '🧾';
      case 'Base64': return '📦';
      case 'PEM Format': return '🗂️';
      case 'Unknown': return '❓';
      default: return '📄';
    }
  };  

  const syntaxHighlightJSON = (json) => {
    if (typeof json !== 'string') {
      json = JSON.stringify(json, null, 2);
    }
  
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(true|false|null)\b|\b\d+\.?\d*\b)/g, (match) => {
      let cls = 'number';
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'key' : 'string';
      } else if (/true|false/.test(match)) {
        cls = 'boolean';
      } else if (/null/.test(match)) {
        cls = 'null';
      }
      return `<span class="json-${cls}">${match}</span>`;
    });
  };

  return (
    <div className={`upload-form ${isDragging ? 'dragging' : ''}`}>
      {!isDragging && (
        <>
          <HeaderWithAnimatedXYZ fullUrl={FULL_URL} />
  
          {successNotification && (
            <div className="success-banner">
              {/* Top-left "View Server Response" button */}
              <button
                className="info-btn"
                onClick={() => setShowResponse((prev) => !prev)}
              >
                ℹ View Server Response
              </button>

              {/* Success message content */}
              <div
                className="success-notification"
                dangerouslySetInnerHTML={{ __html: successNotification }}
              />

              {/* Top-right dismiss button */}
              <button
                onClick={() => setSuccessNotification('')}
                className="dismiss-btn"
              >
                ✖
              </button>
            </div>
          )}

          {showResponse && message && (
            <pre className="output">
              <code dangerouslySetInnerHTML={{ __html: syntaxHighlightJSON(message) }} />
            </pre>
          )}
  
          <section className="upload-box">
            <p>Select or drop a file to begin</p>
            <div className="file-input-wrapper">
              <input
                type="file"
                id="file-upload"
                accept=".pem,.crt,.cer,.asc,.txt"
                onChange={handleFileChange}
              />
              {fileTag && <div className="tag">{getTagIcon(fileTag)} {fileTag}</div>}
              {selectedFile && (
                <div className="file-name">📄 Selected: {selectedFile.name}</div>
              )}
            </div>

            {selectedFile && (
              <button onClick={handleUpload} disabled={uploading}>
                {uploading ? 'Uploading...' : 'Submit File'}
              </button>
            )}

            {selectedFile && !message.includes('✅ Encryption and Upload successful') && (
              <div className="disclaimer">
                ⚠️ <strong>Review before submitting.</strong> Click the{' '}
                <span className="submit-hint">green button</span> to send.
              </div>
            )}
          </section>
  
          <div className="actions">
            <button onClick={() => setShowDocs(!showDocs)}>{showDocs ? 'Hide Docs' : 'Show Docs'}</button>
            <button onClick={() => copyToClipboard(message)}>Copy Output</button>
            <button onClick={() => downloadText('output.txt', message)}>Download Output</button>
            <button onClick={() => setShowResults(!showResults)}>{showResults ? 'Hide Results' : 'Show Results'}</button>
          </div>
  
          {showDocs && (
            <Suspense fallback={<div>Loading docs...</div>}>
              <Docs postUrl={FULL_URL} payloadUrl={FULL_URL} />
            </Suspense>
          )}
  
          {showResults && (
            <section className="result-box">
              {checksum && <div className="checksum">SHA-256: {checksum}</div>}
              {commandSnippets && <pre className="commands">{commandSnippets}</pre>}
            </section>
          )}
  
          <footer>
            <button onClick={() => setShowDetails(!showDetails)}>{showDetails ? 'Hide Payload' : 'Show Payload'}</button>
            {showDetails && <pre className="payload-view">{JSON.stringify(upgpDATA, null, 2)}</pre>}
          </footer>
        </>
      )}
  
      {isDragging && <div className="drag-overlay">📄 Drop file to upload</div>}
    </div>
  );  
}

export default App;