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
  const [showEncryption, setShowEncryption] = useState(false);
  const [showPublicKeys, setShowPublicKeys] = useState(false);
  const [showResponse, setShowResponse] = useState(false);
  const [checksumBefore, setChecksumBefore] = useState(null);
  const [checksumAfter, setChecksumAfter] = useState(null);
  const [commandSnippets, setCommandSnippets] = useState(null);
  const [upgpDATA, setupgpDATA] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [uploadUrl, setUploadUrl] = useState('');

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
        const verifiedResult = await verifyPayloadSignature(keyData);
  
        if (!verifiedResult) {
          console.warn('⛔ Invalid or unverifiable payload.');
          return;
        }
  
        setupgpDATA(verifiedResult);
  
        let rawKey = verifiedResult?.parsed?.key || verifiedResult?.publicKey || '';

        console.log('[debug] parsed.key:', verifiedResult?.parsed?.key);
        console.log('[debug] publicKey:', verifiedResult?.publicKey);
        
        if (typeof rawKey === 'string') {
          // Detect if it's double-escaped (\\n instead of \n)
          if (rawKey.includes('\\n')) {
            try {
              // JSON-parse to convert \\n → \n and preserve the real newlines
              rawKey = JSON.parse(`"${rawKey}"`);
            } catch (err) {
              console.warn('❌ Could not JSON-parse rawKey:', err);
            }
          }
        
          const trimmedKey = rawKey.trim();
          console.log('[debug] trimmedKey:\n', trimmedKey);
          setPublicKey(trimmedKey);
        }
        

        if (verifiedResult?.parsed?.url) {
          setUploadUrl(verifiedResult.parsed.url);
        }else{
          setUploadUrl(DEFAULT_UPLOAD_URL);
        }
      } catch (err) {
        console.warn('❌ Could not verify injected key:', err);
      }
    })();
  }, []);

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) setSelectedFile(file);
  };  

  useEffect(() => {
    let dragCounter = 0;
    const handleDragEnter = (e) => { e.preventDefault(); dragCounter++; setIsDragging(true); };
    const handleDragLeave = (e) => { e.preventDefault(); dragCounter--; if (dragCounter === 0) setIsDragging(false); };
    const handleDragOver = (e) => e.preventDefault();
    const handleDrop = (e) => {
      e.preventDefault(); setIsDragging(false); dragCounter = 0;
      const file = e.dataTransfer.files[0];
      if (file) setSelectedFile(file);
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
  
  useEffect(() => {
    if (publicKey && selectedFile) {
      analyzeFile(selectedFile);
    }
  }, [publicKey, selectedFile]);

  const analyzeFile = async (file) => {
    try {
      const text = await file.text();
      const buffer = await file.arrayBuffer();
  
      // SHA256 of original file
      const rawHashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const rawHashArray = Array.from(new Uint8Array(rawHashBuffer));
      const rawChecksum = rawHashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      setChecksumBefore(rawChecksum);
  
      setMessage('🛡️ Payload will be encrypted before POST.');
      setSelectedFile(file);
  
      // Encrypt using OpenPGP.js
      const openpgp = await import('openpgp');

      console.log('[ENCRYPT] Using publicKey:', publicKey);
      console.log('[ENCRYPT] typeof publicKey:', typeof publicKey);
      console.log('[ENCRYPT] Starts with header?', publicKey?.startsWith('-----BEGIN'));
      
      if (!publicKey || typeof publicKey !== 'string') {
        throw new Error('🛑 Public key is missing or invalid');
      }
      
      const encryptionKeys = await openpgp.readKey({
        armoredKey: publicKey.trim(), // <-- just in case extra linebreaks
      });
      
  
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: text }),
        encryptionKeys,
      });
  
      // SHA256 of encrypted result
      const encryptedBuffer = new TextEncoder().encode(encrypted);
      const encryptedHashBuffer = await crypto.subtle.digest('SHA-256', encryptedBuffer);
      const encryptedHashArray = Array.from(new Uint8Array(encryptedHashBuffer));
      const encryptedChecksum = encryptedHashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      console.log(encryptedChecksum);
      setChecksumAfter(encryptedChecksum);
  
      // Generate terminal-style display
      const publicKeyLine = `# SHA-256 of original file\nsha256sum ${file.name}\n> ${rawChecksum}`;
      const encryptLine = `# Encrypt using GPG and show hash\ngpg --encrypt --armor --recipient-file upgp.asc ${file.name} > encrypted.asc`;
      const hashLine = `sha256sum encrypted.asc\n> ${encryptedChecksum}`;
      const curlLine = `# Upload with curl\ncurl -X POST ${uploadUrl} \\\n  -H "Content-Type: application/json" \\\n  -d '{"content":"<encrypted.asc contents>"}'`;
  
      setCommandSnippets(`${publicKeyLine}\n\n${encryptLine}\n${hashLine}\n\n${curlLine}`);
    } catch (error) {
      console.error('Error analyzing file:', error);
      setMessage('❌ Failed to analyze the file.');
    }
  };

  const handleUpload = async () => {
    if (!selectedFile || !publicKey) return;
    setUploading(true);
  
    try {
      const openpgp = await import('openpgp');
      const fileText = await selectedFile.text();
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
            if ( parsed.message === '✅ Bin Successfully Configured.') {
              displayHTML += `👉 <a href="${fullLink}" target="_blank">${fullLink}</a><br>`;
              displayHTML += `<br><strong>Save this portal URL!</strong><br><br>`;
              displayHTML += `This page is only for you.<br>`;
              displayHTML += `📌 <strong>Save this URL or remember your ID!</strong> You’ll need it to return.<br>`;
            }else{
              displayHTML += `ID: ${parsed.id}<br>`;
              displayHTML += `Upload: ${window.location.origin}${parsed.upload}<br>`;
              displayHTML += `Key: ${window.location.origin}${parsed.key}<br>`;
              displayHTML += `👉 <a href="${fullLink}" target="_blank">${fullLink}</a><br>`;
              displayHTML += `Complete registration by visiting the portal URL.<br>`;
              displayHTML += `This page is only for you.<br>`;
              displayHTML += `📌 Save this URL or remember your ID! You’ll need it to return.<br>`;
            }
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
          {successNotification && (
            <div className="success-banner">
              <button className="info-btn" onClick={() => setShowResponse(prev => !prev)}>
                ℹ View Server Response
              </button>
              <div
                className="success-notification"
                dangerouslySetInnerHTML={{ __html: successNotification }}
              />
              <button onClick={() => setSuccessNotification('')} className="dismiss-btn">✖</button>
            </div>
          )}
  
          {showResponse && message && (
            <pre className="output">
              <code dangerouslySetInnerHTML={{ __html: syntaxHighlightJSON(message) }} />
            </pre>
          )}

          <div className="api-url-bar">
            <span className="method">POST</span>
            <input type="text" value={uploadUrl} disabled />
            <span className="lock-icon">🔒</span>
            <div className="info-icon" title="to learn more&#10;&#10;Click here">
              ℹ
              <div className="tooltip">
                to learn more<br />
                <a href="/learn" target="_blank" rel="noopener noreferrer">Click here</a>
              </div>
            </div>
          </div>
  
          <section className="upload-box fancy-box">
          <p>Select or drop a file to begin</p>
          <div className="file-input-styled">
            <label htmlFor="file-upload" className="custom-file-upload">
              <span>{selectedFile ? selectedFile.name : 'Choose a file...'}</span>
              <input
                type="file"
                id="file-upload"
                accept=".pem,.crt,.cer,.asc,.txt"
                onChange={handleFileChange}
              />
            </label>
          </div>

          {selectedFile && (
            <div className="submit-row">
              <button className="submit-btn-green" onClick={handleUpload} disabled={uploading}>
                {uploading ? 'Uploading...' : 'Submit File'}
              </button>
              {fileTag && <div className="tag right-tag">{getTagIcon(fileTag)} {fileTag}</div>}
            </div>
          )}

          {selectedFile && !message.includes('✅ Encryption and Upload successful') && (
            <div className="disclaimer">
              ⚠️ <strong>Review before submitting.</strong> Click the{' '}
              <span className="submit-hint">green button</span> to send.
            </div>
          )}

          <div className="actions">
            <button onClick={() => setShowDocs(!showDocs)}>{showDocs ? 'Hide Docs' : 'Show Docs'}</button>
            <button onClick={() => setShowEncryption(!showEncryption)}>{showEncryption ? 'Hide Encryption' : 'Show Encryption'}</button>
            <button onClick={() => setShowPublicKeys(!showPublicKeys)}>{showPublicKeys ? 'Hide Public Keys' : 'Show Public Keys'}</button>
          </div>
        </section>

          {showDocs && (
            <Suspense fallback={<div>Loading docs...</div>}>
              <Docs postUrl={FULL_URL} payloadUrl={FULL_URL} />
            </Suspense>
          )}
  
          {showEncryption && (
            <section className="result-box fancy-box">
              {checksumBefore && <div className="checksum">SHA-256 RAW: {checksumBefore}</div>}
              {checksumAfter && <div className="checksum">SHA-256 ENCRYPTED: {checksumAfter}</div>}
              {commandSnippets && <pre className="commands">{commandSnippets}</pre>}
            </section>
          )}

          {showPublicKeys && (
            <section className="result-box fancy-box">
              <pre className="payload-view">{JSON.stringify(upgpDATA, null, 2)}</pre>
            </section>
          )}
        </>
      )}
  
      {isDragging && <div className="drag-overlay">📄 Drop file to upload</div>}
    </div>
  );  
}

export default App;