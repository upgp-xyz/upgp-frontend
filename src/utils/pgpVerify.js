import { SERVER_PUBLIC_KEY } from '../config.js';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const canonicalize = (obj) => {
  return JSON.stringify(obj, Object.keys(obj).sort());
};

export const verifyPayloadSignature = async (signedPayload, updateState = () => {}) => {
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

  try {
    const openpgp = await import('openpgp');

    const cleartext = await openpgp.readCleartextMessage({
      cleartextMessage: signedPayload.signature,
    });

    const parsed = JSON.parse(cleartext.getText());

    // ✅ Use trusted server public key
    const serverPublicKey = await openpgp.readKey({
      armoredKey: SERVER_PUBLIC_KEY,
    });

    // ⏳ Drift check before full verification
    const tempVerification = await openpgp.verify({
      message: cleartext,
      verificationKeys: serverPublicKey,
      date: new Date(0),
    });

    const tempSig = tempVerification.signatures[0];
    const rawSig = await tempSig.signature;
    const created = rawSig?.packets?.[0]?.created;

    if (!created || !(created instanceof Date)) {
      throw new Error('❌ Signature is missing a valid creation timestamp.');
    }

    const now = new Date();
    const drift = created.getTime() - now.getTime();
    const driftAllowance = 60000;

    if (drift > driftAllowance) {
      throw new Error('🕒 Signature creation time is too far in the future.');
    }

    if (drift > 0) {
      await sleep(drift + 100);
    }

    // ✅ Final verification
    const verificationResult = await openpgp.verify({
      message: cleartext,
      verificationKeys: serverPublicKey,
      date: new Date(),
    });

    const { verified } = verificationResult.signatures[0];
    await verified;

    // 🔄 Update state with full parsed content
    const result = {
      raw: signedPayload,
      parsed,
      publicKey: serverPublicKey.armor(),
    };

    updateState(result);

    return result;
  } catch (err) {
    console.warn('⚠️ Signature verification failed:', err.message);
    return false;
  }
};

export const verifyCleartextSignature = async (text, armoredSig, armoredKey) => {
  try {
    const message = await openpgp.createCleartextMessage({ text });
    const signature = await openpgp.readSignature({ armoredSignature: armoredSig });
    const publicKey = await openpgp.readKey({ armoredKey });

    const verificationResult = await openpgp.verify({
      message,
      signature,
      verificationKeys: publicKey,
    });

    const { verified, keyID } = verificationResult.signatures[0];
    await verified;
    console.info(`✅ Response verified. KeyID: ${keyID.toHex()}`);
    return true;
  } catch (err) {
    console.warn('❌ Response signature verification failed:', err);
    return false;
  }
};