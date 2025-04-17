// utils/verifySignedMessage.js
export const verifySignedMessageWithDriftCheck = async ({
    openpgp,
    signed,
    serverPublicKeyArmored,
    driftAllowance = 60000, // default to 60 seconds
  }) => {
    const message = await openpgp.readCleartextMessage({ cleartextMessage: signed });
    const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
  
    // Drift check first
    const tempVerification = await openpgp.verify({
      message,
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
  
    if (drift > driftAllowance) {
      throw new Error('🕒 Signature creation time is too far in the future.');
    }
  
    if (drift > 0) {
      await new Promise((res) => setTimeout(res, drift + 100));
    }
  
    // Final real-time verification
    const finalVerification = await openpgp.verify({
      message,
      verificationKeys: serverPublicKey,
      date: new Date(),
    });
  
    await finalVerification.signatures[0].verified;
    return message;
  };
  