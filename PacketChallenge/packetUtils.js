const crypto = require('crypto');
require('dotenv').config();
const ROTATION_SECRET = process.env.ROTATION_SECRET;
const HMAC_SECRET = process.env.HMAC_SECRET;
const MAX_TIME_DRIFT = 5;
function getRotatedKey(offset = 0) {
  const timeBucket = Math.floor(Date.now() / 60000) + offset;
  const keyBase = `${ROTATION_SECRET}-${timeBucket}`;
  return crypto.createHash('sha256').update(keyBase).digest();
}
function decrypt(encrypted) {
  const ivHex = encrypted.slice(0, 32);
  const dataHex = encrypted.slice(32);
  const iv = Buffer.from(ivHex, 'hex');
  const ciphertext = Buffer.from(dataHex, 'hex');
  for (let offset of [0, -1, 1]) {
    try {
      const key = getRotatedKey(offset);
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(ciphertext);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString();
    } catch (err) {
      continue;
    }
  }
  throw new Error("Unable to decrypt payload with any rotated key");
}
function verifyPacket(packet) {
  const now = Math.floor(Date.now() / 1000);
  const drift = Math.abs(now - packet.timestamp);
  if (drift > MAX_TIME_DRIFT) {
    return { valid: false, reason: "Stale or invalid timestamp" };
  }
  const hmac = crypto.createHmac('sha256', HMAC_SECRET);
  hmac.update(packet.payload + packet.timestamp + packet.nonce);
  const expectedSignature = hmac.digest('hex');
  if (expectedSignature !== packet.signature) {
    return { valid: false, reason: "Invalid HMAC signature" };
  }
  let decrypted;
  try {
    decrypted = decrypt(packet.payload);
  } catch (e) {
    return { valid: false, reason: "AES decryption failed" };
  }
  const expectedHash = crypto.createHash('sha256').update(decrypted).digest('hex');
  if (expectedHash !== packet.hash) {
    return { valid: false, reason: "Payload hash mismatch" };
  }
  let parsedPayload;
  try {
    parsedPayload = JSON.parse(decrypted);
  } catch (e) {
    return { valid: false, reason: "Payload is not valid JSON" };
  }
  if (!parsedPayload.dataText) {
    return { valid: false, reason: "Missing dataText in payload" };
  }
  return {
    valid: true,
    dataText: parsedPayload.dataText
  };
}
module.exports = {
  verifyPacket
};