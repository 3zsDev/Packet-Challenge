const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();
const { getCurrentOpcode } = require('../opcodeManager');
const ROTATION_SECRET = process.env.ROTATION_SECRET;
const HMAC_SECRET = process.env.HMAC_SECRET;
function getRotatedKey(offset = 0) {
  const timeBucket = Math.floor(Date.now() / 60000) + offset;
  const keyBase = `${ROTATION_SECRET}-${timeBucket}`;
  return crypto.createHash('sha256').update(keyBase).digest();
}
function encrypt(payload) {
  const key = getRotatedKey(0);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(payload);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + encrypted.toString('hex');
}
function generateNonce(length = 8) {
  return crypto.randomBytes(length).toString('hex');
}
function generateUUID() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.randomBytes(1)[0] & 15 >> c / 4).toString(16)
  );
}
async function sendPacket(dataText) {
  try {
    const payloadObj = { dataText };
    const payloadJSON = JSON.stringify(payloadObj);
    const encryptedPayload = encrypt(payloadJSON);
    const payloadHash = crypto.createHash('sha256').update(payloadJSON).digest('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce();
    const opcode = getCurrentOpcode('PING');
    const hmac = crypto.createHmac('sha256', HMAC_SECRET);
    hmac.update(encryptedPayload + timestamp + nonce);
    const signature = hmac.digest('hex');
    const packet = {
      id: generateUUID(),
      opcode,
      payload: encryptedPayload,
      timestamp,
      signature,
      nonce,
      challenge_token: "ct_987123",
      hash: payloadHash,
      version: process.env.PROTOCOL_VERSION || "1.0.0",
      client_id: "client_001",
      flags: {
        compressed: false
      }
    };
    const response = await axios.post('http://localhost:3000/packet', packet);
    console.log("Server response:", response.data);
  } catch (err) {
    if (err.response) {
      console.error("Server error:", err.response.data);
    } else {
      console.error("Error:", err.message);
    }
  }
}
const dataText = process.argv[2] || "flag_request:stage1";
sendPacket(dataText);
