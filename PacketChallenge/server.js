const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const path = require('path');
const { verifyPacket } = require('./packetUtils');
const { getCurrentOpcode } = require('./opcodeManager');
const { buildPacket } = require('./clientHelper');
dotenv.config();
const app = express();
const PORT = 3000;
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'client')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'index.html'));
});
app.post('/packet', (req, res) => {
  const packet = req.body;
  try {
    const { valid, reason, dataText } = verifyPacket(packet);
    if (!valid) {
      return res.status(400).json({ success: false, reason });
    }
    const expectedOpcode = getCurrentOpcode('PING');
    if (packet.opcode !== expectedOpcode) {
      return res.status(403).json({ success: false, reason: "Invalid or outdated opcode" });
    }
    if (typeof dataText === 'string' && dataText.startsWith("flag_request:")) {
      return res.json({ success: true, flag: "FLAG{Stage_1_Cleared}" });
    }
    return res.json({ success: true, message: "🎉 You win! You beat the Packet Challenge!" });
  } catch (err) {
    console.error("Error processing packet:", err);
    return res.status(500).json({ success: false, reason: "Server error" });
  }
});
app.post('/send-packet', (req, res) => {
  const { dataText } = req.body;
  if (!dataText) return res.status(400).json({ success: false, reason: "Missing dataText" });
  try {
    const packet = buildPacket(dataText);
    const { valid, reason, dataText: verifiedDataText } = verifyPacket(packet);
    if (!valid) {
      return res.status(400).json({ success: false, reason });
    }
    const expectedOpcode = getCurrentOpcode('PING');
    if (packet.opcode !== expectedOpcode) {
      return res.status(403).json({ success: false, reason: "Invalid or outdated opcode" });
    }
    if (verifiedDataText === "flag_request:stage1") {
      return res.json({ success: true, flag: "FLAG{Stage_1_Cleared}", packet });
    }
    return res.status(403).json({ success: false, reason: "Incorrect dataText" });
  } catch (err) {
    console.error("Error in /send-packet:", err);
    return res.status(500).json({ success: false, reason: "Server error" });
  }
});
app.listen(PORT, () => {
  console.log(`Packet Challenge running at http://localhost:${PORT}`);
});