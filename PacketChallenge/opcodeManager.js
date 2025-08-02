const crypto = require('crypto');
const opcodePool = [
  'A1', 'B2', 'C3', 'D4',
  'E5', 'F6', 'G7', 'H8',
  'I9', 'J0', 'K1', 'L2'
];
const opcodeMap = {
  "PING": 2,
  "LOGIN": 5,
  "FLAG_REQUEST": 7,
  "NOP": 1
};
function getCurrentOpcode(action) {
  const index = opcodeMap[action];
  if (index === undefined) throw new Error(`Unknown opcode action: ${action}`);
  const timeBucket = Math.floor(Date.now() / 60000); // 1-minute rotation
  const rotatedIndex = (index + timeBucket) % opcodePool.length;
  return opcodePool[rotatedIndex];
}
function getOpcodePool() {
  return opcodePool;
}
module.exports = {
  getCurrentOpcode,
  getOpcodePool
};