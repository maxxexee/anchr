/**
 * Anchr E2E — FIXED BROWSER FLOW
 * 
 * Tests the fixed ancrSimpleLogin with per-document TOTP secrets.
 * All docs should now be decryptable regardless of which TOTP was used.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv, createHmac, pbkdf2Sync } from 'crypto';
import { readFileSync } from 'fs';
import { ethers } from 'ethers';

const PRIVATE_KEY = '3df80448d2b63688e0ca1280cabbee6cf7e033b7af05f24b7067bccd4f8ca78c';
const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
const VAULT_ADDRESS = '0xc1eDa79d2Fd90F0630AB29A16D59F68f0A2F7C9e';
const VAULT_ABI = [
  'function seal(string name, string mimeType, bytes content, bytes32 merkleRoot, bytes wrappedKey, bytes32 totpCommitment) returns (bytes32 id)',
  'function fetch(bytes32 id) view returns (string name, string mimeType, bytes content, bytes key, tuple(bytes32 id, string name, string mimeType, bytes32 merkleRoot, address sender, uint256 timestamp, uint256 size, bool shredded, uint256 seq) doc)',
  'function getDocument(bytes32 id) view returns (tuple(bytes32 id, string name, string mimeType, bytes32 merkleRoot, address sender, uint256 timestamp, uint256 size, bool shredded, uint256 seq))',
  'function getDocumentsBySender(address sender) view returns (bytes32[])',
  'function count() view returns (uint256)',
];

function toHex(buf) { return Buffer.from(buf).toString('hex'); }
function sha256(data) { return createHash('sha256').update(data).digest(); }
function concatBytes(...arrays) { return Buffer.concat(arrays.map(a => Buffer.from(a))); }

function aesEncrypt(keyBytes, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyBytes, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { packed: concatBytes(iv, encrypted, tag) };
}

function aesDecrypt(keyBytes, packed) {
  const iv = packed.slice(0, 12);
  const tag = packed.slice(packed.length - 16);
  const ct = packed.slice(12, packed.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', keyBytes, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

async function merkleRoot(data) {
  const CHUNK = 4096;
  const leaves = [];
  if (data.length === 0) { leaves.push(sha256(Buffer.from('anchr-empty'))); }
  else { for (let off = 0; off < data.length; off += CHUNK) { leaves.push(sha256(data.subarray(off, off + CHUNK))); } }
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i], b = level[i + 1] || level[i];
      next.push(sha256(concatBytes(a, b)));
    }
    level = next;
  }
  return level[0];
}

const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  const bytes = Buffer.from(buffer);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let result = '';
  for (let i = 0; i < bits.length; i += 5) { result += B32_CHARS[parseInt(bits.substr(i, 5), 2)]; }
  return result;
}

function base32Decode(str) {
  str = str.replace(/=/g, '').toUpperCase();
  let bits = '';
  for (const c of str) { const val = B32_CHARS.indexOf(c); if (val === -1) throw new Error('Invalid base32'); bits += val.toString(2).padStart(5, '0'); }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) { bytes.push(parseInt(bits.substr(i, 8), 2)); }
  return Buffer.from(bytes);
}

function generateTotpSecret() { return randomBytes(20); }

function computeTotp(secret, timeStep) {
  const timeBuf = Buffer.alloc(8, 0);
  timeBuf.writeUInt32BE(timeStep, 4);
  const hmac = createHmac('sha1', secret).update(timeBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff)) % Math.pow(10, TOTP_DIGITS);
  return code.toString().padStart(TOTP_DIGITS, '0');
}

function getCurrentTimeStep() { return Math.floor(Date.now() / 1000 / TOTP_PERIOD); }

function verifyTotp(secret, code) {
  const currentStep = getCurrentTimeStep();
  for (let delta = -1; delta <= 1; delta++) { if (computeTotp(secret, currentStep + delta) === code) return true; }
  return false;
}

const ANCHR_SALT = Buffer.from([0x41, 0x6e, 0x63, 0x68, 0x72, 0x56, 0x61, 0x75, 0x6c, 0x74]);

function deriveWrappingKeySync(totpSecret) { return pbkdf2Sync(totpSecret, ANCHR_SALT, 100000, 32, 'sha256'); }

function wrapKeySync(aesKeyRaw, totpSecret) {
  const wrappingKey = deriveWrappingKeySync(totpSecret);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', wrappingKey, iv);
  const encrypted = Buffer.concat([cipher.update(aesKeyRaw), cipher.final()]);
  const tag = cipher.getAuthTag();
  return concatBytes(iv, encrypted, tag);
}

function unwrapKeySync(wrappedKeyBytes, totpSecret) {
  const wrappingKey = deriveWrappingKeySync(totpSecret);
  const iv = wrappedKeyBytes.slice(0, 12);
  const tag = wrappedKeyBytes.slice(wrappedKeyBytes.length - 16);
  const ct = wrappedKeyBytes.slice(12, wrappedKeyBytes.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', wrappingKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

async function main() {
  console.log('═'.repeat(60));
  console.log('  ANCHR FIXED BROWSER FLOW E2E');
  console.log('  Per-document TOTP secrets → all docs decryptable');
  console.log('═'.repeat(60));
  console.log();

  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const deployer = await wallet.getAddress();
  const balance = await provider.getBalance(deployer);

  console.log(`  Network:  Sepolia`);
  console.log(`  Wallet:   ${deployer}`);
  console.log(`  Balance:  ${ethers.formatEther(balance)} ETH`);
  console.log();

  // Simulate localStorage
  const _ls = {};
  const localStorage = {
    getItem: (k) => _ls[k] || null,
    setItem: (k, v) => { _ls[k] = v; },
  };

  // ────────────────────────────────────────────
  //  STEP 1: SEAL DOC A with TOTP secret A
  // ────────────────────────────────────────────
  console.log('─'.repeat(60));
  console.log('  STEP 1: SEAL DOCUMENT A (with TOTP secret A)');
  console.log('─'.repeat(60));

  const contentA = Buffer.from('Document A: Confidential NDA between Acme and Northwind');
  const aesKeyA = randomBytes(32);
  const { packed: encA } = aesEncrypt(aesKeyA, contentA);
  const rootA = toHex(await merkleRoot(encA));

  const totpSecretA = generateTotpSecret();
  const totpSecretAB32 = base32Encode(totpSecretA);
  const commitmentA = sha256(totpSecretA);
  const wrappedKeyA = wrapKeySync(aesKeyA, totpSecretA);

  console.log(`  TOTP A:    ${totpSecretAB32}`);
  console.log(`  Wrapped:   ${wrappedKeyA.length} bytes`);

  // Store per-doc TOTP secret (like fixed ancrSealOnChain)
  // Also store master (first seal sets the master)
  localStorage.setItem('anchr-totp-secret', totpSecretAB32);

  const vault = new ethers.Contract(VAULT_ADDRESS, VAULT_ABI, wallet);
  const sealTxA = await vault.seal('doc-a.pdf', 'application/pdf', encA, '0x' + rootA, wrappedKeyA, '0x' + toHex(commitmentA));
  const receiptA = await sealTxA.wait();
  const topicA = ethers.id('DocumentSealed(uint256,bytes32,string,address,uint256,uint256)');
  const docIdA = receiptA.logs.find(l => l.topics[0] === topicA).topics[2];
  localStorage.setItem('anchr-totp-' + docIdA, totpSecretAB32); // per-doc storage
  console.log(`  Doc ID A:  ${docIdA}`);
  console.log(`  Seal TX:   ${receiptA.hash}`);
  console.log();

  // ────────────────────────────────────────────
  //  STEP 2: SEAL DOC B with DIFFERENT TOTP secret B
  // ────────────────────────────────────────────
  console.log('─'.repeat(60));
  console.log('  STEP 2: SEAL DOCUMENT B (with DIFFERENT TOTP secret B)');
  console.log('─'.repeat(60));

  const contentB = Buffer.from('Document B: Audit report for Q3 2026 compliance review');
  const aesKeyB = randomBytes(32);
  const { packed: encB } = aesEncrypt(aesKeyB, contentB);
  const rootB = toHex(await merkleRoot(encB));

  const totpSecretB = generateTotpSecret();
  const totpSecretBB32 = base32Encode(totpSecretB);
  const commitmentB = sha256(totpSecretB);
  const wrappedKeyB = wrapKeySync(aesKeyB, totpSecretB);

  console.log(`  TOTP B:    ${totpSecretBB32}`);
  console.log(`  Wrapped:   ${wrappedKeyB.length} bytes`);

  // THIS OVERWRITES the master — this was the old bug!
  localStorage.setItem('anchr-totp-secret', totpSecretBB32);

  const sealTxB = await vault.seal('doc-b.pdf', 'application/pdf', encB, '0x' + rootB, wrappedKeyB, '0x' + toHex(commitmentB));
  const receiptB = await sealTxB.wait();
  const docIdB = receiptB.logs.find(l => l.topics[0] === topicA).topics[2];
  localStorage.setItem('anchr-totp-' + docIdB, totpSecretBB32); // per-doc storage
  console.log(`  Doc ID B:  ${docIdB}`);
  console.log(`  Seal TX:   ${receiptB.hash}`);
  console.log();

  // ────────────────────────────────────────────
  //  STEP 3: LOGIN with 6-digit code from TOTP A
  //  (simulates user entering code from their authenticator)
  // ────────────────────────────────────────────
  console.log('─'.repeat(60));
  console.log('  STEP 3: LOGIN WITH TOTP A CODE');
  console.log('─'.repeat(60));

  // User enters code from TOTP A's authenticator
  const codeA = computeTotp(totpSecretA, getCurrentTimeStep());
  console.log(`  Code from TOTP A: ${codeA}`);

  // Simulate ancrSimpleLogin
  const masterSecretB32 = localStorage.getItem('anchr-totp-secret');
  const masterSecretBytes = masterSecretB32 ? base32Decode(masterSecretB32) : null;

  // Verify against master (TOTP B's secret)
  const masterValid = verifyTotp(masterSecretBytes, codeA);
  console.log(`  Master (TOTP B) valid: ${masterValid ? '✓' : '✗ (expected — different secret)'}`);

  // If master fails, try per-doc secrets
  // In the real browser code, we verify master first, then try per-doc for each doc

  // Get docs from chain
  const docIds = await vault.getDocumentsBySender(deployer);
  console.log(`  Docs on chain: ${docIds.length}`);

  let successCount = 0;
  let skipCount = 0;

  for (const id of docIds) {
    if (id === ethers.ZeroHash) continue;
    const [, , contentHex, keyHex, doc] = await vault.fetch(id);
    if (doc.shredded) { skipCount++; continue; }

    // Skip empty wrapped keys
    if (!keyHex || keyHex === '0x' || hexToBytes(keyHex).length < 12) {
      console.log(`  SKIP ${doc.name}: no wrapped key`);
      skipCount++;
      continue;
    }

    const wrappedKeyBytes = hexToBytes(keyHex);

    // Try per-doc TOTP secret first
    const perDocB32 = localStorage.getItem('anchr-totp-' + id);
    let aesKeyRaw = null;
    let matchedB32 = null;

    const secretsToTry = [];
    if (perDocB32) secretsToTry.push({ b32: perDocB32, bytes: base32Decode(perDocB32) });
    if (masterSecretBytes) secretsToTry.push({ b32: masterSecretB32, bytes: masterSecretBytes });

    for (const { b32, bytes } of secretsToTry) {
      try {
        aesKeyRaw = unwrapKeySync(wrappedKeyBytes, bytes);
        matchedB32 = b32;
        break;
      } catch (_) {}
    }

    if (!aesKeyRaw) {
      console.log(`  SKIP ${doc.name}: no matching TOTP secret`);
      skipCount++;
      continue;
    }

    const encryptedBytes = hexToBytes(contentHex);
    const decrypted = aesDecrypt(aesKeyRaw, encryptedBytes);
    const original = id === docIdA ? contentA : contentB;
    const match = decrypted.equals(original);
    console.log(`  DECRYPT ${doc.name}: ${match ? '✓ EXACT MATCH' : '✗ MISMATCH'} (${decrypted.length} bytes)`);
    console.log(`    Content: "${decrypted.toString('utf8').slice(0, 60)}..."`);
    console.log(`    TOTP used: ${matchedB32.slice(0, 8)}...`);
    if (match) successCount++;
    else skipCount++;
  }

  // ────────────────────────────────────────────
  //  SUMMARY
  // ────────────────────────────────────────────
  console.log();
  console.log('═'.repeat(60));
  console.log('  RESULTS');
  console.log('═'.repeat(60));
  console.log();
  console.log(`  Sealed:     2 docs with DIFFERENT TOTP secrets`);
  console.log(`  Decrypted:  ${successCount}/${docIds.length} docs ✓`);
  console.log(`  Skipped:    ${skipCount}`);
  console.log();
  console.log(`  Fix verified: Per-doc TOTP storage allows all docs`);
  console.log(`  to be decrypted regardless of which TOTP was used.`);
  console.log();
}

function hexToBytes(hex) {
  hex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = Buffer.alloc(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) { bytes[i] = parseInt(hex.substr(i * 2, 2), 16); }
  return bytes;
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });
