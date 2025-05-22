/**
 * Simple Security Demo for NEHONIX FileGuard
 *
 * This demo showcases the secure encryption capabilities with a focus on
 * making data completely unreadable by humans or other systems except
 * by the FileGuardManager class itself.
 */

import * as fs from "fs";
import * as path from "path";
import { createPersistentRSAFGM, logger } from "./index";
import { FortifyJS as fty } from "fortify2-js";

// Set log level to debug for detailed output
logger.setLogLevel("debug");

// Demo configuration
const DEMO_DIR = path.resolve("./simple-security-demo");
const DEMO_FILE = path.join(DEMO_DIR, "secure-data.nxs");
const RSA_KEYS_PATH = path.join(DEMO_DIR, "secure-rsa-keys.json");

// Ensure we're using absolute paths
console.log(`Demo directory: ${DEMO_DIR}`);
console.log(`Demo file: ${DEMO_FILE}`);
console.log(`RSA keys path: ${RSA_KEYS_PATH}`);

/**
 * Run the simple security demo
 */
async function runSimpleSecurityDemo() {
  console.log("\n🔒 NEHONIX FileGuard SIMPLE SECURITY DEMO 🔒\n");

  // Create demo directory if it doesn't exist
  if (!fs.existsSync(DEMO_DIR)) {
    fs.mkdirSync(DEMO_DIR, { recursive: true });
  }

  // Generate a secure encryption key
  const keyString = fty.generateSecureToken({ length: 32 });
  console.log(
    `Generated secure encryption key: ${keyString.substring(0, 16)}...`
  );

  // Convert string key to Buffer for encryption/decryption
  const key = Buffer.from(keyString, "hex");

  // Create a FileGuardManager with persistent RSA keys
  console.log("\n📝 Creating FileGuardManager with persistent RSA keys...");
  const fgm = createPersistentRSAFGM(keyString, {
    rsaKeysPath: RSA_KEYS_PATH,
  });

  // Sample data to encrypt
  const sampleData = {
    title: "Confidential Document",
    content: "This is sensitive content that requires strong protection.",
    metadata: {
      author: "Security Team",
      classification: "CONFIDENTIAL",
      created: new Date().toISOString(),
    },
  };

  console.log("\nOriginal data:");
  console.log(JSON.stringify(sampleData, null, 2));

  // Encrypt the data
  console.log("\n🔐 Encrypting data...");
  const encryptResult = await fgm.saveWithAdvancedEncryption(
    DEMO_FILE,
    sampleData,
    key,
    fgm.rsaKeyPair,
    {
      securityLevel: "high",
      compressionLevel: "high",
      layers: 1,
      useAlgorithmRotation: false,
      addHoneypots: false,
    }
  );

  console.log(`\nEncryption result: ${JSON.stringify(encryptResult, null, 2)}`);

  // Check if the file exists
  if (!fs.existsSync(DEMO_FILE)) {
    console.error(`\nError: File not found at ${DEMO_FILE}`);
    console.log("Checking directory contents:");
    const dirContents = fs.readdirSync(DEMO_DIR);
    console.log(dirContents);
    return;
  }

  // Show the encrypted file size and details
  const fileStats = fs.statSync(DEMO_FILE);
  console.log(`\nEncrypted file size: ${fileStats.size} bytes`);

  // Try to read the raw encrypted file to demonstrate it's unreadable
  const encryptedBuffer = fs.readFileSync(DEMO_FILE);
  console.log("\nRaw encrypted data (first 100 bytes):");
  console.log(
    Buffer.from(
      encryptedBuffer.buffer,
      encryptedBuffer.byteOffset,
      Math.min(100, encryptedBuffer.length)
    )
      .toString("hex")
      .match(/.{1,2}/g)
      ?.join(" ")
  );

  // Decrypt the data
  console.log("\n🔓 Decrypting data...");
  try {
    const decryptedData = await fgm.loadWithAdvancedDecryption(
      DEMO_FILE,
      key,
      fgm.rsaKeyPair
    );

    // Verify decryption was successful by checking key fields
    const isSuccessful =
      decryptedData.title === sampleData.title &&
      decryptedData.content === sampleData.content &&
      decryptedData.metadata.author === sampleData.metadata.author &&
      decryptedData.metadata.classification ===
        sampleData.metadata.classification;

    console.log(`\nDecryption successful: ${isSuccessful}`);

    // Show the decrypted data
    console.log("\nDecrypted data:");
    console.log(JSON.stringify(decryptedData, null, 2));

    console.log("\n✅ Simple Security Demo completed successfully!");
  } catch (error) {
    console.error("\n❌ Decryption failed:", error);
  }
}

// Run the demo
runSimpleSecurityDemo().catch((error) => {
  console.error("Demo failed:", error);
});
