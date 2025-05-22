/**
 * Integrated Binary Format Demo for NEHONIX FileGuard
 *
 * This demo showcases the integrated binary format in the FileGuardManager
 * that makes data completely unreadable by humans or other systems.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { FileGuardManager, logger } from "./index";

// Set log level to debug for detailed output
logger.setLogLevel("debug");

// Demo configuration
const DEMO_DIR = path.resolve("./integrated-binary-demo");
const DEMO_FILE = path.join(DEMO_DIR, "integrated-binary.nxs");

// Ensure we're using absolute paths
console.log(`Demo directory: ${DEMO_DIR}`);
console.log(`Demo file: ${DEMO_FILE}`);

/**
 * Run the integrated binary format demo
 */
async function runIntegratedBinaryDemo() {
  console.log("\n🔒 NEHONIX FileGuard INTEGRATED BINARY FORMAT DEMO 🔒\n");

  // Create demo directory if it doesn't exist
  if (!fs.existsSync(DEMO_DIR)) {
    fs.mkdirSync(DEMO_DIR, { recursive: true });
  }

  // Generate a secure encryption key
  const key = crypto.randomBytes(32);
  console.log(
    `Generated secure encryption key: ${key
      .toString("hex")
      .substring(0, 16)}...`
  );

  // Create a FileGuardManager
  console.log("\n📝 Creating FileGuardManager...");
  const fgm = new FileGuardManager(key.toString("hex"));

  // Sample data to encrypt
  const sampleData = {
    title: "TOP SECRET",
    content:
      "This is extremely sensitive content that requires the highest possible security protection.",
    credentials: {
      username: "admin",
      apiKey: crypto.randomBytes(16).toString("hex"),
      accessToken: crypto.randomBytes(32).toString("hex"),
    },
    metadata: {
      author: "Security Officer",
      department: "Classified Operations",
      classification: "TOP SECRET",
      created: new Date().toISOString(),
      accessControl: {
        clearanceLevel: "ULTRA",
        authorizedPersonnel: ["Director", "Security Officer"],
        auditTrail: true,
      },
    },
  };

  console.log("\nOriginal data:");
  console.log(JSON.stringify(sampleData, null, 2));

  // Encrypt the data using the simple binary format
  console.log("\n🔐 Encrypting data with simple binary format...");
  const encryptResult = await fgm.saveWithSimpleBinaryFormat(
    DEMO_FILE,
    sampleData,
    key
  );

  console.log(`\nData encrypted successfully to ${DEMO_FILE}`);
  console.log(`Encryption result: ${JSON.stringify(encryptResult, null, 2)}`);

  // Show the encrypted file size
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
    const decryptedData = await fgm.loadWithSimpleBinaryFormat(DEMO_FILE, key);

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

    console.log("\n✅ Integrated Binary Format Demo completed successfully!");
  } catch (error) {
    console.error("\n❌ Decryption failed:", error);
  }
}

// Run the demo
runIntegratedBinaryDemo().catch((error) => {
  console.error("Demo failed:", error);
});
