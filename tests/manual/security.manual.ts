/**
 * Manual test for security features
 * Run with: npx ts-node tests/manual/security.manual.ts
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { FileGuardManager } from "../../dist/core/FileGuardManager";
import { createPersistentRSAFGM } from "../../dist/utils/rsaSolution";

// Create output directory
const TEST_DIR = path.join(__dirname, "..", "output");
if (!fs.existsSync(TEST_DIR)) {
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

// Generate a test file path
function getTestFilePath(
  prefix: string = "test",
  extension: string = ".nxs"
): string {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  return path.join(TEST_DIR, `${prefix}-${timestamp}-${random}${extension}`);
}

// Generate a random encryption key
function generateTestEncryptionKey(): Buffer {
  return Random.getRandomBytes(32);
}

// Generate an RSA key pair
function generateTestRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey };
}

// Generate test data
function generateTestData(): any {
  return {
    title: "Security Test Document",
    timestamp: new Date().toISOString(),
    content: "This is a test document for security testing.",
    securityLevel: "high",
    metadata: {
      author: "Security Tester",
      classification: "Confidential",
      tags: ["security", "test", "encryption"],
    },
  };
}

// Run the test
async function runTest() {
  console.log("=== Manual Test: Security Features ===\n");

  try {
    // Generate encryption key and RSA key pair
    const encryptionKey = generateTestEncryptionKey();
    const rsaKeyPair = generateTestRSAKeyPair();

    // Create FileGuardManager instance
    const fgm = new FileGuardManager(encryptionKey.toString("hex"));
    console.log("Created FileGuardManager instance");

    // Test 1: Tamper Protection
    console.log("\nTest 1: Tamper Protection");
    const testData = generateTestData();
    const filePath = getTestFilePath("tamper-test");

    console.log("Encrypting data...");
    await fgm.saveWithAdvancedEncryption(
      filePath,
      testData,
      encryptionKey,
      rsaKeyPair,
      {
        securityLevel: "high",
        compressionLevel: "medium",
        layers: 2,
        useAlgorithmRotation: true,
      }
    );

    console.log("Encryption successful!");

    // Add a small delay to ensure file system operations are complete
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Verify the file exists
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    console.log(
      `File exists at ${filePath}, size: ${fs.statSync(filePath).size} bytes`
    );

    // First, try normal decryption to make sure it works
    console.log("\nVerifying normal decryption works...");
    const decryptedData = await fgm.loadWithAdvancedDecryption(
      filePath,
      encryptionKey,
      rsaKeyPair
    );

    console.log("Normal decryption successful!");

    // Now tamper with the file
    console.log("\nTampering with the file...");
    const fileContent = fs.readFileSync(filePath);
    // Modify a byte in the middle of the file
    const tamperedContent = Buffer.from(fileContent);
    tamperedContent[Math.floor(tamperedContent.length / 2)] ^= 0xff; // Flip all bits in a byte
    fs.writeFileSync(filePath, tamperedContent);

    console.log("File has been tampered with");

    // Try to decrypt the tampered file
    console.log("\nAttempting to decrypt tampered file...");
    try {
      await fgm.loadWithAdvancedDecryption(
        filePath,
        encryptionKey,
        rsaKeyPair,
        {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        }
      );

      console.log(
        "SECURITY ISSUE: Decryption of tampered file succeeded when it should have failed!"
      );
      return false;
    } catch (error) {
      console.log("Decryption of tampered file failed as expected ✓");
      console.log(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Test 2: Key Security
    console.log("\nTest 2: Key Security");
    const keySecurityFilePath = getTestFilePath("key-security");

    console.log("Encrypting data...");
    await fgm.saveWithAdvancedEncryption(
      keySecurityFilePath,
      testData,
      encryptionKey,
      rsaKeyPair,
      {
        securityLevel: "high",
        compressionLevel: "medium",
      }
    );

    console.log("Encryption successful!");

    // Add a small delay to ensure file system operations are complete
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Generate a different key
    const wrongKey = generateTestEncryptionKey();

    // Try to decrypt with the wrong key
    console.log("\nAttempting to decrypt with wrong key...");
    try {
      await fgm.loadWithAdvancedDecryption(
        keySecurityFilePath,
        wrongKey,
        rsaKeyPair,
        {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        }
      );

      console.log(
        "SECURITY ISSUE: Decryption with wrong key succeeded when it should have failed!"
      );
      return false;
    } catch (error) {
      console.log("Decryption with wrong key failed as expected ✓");
      console.log(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Generate a different RSA key pair
    const wrongRSAKeyPair = generateTestRSAKeyPair();

    // Try to decrypt with the wrong RSA key pair
    console.log("\nAttempting to decrypt with wrong RSA key pair...");
    try {
      await fgm.loadWithAdvancedDecryption(
        keySecurityFilePath,
        encryptionKey,
        wrongRSAKeyPair,
        {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        }
      );

      console.log(
        "SECURITY ISSUE: Decryption with wrong RSA key pair succeeded when it should have failed!"
      );
      return false;
    } catch (error) {
      console.log("Decryption with wrong RSA key pair failed as expected ✓");
      console.log(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Test 3: Persistent RSA Keys
    console.log("\nTest 3: Persistent RSA Keys");

    // RSA keys path
    const rsaKeysPath = getTestFilePath("test-rsa-keys", ".json");

    // Create a FileGuardManager with persistent RSA keys
    console.log("Creating FileGuardManager with persistent RSA keys...");
    const persistentFgm = createPersistentRSAFGM(
      encryptionKey.toString("hex"),
      {
        rsaKeysPath,
      }
    );

    // Verify RSA key pair exists
    if (!persistentFgm.rsaKeyPair) {
      throw new Error("RSA key pair not generated");
    }

    console.log("Persistent RSA key pair generated successfully");
    console.log(`RSA keys saved to: ${rsaKeysPath}`);

    // Verify RSA keys file exists
    if (!fs.existsSync(rsaKeysPath)) {
      throw new Error(`RSA keys file not found: ${rsaKeysPath}`);
    }

    // Encrypt data with persistent RSA keys
    const persistentFilePath = getTestFilePath("persistent-rsa");

    console.log("\nEncrypting data with persistent RSA keys...");
    await persistentFgm.saveWithAdvancedEncryption(
      persistentFilePath,
      testData,
      encryptionKey,
      persistentFgm.rsaKeyPair,
      {
        securityLevel: "high",
        compressionLevel: "medium",
      }
    );

    console.log("Encryption with persistent RSA keys successful!");

    // Add a small delay to ensure file system operations are complete
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Create a new instance with the same RSA keys path
    console.log(
      "\nCreating a new FileGuardManager instance with the same RSA keys path..."
    );
    const newPersistentFgm = createPersistentRSAFGM(
      encryptionKey.toString("hex"),
      {
        rsaKeysPath,
      }
    );

    // Verify the new instance has the same RSA keys
    if (!newPersistentFgm.rsaKeyPair) {
      throw new Error("RSA key pair not loaded in new instance");
    }

    const keysMatch =
      newPersistentFgm.rsaKeyPair.publicKey ===
        persistentFgm.rsaKeyPair.publicKey &&
      newPersistentFgm.rsaKeyPair.privateKey ===
        persistentFgm.rsaKeyPair.privateKey;

    console.log(`RSA keys match: ${keysMatch ? "YES ✓" : "NO ✗"}`);

    if (!keysMatch) {
      throw new Error("RSA keys do not match between instances");
    }

    // Decrypt data with the new instance
    console.log("\nDecrypting data with the new instance...");
    await newPersistentFgm.loadWithAdvancedDecryption(
      persistentFilePath,
      encryptionKey,
      newPersistentFgm.rsaKeyPair
    );

    console.log("Decryption with persistent RSA keys successful! ✓");

    console.log("\n=== All security tests completed successfully! ===");
    return true;
  } catch (error) {
    console.error("\nTest failed with error:", error);
    return false;
  }
}

// Run the test
runTest()
  .then((success) => {
    process.exit(success ? 0 : 1);
  })
  .catch((error) => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
