/**
 * RSA Layer Isolation Test
 * Test only the RSA encryption/decryption layer
 * Run with: bun ./tests/rsa-layer-test.ts
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// Create output directory
const OUTPUT_DIR = path.join(__dirname, "output", "rsa-layer");
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Test data - simulate what would be passed to RSA layer
const testData = Buffer.from("This is test data for RSA layer encryption", "utf8");

async function testRSALayerIsolation() {
  try {
    console.log("=== RSA Layer Isolation Test ===");
    console.log("Test data:", testData.toString());
    console.log("Test data size:", testData.length, "bytes");
    
    // Generate RSA key pair
    console.log("\n--- Generating RSA Key Pair ---");
    const rsaKeyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    
    console.log("RSA key pair generated");
    console.log("Public key length:", rsaKeyPair.publicKey.length);
    console.log("Private key length:", rsaKeyPair.privateKey.length);
    
    // Simulate the RSA hybrid encryption process
    console.log("\n--- RSA Hybrid Encryption ---");
    
    // Generate AES key and IV (same as in BinarySecureFormat)
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    console.log("AES key size:", aesKey.length, "bytes");
    console.log("IV size:", iv.length, "bytes");
    console.log("Data to encrypt size:", testData.length, "bytes");
    
    // AES-GCM encryption
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    const aadString = "enhanced-rsa-hybrid-layer";
    cipher.setAAD(Buffer.from(aadString));
    
    const encrypted = Buffer.concat([cipher.update(testData), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    console.log("AES-GCM encryption successful:");
    console.log("- Encrypted data size:", encrypted.length, "bytes");
    console.log("- Auth tag size:", authTag.length, "bytes");
    
    // RSA encryption of AES key
    const encryptedKey = crypto.publicEncrypt(
      {
        key: rsaKeyPair.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKey
    );
    
    console.log("RSA encryption successful:");
    console.log("- Encrypted AES key size:", encryptedKey.length, "bytes");
    
    // Create metadata
    const metadata = {
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedKey: encryptedKey.toString("base64"),
      algorithm: "aes-256-gcm",
      oaepHash: "sha256",
      rsaKeySize: 2048,
    };
    
    // Create the complete encrypted package
    const metadataBuffer = Buffer.from(JSON.stringify(metadata));
    const metadataLength = Buffer.alloc(4);
    metadataLength.writeUInt32BE(metadataBuffer.length, 0);
    
    const encryptedPackage = Buffer.concat([metadataLength, metadataBuffer, encrypted]);
    
    console.log("Complete package created:");
    console.log("- Metadata size:", metadataBuffer.length, "bytes");
    console.log("- Total package size:", encryptedPackage.length, "bytes");
    
    // Save to file for inspection
    const filePath = path.join(OUTPUT_DIR, "rsa-test.bin");
    fs.writeFileSync(filePath, encryptedPackage);
    console.log("Package saved to:", filePath);
    
    // Now test decryption
    console.log("\n--- RSA Hybrid Decryption ---");
    
    // Read the package
    const packageData = fs.readFileSync(filePath);
    console.log("Package read from file, size:", packageData.length, "bytes");
    
    // Extract metadata
    const readMetadataLength = packageData.readUInt32BE(0);
    console.log("Metadata length:", readMetadataLength, "bytes");
    
    const readMetadataBuffer = packageData.subarray(4, 4 + readMetadataLength);
    const readMetadata = JSON.parse(readMetadataBuffer.toString("utf8"));
    console.log("Metadata parsed successfully");
    
    const readEncryptedData = packageData.subarray(4 + readMetadataLength);
    console.log("Encrypted data extracted, size:", readEncryptedData.length, "bytes");
    
    // Decrypt AES key with RSA
    const readEncryptedKey = Buffer.from(readMetadata.encryptedKey, "base64");
    console.log("Encrypted AES key size:", readEncryptedKey.length, "bytes");
    
    const decryptedAesKey = crypto.privateDecrypt(
      {
        key: rsaKeyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: readMetadata.oaepHash || "sha256",
      },
      readEncryptedKey
    );
    
    console.log("RSA decryption successful:");
    console.log("- Decrypted AES key size:", decryptedAesKey.length, "bytes");
    console.log("- Keys match:", aesKey.equals(decryptedAesKey) ? "YES ✓" : "NO ✗");
    
    // Decrypt data with AES-GCM
    const readIv = Buffer.from(readMetadata.iv, "base64");
    const readAuthTag = Buffer.from(readMetadata.authTag, "base64");
    
    console.log("AES-GCM decryption parameters:");
    console.log("- IV size:", readIv.length, "bytes");
    console.log("- Auth tag size:", readAuthTag.length, "bytes");
    console.log("- Algorithm:", readMetadata.algorithm);
    console.log("- Data to decrypt size:", readEncryptedData.length, "bytes");
    
    const decipher = crypto.createDecipheriv(readMetadata.algorithm, decryptedAesKey, readIv);
    decipher.setAuthTag(readAuthTag);
    decipher.setAAD(Buffer.from(aadString));
    
    const decrypted = Buffer.concat([decipher.update(readEncryptedData), decipher.final()]);
    
    console.log("AES-GCM decryption successful:");
    console.log("- Decrypted data size:", decrypted.length, "bytes");
    console.log("- Data matches:", testData.equals(decrypted) ? "YES ✓" : "NO ✗");
    console.log("- Decrypted content:", decrypted.toString());
    
    return testData.equals(decrypted);
    
  } catch (error) {
    console.error("RSA layer test failed:", error);
    console.error("Error details:", error.message);
    console.error("Stack trace:", error.stack);
    return false;
  }
}

// Run the test
testRSALayerIsolation()
  .then(success => {
    console.log("\n=== FINAL RESULT ===");
    console.log("RSA Layer Test:", success ? "PASSED ✅" : "FAILED ❌");
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
