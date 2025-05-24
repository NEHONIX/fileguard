/**
 * Binary Format Only Test
 * Run with: bun ./tests/binary-only-test.ts
 */

import { decryptData, encryptData } from "../src/utils/cryptUtils";
import { generateRSAKeyPairForData, testRSAWithDataSize, calculateRSAKeySize } from "fortify2-js";
import * as fs from "fs";
import * as crypto from "crypto";
import { fileURLToPath } from "url";
import path from "path";

// Create output directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUTPUT_DIR = path.join(__dirname, "output", "binary-only");
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Test data
const data = [{ user: "test3" }, "p1", 2, 0x204];
const dataString = JSON.stringify(data);
const dataSize = Buffer.from(dataString).length;

async function runBinaryOnlyTest() {
  try {
    console.log("=== Binary Format Encryption/Decryption Test ===");
    console.log("Test data:", JSON.stringify(data));
    console.log("Data size:", dataSize, "bytes");
    
    // Step 1: Calculate appropriate RSA key size
    console.log("\n--- Step 1: RSA Key Size Calculation ---");
    const recommendedKeySize = calculateRSAKeySize(32); // AES key is 32 bytes
    console.log("Recommended RSA key size for 32-byte AES key:", recommendedKeySize, "bits");
    
    // Step 2: Test RSA with different key sizes
    console.log("\n--- Step 2: RSA Capability Testing ---");
    const testSizes = [1024, 2048, 3072, 4096];
    
    for (const keySize of testSizes) {
      console.log(`\nTesting RSA ${keySize} bits with 32-byte data...`);
      const result = await testRSAWithDataSize(32, keySize);
      
      if (result.success) {
        console.log(`✅ RSA ${keySize}: SUCCESS - Encrypted: ${result.encryptedSize} bytes, Match: ${result.decryptedMatches ? "YES" : "NO"}`);
      } else {
        console.log(`❌ RSA ${keySize}: FAILED - ${result.error}`);
      }
    }
    
    // Step 3: Generate appropriate RSA key pair
    console.log("\n--- Step 3: Generate RSA Key Pair ---");
    const rsaKeyInfo = generateRSAKeyPairForData(32); // For 32-byte AES key
    console.log("Generated RSA key size:", rsaKeyInfo.keySize, "bits");
    console.log("Public key length:", rsaKeyInfo.publicKey.length, "characters");
    console.log("Private key length:", rsaKeyInfo.privateKey.length, "characters");
    
    // Step 4: Test binary format encryption
    console.log("\n--- Step 4: Binary Format Encryption ---");
    const binaryFilePath = path.join(OUTPUT_DIR, "binary-test.nxs");
    
    // Always serialize data to Buffer for encryption!
    const dataBuffer = Buffer.from(JSON.stringify(data));
    console.log("Encrypting data with binary format...");
    const binaryResult = await encryptData(dataBuffer, binaryFilePath, {
      useBinaryFormat: true,
      securityLevel: "high",
      compressionLevel: "medium",
      layers: 2
    });
    
    console.log("✅ Binary format encryption successful!");
    console.log(`File saved to: ${binaryResult.filePath}`);
    console.log(`Original size: ${binaryResult.originalSize} bytes`);
    console.log(`Encrypted size: ${binaryResult.encryptedSize} bytes`);
    console.log(`Compression ratio: ${binaryResult.compressionRatio?.toFixed(2) || 'N/A'}`);
    console.log(`RSA key size used: ${binaryResult.rsaKeyPair ? 'Generated' : 'None'}`);
    
    // Verify file exists
    if (!fs.existsSync(binaryResult.filePath)) {
      throw new Error(`Encrypted file not found: ${binaryResult.filePath}`);
    }
    
    const fileSize = fs.statSync(binaryResult.filePath).size;
    console.log(`File exists on disk: ${fileSize} bytes`);
    
    // Step 5: Test binary format decryption
    console.log("\n--- Step 5: Binary Format Decryption ---");
    
    // Add a delay to ensure file operations are complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log("Attempting to decrypt binary data...");
    console.log("Using encryption key:", binaryResult.encryptionKeyHex.substring(0, 16) + "...");
    console.log("Using RSA key pair:", binaryResult.rsaKeyPair ? "YES" : "NO");
    
    if (!binaryResult.rsaKeyPair) {
      throw new Error("RSA key pair is required for binary format decryption");
    }
    
    try {
      const binaryDecryptedBuffer = await decryptData(
        binaryResult.filePath,
        binaryResult.encryptionKeyHex,
        binaryResult.rsaKeyPair,
        false, // not ultra secure
        true   // is binary format
      );
      // Always deserialize decrypted Buffer back to original data
      const binaryDecrypted = JSON.parse(binaryDecryptedBuffer.toString());
      
      console.log("✅ Binary format decryption successful!");
      console.log("Decrypted data:", JSON.stringify(binaryDecrypted));
      
      // Verify data integrity
      const originalJson = JSON.stringify(data);
      const decryptedJson = JSON.stringify(binaryDecrypted);
      const dataMatches = originalJson === decryptedJson;
      
      console.log("Data integrity check:", dataMatches ? "PASSED ✅" : "FAILED ❌");
      
      if (!dataMatches) {
        console.log("Original :", originalJson);
        console.log("Decrypted:", decryptedJson);
      }
      
      return dataMatches;
      
    } catch (decryptError) {
      console.error("❌ Binary format decryption failed:", decryptError);
      console.error("Error details:", decryptError.message);
      console.error("Stack trace:", decryptError.stack);
      return false;
    }
    
  } catch (error) {
    console.error("❌ Binary test failed:", error);
    console.error("Error details:", error.message);
    console.error("Stack trace:", error.stack);
    return false;
  }
}

// Run the test
runBinaryOnlyTest()
  .then(success => {
    console.log("\n=== FINAL RESULT ===");
    console.log("Binary Format Test:", success ? "PASSED ✅" : "FAILED ❌");
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
