/**
 * Test for SimpleBinaryFormat
 * Run with: bun ./tests/simple-binary-test.ts
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { SimpleBinaryFormat } from "../src/utils/simpleBinaryFormat";

// Create output directory
const OUTPUT_DIR = path.join(__dirname, "output", "simple-binary");
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Generate a random encryption key
const encryptionKey = crypto.randomBytes(32);
console.log("Encryption Key:", encryptionKey.toString("hex").substring(0, 10) + "...");

// Test data
const data = {
  test: 1,
  timestamp: new Date().toISOString(),
  message: "This is a test message for SimpleBinaryFormat encryption",
};
console.log("Test Data:", data);

// Test SimpleBinaryFormat
async function testSimpleBinaryFormat() {
  console.log("\n=== Testing SimpleBinaryFormat ===");
  const filePath = path.join(OUTPUT_DIR, "simple-binary.nxs");
  
  try {
    console.log("Encrypting data...");
    const result = await SimpleBinaryFormat.encrypt(
      data,
      encryptionKey,
      filePath,
      {
        compressionLevel: 6,
        addRandomPadding: true,
      }
    );
    
    console.log("Encryption successful!");
    console.log(`File saved to: ${result.filepath}`);
    console.log(`Original size: ${result.size.original} bytes`);
    console.log(`Encrypted size: ${result.size.encrypted} bytes`);
    
    // Wait for file system operations to complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify the file exists
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log(`\nFile exists at ${filePath}, size: ${fs.statSync(filePath).size} bytes`);
    
    console.log('\nDecrypting data...');
    const decryptedData = await SimpleBinaryFormat.decrypt(
      filePath,
      encryptionKey
    );
    
    console.log("Decryption successful!");
    console.log("Decrypted data:", decryptedData);
    
    // Verify data integrity
    const isEqual = JSON.stringify(data) === JSON.stringify(decryptedData);
    console.log(`\nData integrity check: ${isEqual ? "PASSED ✓" : "FAILED ✗"}`);
    
    return isEqual;
  } catch (error) {
    console.error("SimpleBinaryFormat test failed:", error);
    return false;
  }
}

// Run the test
testSimpleBinaryFormat()
  .then(success => {
    console.log("\nTest completed:", success ? "PASSED ✓" : "FAILED ✗");
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
