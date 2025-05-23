/**
 * Debug test for encryption/decryption
 * Run with: bun ./tests/debug-test.ts
 */

import { decryptData, encryptData } from "../src/utils/cryptUtils";
import * as fs from "fs";
import * as path from "path";

// Create output directory
const OUTPUT_DIR = path.join(__dirname, "output", "debug");
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Test data
const data = [{ user: "test3" }, "p1", 2, 0x204];

async function runDebugTest() {
  try {
    console.log("Starting debug test...");
    console.log("Test data:", JSON.stringify(data));

    // Test 1: Standard Encryption
    console.log("\n=== Test 1: Standard Encryption ===");
    const standardFilePath = path.join(OUTPUT_DIR, "standard.nxs");

    console.log("Encrypting data with standard encryption...");
    const standardResult = await encryptData(data, standardFilePath, {
      securityLevel: "high",
      compressionLevel: "medium",
      layers: 2,
      useAlgorithmRotation: false,
      addHoneypots: true,
    });

    console.log("Standard encryption successful!");
    console.log(`File saved to: ${standardResult.filePath}`);
    console.log(`Original size: ${standardResult.originalSize} bytes`);
    console.log(`Encrypted size: ${standardResult.encryptedSize} bytes`);

    // Add a small delay to ensure file system operations are complete
    await new Promise((resolve) => setTimeout(resolve, 1000));

    console.log("\nDecrypting data...");
    const standardDecrypted = await decryptData(
      standardResult.filePath,
      standardResult.encryptionKeyHex,
      standardResult.rsaKeyPair!
    );

    console.log("Standard decryption successful!");
    console.log("Decrypted data:", JSON.stringify(standardDecrypted));
    console.log(
      "Data integrity check:",
      JSON.stringify(data) === JSON.stringify(standardDecrypted)
        ? "PASSED ✓"
        : "FAILED ✗"
    );

    // Test 2: Binary Format
    console.log("\n=== Test 2: Binary Format ===");
    const binaryFilePath = path.join(OUTPUT_DIR, "binary.nxs");

    try {
      console.log("Encrypting data with binary format...");
      const binaryResult = await encryptData(data, binaryFilePath, {
        useBinaryFormat: true,
        securityLevel: "high",
        compressionLevel: "medium",
        layers: 2,
      });

      console.log("Binary format encryption successful!");
      console.log(`File saved to: ${binaryResult.filePath}`);
      console.log(`Original size: ${binaryResult.originalSize} bytes`);
      console.log(`Encrypted size: ${binaryResult.encryptedSize} bytes`);

      // Add a small delay to ensure file system operations are complete
      await new Promise((resolve) => setTimeout(resolve, 1000));

      console.log("\nDecrypting binary data...");
      const binaryDecrypted = await decryptData(
        binaryResult.filePath,
        binaryResult.encryptionKeyHex,
        binaryResult.rsaKeyPair!,
        false, // not ultra secure
        true // is binary format
      );

      console.log("Binary format decryption successful!");
      console.log("Decrypted data:", JSON.stringify(binaryDecrypted));
      console.log(
        "Data integrity check:",
        JSON.stringify(data) === JSON.stringify(binaryDecrypted)
          ? "PASSED ✓"
          : "FAILED ✗"
      );
    } catch (error) {
      console.error("Binary format test failed:", error);
      console.error("Binary format error stack:", error.stack);
    }

    console.log("\n=== Debug test completed! ===");
  } catch (error) {
    console.error("Debug test failed:", error);
    console.error("Stack trace:", error.stack);
  }
}

runDebugTest();
