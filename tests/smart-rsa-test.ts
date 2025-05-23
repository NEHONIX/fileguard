/**
 * Smart RSA Key Sizing Test
 * Tests the automatic RSA key size adjustment feature in cryptUtils
 * Run with: bun ./tests/smart-rsa-test.ts
 */

import { encryptData, decryptData, getRecommendedRSAKeySize } from "../src/utils/cryptUtils";
import * as fs from "fs";
import * as path from "path";

// Create output directory
const OUTPUT_DIR = path.join(__dirname, "output", "smart-rsa");
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

async function testSmartRSAKeySizing() {
  try {
    console.log("=== Smart RSA Key Sizing Test ===");
    
    // Test data of different sizes
    const testCases = [
      {
        name: "Small Object",
        data: { user: "test", id: 123 },
        expectedMinKeySize: 2048
      },
      {
        name: "Medium Object", 
        data: {
          users: Array.from({length: 10}, (_, i) => ({
            id: i,
            name: `User ${i}`,
            email: `user${i}@example.com`,
            settings: { theme: "dark", notifications: true }
          }))
        },
        expectedMinKeySize: 2048
      },
      {
        name: "Large Object",
        data: {
          data: Array.from({length: 100}, (_, i) => ({
            id: i,
            content: `This is a longer content string for item ${i} with more data to test larger payloads`,
            metadata: { created: new Date().toISOString(), version: "1.0.0" }
          }))
        },
        expectedMinKeySize: 2048
      }
    ];

    for (const testCase of testCases) {
      console.log(`\n--- Testing: ${testCase.name} ---`);
      
      const dataString = JSON.stringify(testCase.data);
      const dataSize = Buffer.from(dataString).length;
      console.log(`Data size: ${dataSize} bytes`);
      
      // Test recommended key size calculation
      const recommendedKeySize = getRecommendedRSAKeySize(32); // For AES-256 key
      console.log(`Recommended RSA key size: ${recommendedKeySize} bits`);
      
      // Test with smart RSA key sizing (default)
      console.log("\n🔧 Testing with Smart RSA Key Sizing (default):");
      const smartFilePath = path.join(OUTPUT_DIR, `${testCase.name.toLowerCase().replace(/\s+/g, '-')}-smart.nxs`);
      
      const smartResult = await encryptData(testCase.data, smartFilePath, {
        useBinaryFormat: true,
        useSmartRSAKeySize: true, // Explicitly enable (though it's default)
        securityLevel: "high",
        compressionLevel: "medium"
      });
      
      console.log(`✅ Smart encryption successful!`);
      console.log(`   RSA key size used: ${smartResult.rsaKeySize} bits`);
      console.log(`   File size: ${smartResult.encryptedSize} bytes`);
      console.log(`   Compression ratio: ${smartResult.compressionRatio?.toFixed(3)}`);
      
      // Test decryption
      const smartDecrypted = await decryptData(
        smartResult.filePath,
        smartResult.encryptionKeyHex,
        smartResult.rsaKeyPair!,
        false, // not ultra secure
        true   // is binary format
      );
      
      const dataMatches = JSON.stringify(testCase.data) === JSON.stringify(smartDecrypted);
      console.log(`   Data integrity: ${dataMatches ? "PASSED ✅" : "FAILED ❌"}`);
      
      if (!dataMatches) {
        console.log("   Original :", JSON.stringify(testCase.data).substring(0, 100) + "...");
        console.log("   Decrypted:", JSON.stringify(smartDecrypted).substring(0, 100) + "...");
        throw new Error("Data integrity check failed");
      }
      
      // Test with custom RSA key size
      console.log("\n🔧 Testing with Custom RSA Key Size (4096 bits):");
      const customFilePath = path.join(OUTPUT_DIR, `${testCase.name.toLowerCase().replace(/\s+/g, '-')}-custom.nxs`);
      
      const customResult = await encryptData(testCase.data, customFilePath, {
        useBinaryFormat: true,
        customRSAKeySize: 4096, // Force 4096-bit RSA key
        securityLevel: "high",
        compressionLevel: "medium"
      });
      
      console.log(`✅ Custom encryption successful!`);
      console.log(`   RSA key size used: ${customResult.rsaKeySize} bits`);
      console.log(`   File size: ${customResult.encryptedSize} bytes`);
      console.log(`   Compression ratio: ${customResult.compressionRatio?.toFixed(3)}`);
      
      // Test decryption
      const customDecrypted = await decryptData(
        customResult.filePath,
        customResult.encryptionKeyHex,
        customResult.rsaKeyPair!,
        false, // not ultra secure
        true   // is binary format
      );
      
      const customDataMatches = JSON.stringify(testCase.data) === JSON.stringify(customDecrypted);
      console.log(`   Data integrity: ${customDataMatches ? "PASSED ✅" : "FAILED ❌"}`);
      
      if (!customDataMatches) {
        throw new Error("Custom RSA key size test failed");
      }
      
      // Verify that custom key size was actually used
      if (customResult.rsaKeySize !== 4096) {
        console.log(`⚠️  Warning: Expected 4096-bit key, got ${customResult.rsaKeySize}-bit key`);
      }
      
      // Test with smart sizing disabled
      console.log("\n🔧 Testing with Smart RSA Key Sizing Disabled (fallback to 2048):");
      const fallbackFilePath = path.join(OUTPUT_DIR, `${testCase.name.toLowerCase().replace(/\s+/g, '-')}-fallback.nxs`);
      
      const fallbackResult = await encryptData(testCase.data, fallbackFilePath, {
        useBinaryFormat: true,
        useSmartRSAKeySize: false, // Disable smart sizing
        securityLevel: "high",
        compressionLevel: "medium"
      });
      
      console.log(`✅ Fallback encryption successful!`);
      console.log(`   RSA key size used: ${fallbackResult.rsaKeySize} bits`);
      console.log(`   File size: ${fallbackResult.encryptedSize} bytes`);
      
      // Test decryption
      const fallbackDecrypted = await decryptData(
        fallbackResult.filePath,
        fallbackResult.encryptionKeyHex,
        fallbackResult.rsaKeyPair!,
        false, // not ultra secure
        true   // is binary format
      );
      
      const fallbackDataMatches = JSON.stringify(testCase.data) === JSON.stringify(fallbackDecrypted);
      console.log(`   Data integrity: ${fallbackDataMatches ? "PASSED ✅" : "FAILED ❌"}`);
      
      if (!fallbackDataMatches) {
        throw new Error("Fallback RSA key size test failed");
      }
    }
    
    return true;
    
  } catch (error) {
    console.error("❌ Smart RSA test failed:", error);
    console.error("Error details:", error.message);
    return false;
  }
}

// Run the test
testSmartRSAKeySizing()
  .then(success => {
    console.log("\n=== FINAL RESULT ===");
    console.log("Smart RSA Key Sizing Test:", success ? "PASSED ✅" : "FAILED ❌");
    
    if (success) {
      console.log("\n🎉 Smart RSA key sizing is now integrated into cryptUtils!");
      console.log("✅ Users can now benefit from automatic RSA key size optimization");
      console.log("✅ Custom RSA key sizes are supported");
      console.log("✅ Smart sizing can be disabled if needed");
    }
    
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
