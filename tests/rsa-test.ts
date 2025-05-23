/**
 * RSA encryption/decryption test
 * Run with: bun ./tests/rsa-test.ts
 */

import * as crypto from "crypto";

async function testRSA() {
  console.log("Testing RSA encryption/decryption...");
  
  // Generate RSA key pair
  const rsaKeyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  
  console.log("RSA key pair generated");
  console.log("Public key length:", rsaKeyPair.publicKey.length);
  console.log("Private key length:", rsaKeyPair.privateKey.length);
  
  // Test data (32-byte AES key)
  const aesKey = crypto.randomBytes(32);
  console.log("AES key to encrypt:", aesKey.toString("hex"));
  
  try {
    // Test PKCS1 padding
    console.log("\nTesting PKCS1 padding...");
    const encryptedPKCS1 = crypto.publicEncrypt(
      {
        key: rsaKeyPair.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      aesKey
    );
    
    console.log("PKCS1 encryption successful, encrypted length:", encryptedPKCS1.length);
    
    const decryptedPKCS1 = crypto.privateDecrypt(
      {
        key: rsaKeyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      encryptedPKCS1
    );
    
    console.log("PKCS1 decryption successful");
    console.log("Decrypted key:", decryptedPKCS1.toString("hex"));
    console.log("Keys match:", aesKey.equals(decryptedPKCS1) ? "YES ✓" : "NO ✗");
    
  } catch (error) {
    console.error("PKCS1 test failed:", error);
  }
  
  try {
    // Test OAEP padding
    console.log("\nTesting OAEP padding with SHA-256...");
    const encryptedOAEP = crypto.publicEncrypt(
      {
        key: rsaKeyPair.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKey
    );
    
    console.log("OAEP encryption successful, encrypted length:", encryptedOAEP.length);
    
    const decryptedOAEP = crypto.privateDecrypt(
      {
        key: rsaKeyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedOAEP
    );
    
    console.log("OAEP decryption successful");
    console.log("Decrypted key:", decryptedOAEP.toString("hex"));
    console.log("Keys match:", aesKey.equals(decryptedOAEP) ? "YES ✓" : "NO ✗");
    
  } catch (error) {
    console.error("OAEP test failed:", error);
  }
  
  console.log("\nRSA test completed!");
}

testRSA();
