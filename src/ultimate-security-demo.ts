/**
 * Ultimate Security Demo for NEHONIX FileGuard
 *
 * This demo showcases the most secure encryption capabilities available,
 * making data completely unreadable by humans or other systems except
 * by the FileGuardManager class itself.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import {
  createPersistentRSAFGM,
  logger,
  ProgressTracker,
  OperationType,
} from "./index";
import { generateSecureParams } from "./utils/fortifyIntegration";
import { FortifyJS as fty } from "fortify2-js";

// Define the extended FileGuardManager type with rsaKeyPair
interface ExtendedFileGuardManager {
  saveWithAdvancedEncryption: Function;
  loadWithAdvancedDecryption: Function;
  saveWithUltraSecureEncryption: Function;
  loadWithUltraSecureDecryption: Function;
  rsaKeyPair: { publicKey: string; privateKey: string };
}

// Set log level to debug for detailed output
logger.setLogLevel("debug");

// Demo configuration
const DEMO_DIR = path.resolve("./ultimate-security-demo");
const DEMO_FILE = path.join(DEMO_DIR, "ultimate-secure.nxs");
const RSA_KEYS_PATH = path.join(DEMO_DIR, "ultimate-secure-rsa-keys.json");

// Ensure we're using absolute paths
console.log(`Demo directory: ${DEMO_DIR}`);
console.log(`Demo file: ${DEMO_FILE}`);
console.log(`RSA keys path: ${RSA_KEYS_PATH}`);

/**
 * Run the ultimate security demo
 */
async function runUltimateSecurityDemo() {
  console.log("\n🔒🔒🔒 NEHONIX FileGuard ULTIMATE SECURITY DEMO 🔒🔒🔒\n");

  // Create demo directory if it doesn't exist
  if (!fs.existsSync(DEMO_DIR)) {
    fs.mkdirSync(DEMO_DIR, { recursive: true });
  }

  // Generate a cryptographically secure encryption key
  const key = crypto.randomBytes(1024);
  console.log(
    `Generated ultra-secure encryption key: ${key}
   `
  );

  // Create a FileGuardManager with persistent RSA keys
  console.log("\n📝 Creating FileGuardManager with persistent RSA keys...");
  const fgm = createPersistentRSAFGM(key.toString("hex"), {
    rsaKeysPath: RSA_KEYS_PATH,
  });

  // Generate sample data of different types
  const sampleData = generateSampleData();

  // Demonstrate encryption with different security levels
  await demonstrateSecurityLevels(fgm, key, sampleData);

  // Demonstrate ultra-secure encryption with maximum protection
  await demonstrateUltraSecureEncryption(fgm, key, sampleData.sensitiveData);

  // Demonstrate binary data encryption
  await demonstrateBinaryEncryption(fgm, key);

  // Demonstrate security features
  demonstrateSecurityFeatures(key);

  console.log("\n✅ Ultimate Security Demo completed successfully!");
}

/**
 * Generate sample data for encryption
 */
function generateSampleData() {
  return {
    basicData: {
      title: "Basic Document",
      content: "This is standard content with basic protection needs.",
      created: new Date().toISOString(),
    },

    confidentialData: {
      title: "Confidential Document",
      content: "This content is confidential and requires strong protection.",
      metadata: {
        author: "Security Team",
        classification: "CONFIDENTIAL",
        created: new Date().toISOString(),
      },
    },

    sensitiveData: {
      title: "TOP SECRET - ULTRA SECURE",
      content:
        "This is extremely sensitive content that requires the highest possible security protection.",
      credentials: {
        username: "admin",
        apiKey: fty.generateAPIKey({ prefix: "nxs.api" }),
        accessToken: fty.generateSecureToken({
          length: 64,
          entropy: "maximum",
        }),
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
    },
  };
}

/**
 * Demonstrate encryption with different security levels
 */
async function demonstrateSecurityLevels(
  fgm: ExtendedFileGuardManager,
  key: any,
  sampleData: any
) {
  console.log("\n🔐 Demonstrating Different Security Levels");

  // Standard security level
  console.log("\n📊 STANDARD Security Level");
  const standardSecurityPath = path.join(DEMO_DIR, "standard-security.nxs");
  console.log(`Standard security file path: ${standardSecurityPath}`);
  await encryptAndDecrypt(
    fgm,
    key,
    sampleData.basicData,
    standardSecurityPath,
    {
      securityLevel: "standard",
      compressionLevel: "medium",
      layers: 1,
      useAlgorithmRotation: false,
      addHoneypots: false,
    }
  );

  // High security level
  console.log("\n📊 HIGH Security Level");
  const highSecurityPath = path.join(DEMO_DIR, "high-security.nxs");
  console.log(`High security file path: ${highSecurityPath}`);
  await encryptAndDecrypt(
    fgm,
    key,
    sampleData.confidentialData,
    highSecurityPath,
    {
      securityLevel: "high",
      compressionLevel: "high",
      layers: 3,
      useAlgorithmRotation: true,
      addHoneypots: false,
    }
  );
}

/**
 * Demonstrate ultra-secure encryption with maximum protection
 */
async function demonstrateUltraSecureEncryption(
  fgm: ExtendedFileGuardManager,
  key: any,
  data: any
) {
  console.log("\n🔐🔐🔐 ULTRA-SECURE Encryption (Maximum Protection)");

  // Configure encryption with maximum security
  const config = {
    securityLevel: "max" as "standard" | "high" | "max",
    encryptLevel: "max" as "standard" | "high" | "max",
    compressionLevel: "maximum" as
      | "none"
      | "low"
      | "medium"
      | "high"
      | "maximum",
    layers: 5,
    useAlgorithmRotation: true,
    addHoneypots: true,
  };

  console.log(`\nConfiguration: ${JSON.stringify(config, null, 2)}`);

  // Encrypt the data with ultra-secure protection
  console.log("\nStep 1: Encrypting with ultra-secure protection...");
  const encryptResult = await fgm.saveWithUltraSecureEncryption(
    DEMO_FILE,
    data,
    key,
    fgm.rsaKeyPair,
    config
  );

  console.log(`\nEncryption result: ${JSON.stringify(encryptResult, null, 2)}`);

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

  // Decrypt the data with ultra-secure decryption
  console.log("\nStep 2: Decrypting with ultra-secure protection...");
  const decryptedData = await fgm.loadWithUltraSecureDecryption(
    DEMO_FILE,
    key,
    fgm.rsaKeyPair
  );

  // Verify decryption was successful
  const isSuccessful = JSON.stringify(decryptedData) === JSON.stringify(data);
  console.log(`\nDecryption successful: ${isSuccessful}`);

  if (isSuccessful) {
    console.log("\nDecrypted data:");
    console.log(JSON.stringify(decryptedData, null, 2));
  }
}

/**
 * Demonstrate binary data encryption
 */
async function demonstrateBinaryEncryption(
  fgm: ExtendedFileGuardManager,
  key: any
) {
  console.log("\n🔐 Binary Data Encryption Demo");

  // Create binary data (simulating an image or document)
  const binaryData = Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG header
    fty.createSecureBuffer(1024).getBuffer(), // Random data
  ]);

  // Configure encryption with maximum security
  const config = {
    securityLevel: "max" as "standard" | "high" | "max",
    compressionLevel: "medium" as
      | "none"
      | "low"
      | "medium"
      | "high"
      | "maximum",
    layers: 3,
    useAlgorithmRotation: true,
    addHoneypots: true,
  };

  const binaryFilePath = path.join(DEMO_DIR, "binary-data.nxs");
  console.log(`Binary file path: ${binaryFilePath}`);

  // Encrypt the binary data
  console.log("Encrypting binary data...");
  await fgm.saveWithUltraSecureEncryption(
    binaryFilePath,
    binaryData,
    key,
    fgm.rsaKeyPair,
    config
  );

  // Decrypt the binary data
  console.log("Decrypting binary data...");
  const decryptedBinary = await fgm.loadWithUltraSecureDecryption(
    binaryFilePath,
    key,
    fgm.rsaKeyPair
  );

  // Verify the binary data matches
  const binaryMatches =
    Buffer.isBuffer(decryptedBinary) &&
    decryptedBinary.length === binaryData.length &&
    decryptedBinary.compare(binaryData) === 0;

  console.log(`Binary data encryption/decryption successful: ${binaryMatches}`);
}

/**
 * Helper function to encrypt and decrypt data
 */
async function encryptAndDecrypt(
  fgm: ExtendedFileGuardManager,
  key: any,
  data: any,
  filepath: string,
  config: any
) {
  console.log(`Encrypting with configuration: ${JSON.stringify(config)}`);

  // Encrypt the data
  const encryptResult = await fgm.saveWithAdvancedEncryption(
    filepath,
    data,
    key,
    fgm.rsaKeyPair,
    config
  );

  console.log(`Encryption result: ${JSON.stringify(encryptResult, null, 2)}`);

  // Decrypt the data
  const decryptedData = await fgm.loadWithAdvancedDecryption(
    filepath,
    key,
    fgm.rsaKeyPair
  );

  // Verify decryption was successful
  const isSuccessful = JSON.stringify(decryptedData) === JSON.stringify(data);
  console.log(`Decryption successful: ${isSuccessful}`);
}

/**
 * Demonstrate security features
 */
function demonstrateSecurityFeatures(key: any) {
  console.log("\n🛡️ Security Features Demonstration");

  // 1. Demonstrate secure parameters generation
  console.log("\n1. Secure Parameters Generation:");
  const secureParams = generateSecureParams(key, "max");
  console.log(
    `- Salt: ${
      secureParams.salt?.toString("hex").substring(0, 16) || "Not Generated"
    }...`
  );
  console.log(
    `- IV: ${
      secureParams.iv?.toString("hex").substring(0, 16) || "Not Generated"
    }...`
  );
  console.log(
    `- AAD: ${
      secureParams.aad?.toString("hex").substring(0, 16) || "Not Generated"
    }...`
  );
  console.log(
    `- Post-Quantum Key Pair: ${
      secureParams.postQuantumKeyPair ? "Generated" : "Not Generated"
    }`
  );

  // 2. Show security features
  console.log("\n2. Security Features Used:");
  console.log("- Multi-layer encryption (up to 5 layers)");
  console.log("- Algorithm rotation (different algorithm for each layer)");
  console.log("- Memory-hard key derivation (resistant to hardware attacks)");
  console.log("- Post-quantum cryptography (resistant to quantum computers)");
  console.log("- Honeypot data (to confuse attackers)");
  console.log("- Secure random number generation");
  console.log("- Tamper protection with integrity checks");
  console.log("- Secure memory handling");
}

// Run the demo
runUltimateSecurityDemo().catch((error) => {
  console.error("Demo failed:", error);
});
