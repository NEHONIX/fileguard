/**
 * Fortify integration utilities for NEHONIX FileGuard
 * Provides integration with the Fortify security library
 */

import * as crypto from "crypto";
import * as zlib from "zlib";
import {
  SecurityLevel,
  CompressionLevel,
  AdvancedEncryptionConfig,
  FortifyEncryptionOptions,
  FortifyEncryptionResult,
  FortifySecurityParams,
} from "../types";
import { logger } from "./logger";
import { ProgressTracker, OperationType } from "./progress";

// Import Fortify utilities
import { Random, SecureRandom } from "fortify2-js";
import { argon2Derive, balloonDerive } from "fortify2-js";
import {
  lamportGenerateKeypair,
  lamportSign,
  lamportVerify,
  generateKyberKeyPair,
  kyberEncapsulate,
  kyberDecapsulate,
} from "fortify2-js";

/**
 * Convert standard security level to Fortify security level
 * @param level - Standard security level
 * @returns Fortify security level
 */
export function toFortifySecurityLevel(level: SecurityLevel): number {
  switch (level) {
    case "standard":
      return 1;
    case "high":
      return 3;
    case "max":
      return 5;
    default:
      return 3;
  }
}

/**
 * Generate secure encryption parameters using Fortify
 * @param key - Master encryption key
 * @param securityLevel - Security level
 * @returns Secure encryption parameters
 */
export function generateSecureParams(
  key: Buffer,
  securityLevel: SecurityLevel
): FortifySecurityParams {
  // Generate a secure salt
  const salt = Buffer.from(SecureRandom.getRandomBytes(16));

  // Generate a secure IV
  const iv = Buffer.from(SecureRandom.getRandomBytes(16));

  // Generate additional authenticated data
  const aad = Buffer.from(SecureRandom.getRandomBytes(32));

  // For maximum security, generate a post-quantum key pair
  let postQuantumKeyPair = undefined;

  if (securityLevel === "max") {
    try {
      // Generate a Kyber key pair for post-quantum security
      const kyberKeyPair = generateKyberKeyPair({
        securityLevel: toFortifySecurityLevel(securityLevel),
      });

      postQuantumKeyPair = {
        publicKey: kyberKeyPair.publicKey,
        privateKey: kyberKeyPair.privateKey,
      };

      logger.debug("Generated post-quantum key pair for maximum security");
    } catch (error) {
      logger.warn(
        "Failed to generate post-quantum key pair, falling back to standard encryption",
        error
      );
    }
  }

  return {
    key,
    salt,
    iv,
    aad,
    postQuantumKeyPair,
  };
}

/**
 * Derive a key using memory-hard key derivation
 * @param password - Password or key
 * @param salt - Salt
 * @param options - Key derivation options
 * @returns Derived key
 */
export async function deriveSecureKey(
  password: string | Buffer,
  salt: Buffer,
  options: {
    memoryCost?: number;
    timeCost?: number;
    keyLength?: number;
  } = {}
): Promise<Buffer> {
  const startTime = Date.now();

  // Convert password to string if it's a buffer
  const passwordStr = Buffer.isBuffer(password)
    ? password.toString("hex")
    : password;

  // Set default options
  const memoryCost = options.memoryCost || 16384; // 16 MB
  const timeCost = options.timeCost || 4;
  const keyLength = options.keyLength || 32;

  try {
    // Use Argon2 for memory-hard key derivation
    const result = await argon2Derive(passwordStr, {
      memoryCost,
      timeCost,
      parallelism: 1,
      keyLength,
      salt: new Uint8Array(salt),
    });

    logger.debug(
      `Key derived using Argon2 (${result.metrics.timeTakenMs}ms, ${result.metrics.memoryUsedBytes} bytes)`
    );

    return Buffer.from(result.derivedKey, "hex");
  } catch (error) {
    logger.warn("Argon2 key derivation failed, falling back to Balloon", error);

    // Fallback to Balloon
    const result = balloonDerive(passwordStr, {
      memoryCost,
      timeCost,
      parallelism: 1,
      keyLength,
      salt: new Uint8Array(salt),
    });

    logger.debug(
      `Key derived using Balloon (${result.metrics.timeTakenMs}ms, ${result.metrics.memoryUsedBytes} bytes)`
    );

    return Buffer.from(result.derivedKey, "hex");
  }
}

/**
 * Encrypt data using Fortify security
 * @param data - Data to encrypt
 * @param params - Security parameters
 * @param options - Encryption options
 * @returns Encrypted data and metadata
 */
export async function encryptWithFortify(
  data: Buffer | string,
  params: FortifySecurityParams,
  options: FortifyEncryptionOptions
): Promise<FortifyEncryptionResult> {
  const startTime = Date.now();
  const operationId = crypto.randomBytes(8).toString("hex");

  // Start tracking the encryption operation
  ProgressTracker.startOperation(
    OperationType.Encryption,
    operationId,
    options.layers || 3
  );

  try {
    // Convert data to buffer if it's a string
    const dataBuffer = typeof data === "string" ? Buffer.from(data) : data;

    // Step 1: Compress data if compression is enabled
    ProgressTracker.updateProgress(operationId, 10, "Compressing data...");
    let processedData = dataBuffer;

    if (options.compressionLevel !== "none") {
      processedData = await compressData(dataBuffer, options.compressionLevel);
      ProgressTracker.updateProgress(operationId, 20, "Data compressed");
    }

    // Step 2: Derive a secure key if memory-hard KDF is enabled
    ProgressTracker.updateProgress(operationId, 30, "Deriving secure key...");
    let encryptionKey = params.key;

    if (options.useMemoryHardKDF && params.salt) {
      encryptionKey = await deriveSecureKey(params.key, params.salt, {
        memoryCost: options.memoryCost,
        timeCost: options.timeCost,
        keyLength: 32,
      });

      ProgressTracker.updateProgress(operationId, 40, "Secure key derived");
    }

    // Step 3: Encrypt the data with multiple layers
    ProgressTracker.nextStep(operationId, "Encrypting data...");

    // Determine number of layers based on security level
    const layers = options.layers || getDefaultLayers(options.securityLevel);

    // Track algorithms used
    const algorithms: string[] = [];

    // Apply multiple encryption layers
    let currentData = processedData;

    for (let i = 0; i < layers; i++) {
      ProgressTracker.updateProgress(
        operationId,
        40 + Math.floor(((i + 1) / layers) * 40),
        `Applying encryption layer ${i + 1}/${layers}...`
      );

      // Use different algorithms for each layer if rotation is enabled
      const algorithm = options.useAlgorithmRotation
        ? getAlgorithmForLayer(i, layers)
        : "aes-256-gcm";

      algorithms.push(algorithm);

      // Derive a unique key for this layer
      const layerKey = deriveLayerKey(encryptionKey, i, algorithm);

      // Generate initialization vector
      const iv = params.iv || crypto.randomBytes(16);

      // Create cipher
      const cipher = crypto.createCipheriv(algorithm, layerKey, iv);

      // Add authentication data if using GCM mode
      if (algorithm.endsWith("-gcm") && params.aad) {
        (cipher as any).setAAD(params.aad);
      }

      // Encrypt data
      let encrypted = Buffer.concat([
        cipher.update(currentData),
        cipher.final(),
      ]);

      // Get auth tag if using GCM mode
      let authTag: Buffer | undefined;
      if (algorithm.endsWith("-gcm")) {
        authTag = (cipher as any).getAuthTag();
      }

      // Prepare for next layer
      const layerData = {
        algorithm,
        iv: iv.toString("base64"),
        authTag: authTag ? authTag.toString("base64") : undefined,
        data: encrypted.toString("base64"),
        layer: i,
      };

      currentData = Buffer.from(JSON.stringify(layerData));
    }

    // Step 4: Add post-quantum encryption if enabled
    ProgressTracker.updateProgress(operationId, 80, "Finalizing encryption...");

    if (options.usePostQuantum && params.postQuantumKeyPair) {
      try {
        // Use Kyber for post-quantum key encapsulation
        const encapsulation = kyberEncapsulate(
          params.postQuantumKeyPair.publicKey,
          { securityLevel: toFortifySecurityLevel(options.securityLevel) }
        );

        // Use the shared secret to encrypt the data with AES
        const sharedSecret = Buffer.from(encapsulation.sharedSecret, "hex");
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv("aes-256-gcm", sharedSecret, iv);

        // Encrypt the data
        const encrypted = Buffer.concat([
          cipher.update(currentData),
          cipher.final(),
        ]);

        // Get the auth tag
        const authTag = (cipher as any).getAuthTag();

        // Create the final encrypted data
        const pqData = {
          type: "post-quantum",
          algorithm: "kyber+aes-256-gcm",
          ciphertext: encapsulation.ciphertext,
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64"),
          data: encrypted.toString("base64"),
        };

        currentData = Buffer.from(JSON.stringify(pqData));
        algorithms.push("kyber+aes-256-gcm");

        logger.debug("Applied post-quantum encryption layer");
      } catch (error) {
        logger.warn(
          "Post-quantum encryption failed, using standard encryption",
          error
        );
      }
    }

    // Step 5: Add honeypots if enabled
    if (options.addHoneypots) {
      currentData = addHoneypots(currentData);
      logger.debug("Added honeypots to encrypted data");
    }

    // Complete the operation
    const endTime = Date.now();
    const encryptionTimeMs = endTime - startTime;

    ProgressTracker.completeOperation(
      operationId,
      "Data encrypted successfully"
    );

    return {
      data: currentData,
      metadata: {
        algorithms,
        postQuantum: options.usePostQuantum,
        memoryHardKDF: options.useMemoryHardKDF,
        kdfParams: options.useMemoryHardKDF
          ? {
              memoryCost: options.memoryCost || 16384,
              timeCost: options.timeCost || 4,
              parallelism: 1,
            }
          : undefined,
        encryptionTimeMs,
      },
    };
  } catch (error) {
    // Handle errors
    ProgressTracker.failOperation(
      operationId,
      `Encryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );

    logger.error("Encryption failed", error);
    throw error;
  }
}

/**
 * Decrypt data encrypted with Fortify
 * @param encryptedData - Encrypted data
 * @param params - Security parameters
 * @param options - Decryption options
 * @returns Decrypted data
 */
export async function decryptWithFortify(
  encryptedData: Buffer,
  params: FortifySecurityParams,
  options: FortifyEncryptionOptions
): Promise<Buffer> {
  const operationId = crypto.randomBytes(8).toString("hex");

  // Start tracking the decryption operation
  ProgressTracker.startOperation(
    OperationType.Decryption,
    operationId,
    options.layers || 3
  );

  try {
    // Step 1: Derive a secure key if memory-hard KDF is enabled
    ProgressTracker.updateProgress(operationId, 10, "Deriving secure key...");
    let decryptionKey = params.key;

    if (options.useMemoryHardKDF && params.salt) {
      decryptionKey = await deriveSecureKey(params.key, params.salt, {
        memoryCost: options.memoryCost,
        timeCost: options.timeCost,
        keyLength: 32,
      });

      ProgressTracker.updateProgress(operationId, 20, "Secure key derived");
    }

    // Step 2: Remove honeypots if present
    ProgressTracker.updateProgress(
      operationId,
      30,
      "Processing encrypted data..."
    );
    let currentData = removeHoneypots(encryptedData);

    // Step 3: Check for post-quantum encryption
    let parsedData: any;

    try {
      parsedData = JSON.parse(currentData.toString());
    } catch (e) {
      throw new Error("Invalid encrypted data format");
    }

    if (parsedData.type === "post-quantum" && params.postQuantumKeyPair) {
      ProgressTracker.updateProgress(
        operationId,
        40,
        "Decrypting post-quantum layer..."
      );

      try {
        // Decapsulate the shared secret using Kyber
        const decapsulation = kyberDecapsulate(
          params.postQuantumKeyPair.privateKey,
          parsedData.ciphertext,
          { securityLevel: toFortifySecurityLevel(options.securityLevel) }
        );

        // Use the shared secret to decrypt the data
        const sharedSecret = Buffer.from(decapsulation.sharedSecret, "hex");
        const iv = Buffer.from(parsedData.iv, "base64");
        const authTag = Buffer.from(parsedData.authTag, "base64");
        const encryptedContent = Buffer.from(parsedData.data, "base64");

        // Create decipher
        const decipher = crypto.createDecipheriv(
          "aes-256-gcm",
          sharedSecret,
          iv
        );
        (decipher as any).setAuthTag(authTag);

        // Decrypt the data
        const decrypted = Buffer.concat([
          decipher.update(encryptedContent),
          decipher.final(),
        ]);

        currentData = decrypted;
        logger.debug("Decrypted post-quantum layer");
      } catch (error) {
        logger.error("Post-quantum decryption failed", error);
        throw new Error("Post-quantum decryption failed");
      }
    }

    // Step 4: Decrypt multiple layers
    ProgressTracker.nextStep(operationId, "Decrypting layers...");

    // Determine number of layers based on security level
    const layers = options.layers || getDefaultLayers(options.securityLevel);

    for (let i = layers - 1; i >= 0; i--) {
      ProgressTracker.updateProgress(
        operationId,
        50 + Math.floor(((layers - i) / layers) * 30),
        `Decrypting layer ${layers - i}/${layers}...`
      );

      try {
        // Parse the layer data
        const layerData = JSON.parse(currentData.toString());

        // Extract encryption parameters
        const { algorithm, iv, authTag, data } = layerData;

        // Derive the layer key
        const layerKey = deriveLayerKey(decryptionKey, i, algorithm);

        // Create decipher
        const decipher = crypto.createDecipheriv(
          algorithm,
          layerKey,
          Buffer.from(iv, "base64")
        );

        // Set auth tag if using GCM mode
        if (algorithm.endsWith("-gcm") && authTag) {
          (decipher as any).setAuthTag(Buffer.from(authTag, "base64"));

          if (params.aad) {
            (decipher as any).setAAD(params.aad);
          }
        }

        // Decrypt data
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(data, "base64")),
          decipher.final(),
        ]);

        // Prepare for next layer
        currentData = decrypted;
      } catch (error) {
        logger.error(`Error decrypting layer ${i}`, error);
        throw new Error(`Decryption failed at layer ${i}`);
      }
    }

    // Step 5: Decompress if needed
    if (options.compressionLevel !== "none") {
      ProgressTracker.nextStep(operationId, "Decompressing data...");
      currentData = await decompressData(currentData);
    }

    // Complete the operation
    ProgressTracker.completeOperation(
      operationId,
      "Data decrypted successfully"
    );

    return currentData;
  } catch (error) {
    // Handle errors
    ProgressTracker.failOperation(
      operationId,
      `Decryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );

    logger.error("Decryption failed", error);
    throw error;
  }
}

/**
 * Compress data using the specified compression level
 * @param data - Data to compress
 * @param level - Compression level
 * @returns Promise resolving to compressed data
 */
async function compressData(
  data: Buffer,
  level: CompressionLevel
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const options: zlib.ZlibOptions = {
      level: getZlibCompressionLevel(level),
    };

    zlib.deflate(data, options, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer);
      }
    });
  });
}

/**
 * Decompress data
 * @param data - Compressed data
 * @returns Promise resolving to decompressed data
 */
async function decompressData(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zlib.inflate(data, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

/**
 * Convert compression level to zlib level
 * @param level - Compression level
 * @returns zlib compression level
 */
function getZlibCompressionLevel(level: CompressionLevel): number {
  switch (level) {
    case "none":
      return 0;
    case "low":
      return 3;
    case "medium":
      return 6;
    case "high":
      return 8;
    case "maximum":
      return 9;
    default:
      return 6;
  }
}

/**
 * Get default number of encryption layers based on security level
 * @param level - Security level
 * @returns Number of layers
 */
function getDefaultLayers(level: SecurityLevel): number {
  switch (level) {
    case "standard":
      return 1;
    case "high":
      return 3;
    case "max":
      return 5;
    default:
      return 3;
  }
}

/**
 * Get encryption algorithm for a specific layer
 * @param layerIndex - Layer index
 * @param totalLayers - Total number of layers
 * @returns Encryption algorithm
 */
function getAlgorithmForLayer(layerIndex: number, totalLayers: number): string {
  // Rotate between different algorithms for better security
  const algorithms = [
    "aes-256-gcm",
    "aes-256-cbc",
    "aes-256-ctr",
    "camellia-256-cbc",
    "aria-256-gcm",
  ];

  return algorithms[layerIndex % algorithms.length];
}

/**
 * Derive a unique key for each encryption layer
 * @param masterKey - Master key
 * @param layerIndex - Layer index
 * @param algorithm - Encryption algorithm
 * @returns Derived key
 */
function deriveLayerKey(
  masterKey: Buffer,
  layerIndex: number,
  algorithm: string
): Buffer {
  // Create a unique salt for this layer
  const salt = Buffer.from(`nehonix-layer-${layerIndex}-${algorithm}`);

  // Derive key using PBKDF2
  return crypto.pbkdf2Sync(masterKey, salt, 10000, 32, "sha512");
}

/**
 * Add honeypots to encrypted data
 * @param data - Encrypted data
 * @returns Data with honeypots
 */
function addHoneypots(data: Buffer): Buffer {
  try {
    // Parse the data
    const parsed = JSON.parse(data.toString());

    // Add honeypot fields that look like real data
    parsed.honeypot1 = Random.getRandomBytes(32).toString("base64");
    parsed.decryptionKey = crypto.randomBytes(16).toString("base64");
    parsed._meta = {
      timestamp: Date.now(),
      version: "1.0.0",
      checksum: crypto.createHash("sha256").update(data).digest("hex"),
    };

    return Buffer.from(JSON.stringify(parsed));
  } catch (e) {
    // If parsing fails, return original data
    return data;
  }
}

/**
 * Remove honeypots from encrypted data
 * @param data - Data with honeypots
 * @returns Clean data
 */
function removeHoneypots(data: Buffer): Buffer {
  try {
    // Parse the data
    const parsed = JSON.parse(data.toString());

    // Remove known honeypot fields
    delete parsed.honeypot1;
    delete parsed.decryptionKey;
    delete parsed._meta;

    return Buffer.from(JSON.stringify(parsed));
  } catch (e) {
    // If parsing fails, return original data
    return data;
  }
}
