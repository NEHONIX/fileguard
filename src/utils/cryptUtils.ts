/**
 * Utility functions for simplified encryption and decryption operations
 * This module provides easy-to-use functions for encrypting and decrypting data
 * without requiring users to implement all the details themselves.
 */

import { FileGuardManager } from "../core/FileGuardManager";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { SecurityLevel, CompressionLevel, RSAKeyPair } from "../types";
import { SecureBuffer, Random } from "fortify2-js";
import { generateRSAKeyPairForData, calculateRSAKeySize } from "fortify2-js";

/**
 * Options for encryption operations
 */
export interface EncryptionOptions {
  /**
   * Security level for encryption (standard, high, max)
   * @default "high"
   */
  securityLevel?: SecurityLevel;

  /**
   * Compression level for encrypted data (none, low, medium, high, maximum)
   * @default "medium"
   */
  compressionLevel?: CompressionLevel;

  /**
   * Number of encryption layers
   * @default 2
   */
  layers?: number;

  /**
   * Whether to use algorithm rotation for enhanced security
   * @default false
   */
  useAlgorithmRotation?: boolean;

  /**
   * Whether to add honeypots to the encrypted data
   * @default false
   */
  addHoneypots?: boolean;

  /**
   * Whether to use ultra-secure encryption (uses more resources)
   * @default false
   */
  useUltraSecure?: boolean;

  /**
   * Whether to use binary format for encryption
   * @default false
   */
  useBinaryFormat?: boolean;

  /**
   * Custom metadata to include with the encrypted file
   */
  metadata?: Record<string, any>;

  /**
   * Whether to use automatic RSA key size adjustment based on data size
   * @default true
   */
  useSmartRSAKeySize?: boolean;

  /**
   * Custom RSA key size in bits (overrides smart sizing if specified)
   */
  customRSAKeySize?: number;
}

/**
 * Result of an encryption operation
 */
export interface SimplifiedEncryptionResult {
  /**
   * Path to the encrypted file
   */
  filePath: string;

  /**
   * Size of the original data in bytes
   */
  originalSize: number;

  /**
   * Size of the encrypted data in bytes
   */
  encryptedSize: number;

  /**
   * Compression ratio (original size / encrypted size)
   */
  compressionRatio?: number;

  /**
   * Encryption key used (hex string)
   */
  encryptionKeyHex: string;

  /**
   * RSA key pair used for encryption (if applicable)
   */
  rsaKeyPair?: RSAKeyPair;

  /**
   * Whether binary format was used for encryption
   */
  usedBinaryFormat?: boolean;

  /**
   * Whether ultra-secure encryption was used
   */
  usedUltraSecure?: boolean;

  /**
   * RSA key size used for encryption (in bits)
   */
  rsaKeySize?: number;
}

/**
 * Generate a secure random encryption key
 * @param keySize - Key size in bytes (default: 32 bytes for AES-256)
 * @returns Buffer containing the encryption key
 */
export function generateEncryptionKey(keySize: number = 32): Buffer {
  return Random.getRandomBytes(keySize).getBuffer();
}

/**
 * Generate an RSA key pair for enhanced security with automatic size adjustment
 * @param dataSize - Optional data size to optimize key size for (defaults to 32 bytes for AES key)
 * @returns RSA key pair with public and private keys
 */
export function generateRSAKeyPair(dataSize: number = 32): RSAKeyPair {
  // Use smart RSA key sizing based on data requirements
  const keyInfo = generateRSAKeyPairForData(dataSize);

  return {
    publicKey: keyInfo.publicKey,
    privateKey: keyInfo.privateKey,
  };
}

/**
 * Generate an RSA key pair with a specific key size
 * @param keySize - RSA key size in bits (1024, 2048, 3072, 4096, etc.)
 * @returns RSA key pair with public and private keys
 */
export function generateRSAKeyPairWithSize(keySize: number): RSAKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: keySize,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey };
}

/**
 * Calculate the recommended RSA key size for given data
 * @param dataSize - Size of data in bytes
 * @returns Recommended RSA key size in bits
 */
export function getRecommendedRSAKeySize(dataSize: number): number {
  return calculateRSAKeySize(dataSize);
}

/**
 * Ensure a directory exists, creating it if necessary
 * @param dirPath - Path to the directory
 */
export function ensureDirectoryExists(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

/**
 * Encrypt data and save it to a file with simplified options
 * @param data - Data to encrypt (object or string)
 * @param filePath - Path where the encrypted file will be saved
 * @param options - Encryption options
 * @returns Promise resolving to encryption result
 */
export async function encryptData(
  data: any,
  filePath: string,
  options: EncryptionOptions = {
    useBinaryFormat: true,
    layers: 3,
  }
): Promise<SimplifiedEncryptionResult> {
  // Generate encryption key if not provided
  const encryptionKey = generateEncryptionKey();
  const encryptionKeyHex = encryptionKey.toString("hex");

  // Calculate data size for smart RSA key sizing
  const dataString = JSON.stringify(data);
  const dataSize = SecureBuffer.from(dataString).length();

  // Generate RSA key pair with smart sizing or custom size
  let rsaKeyPair: RSAKeyPair;

  if (options.customRSAKeySize) {
    // Use custom RSA key size if specified
    rsaKeyPair = generateRSAKeyPairWithSize(options.customRSAKeySize);
  } else if (options.useSmartRSAKeySize !== false) {
    // Use smart RSA key sizing by default (can be disabled by setting to false)
    // Use 32 bytes for AES-256 key, but could also consider data size for future optimization
    rsaKeyPair = generateRSAKeyPair(Math.max(32, Math.min(dataSize, 256))); // Smart sizing with bounds
  } else {
    // Fallback to standard 2048-bit RSA key
    rsaKeyPair = generateRSAKeyPairWithSize(2048);
  }

  // Create FileGuardManager instance
  const fgm = new FileGuardManager(encryptionKeyHex);

  // Ensure the output directory exists
  const outputDir = path.dirname(filePath);
  ensureDirectoryExists(outputDir);

  // Set default options
  const securityLevel = options.securityLevel || "high";
  const compressionLevel = options.compressionLevel || "maximum";
  const layers = options.layers || 2;
  const useAlgorithmRotation = options.useAlgorithmRotation || false;
  const addHoneypots = options.addHoneypots || false;
  const metadata = options.metadata || {};

  // Determine which encryption method to use
  let encryptResult;

  if (options.useUltraSecure) {
    // Use ultra-secure encryption
    encryptResult = await fgm.saveWithUltraSecureEncryption(
      filePath,
      data,
      encryptionKey,
      rsaKeyPair,
      {
        securityLevel,
        compressionLevel,
        useAlgorithmRotation,
        addHoneypots,
      }
    );
  } else if (options.useBinaryFormat) {
    // Use binary format encryption (the secure version)
    encryptResult = await fgm.saveWithBinarySecureFormat(
      filePath,
      data,
      encryptionKey,
      rsaKeyPair,
      {
        layers,
        addRandomPadding: true,
        compressionLevel:
          compressionLevel === "none"
            ? 0
            : compressionLevel === "low"
            ? 3
            : compressionLevel === "medium"
            ? 6
            : compressionLevel === "high"
            ? 8
            : 9,
      }
    );
  } else {
    // Use advanced encryption (most compatible)
    encryptResult = await fgm.saveWithAdvancedEncryption(
      filePath,
      data,
      encryptionKey,
      rsaKeyPair,
      {
        securityLevel,
        compressionLevel,
        layers,
        useAlgorithmRotation,
        addHoneypots,
        metadata: metadata,
      }
    );
  }

  // Extract RSA key size for reporting
  const rsaKeySize = options.customRSAKeySize || getRecommendedRSAKeySize(32);

  // Return simplified result with encryption keys
  return {
    filePath: encryptResult.filepath,
    originalSize: encryptResult.size.original,
    encryptedSize: encryptResult.size.encrypted,
    compressionRatio:
      encryptResult.compressionRatio ||
      encryptResult.size.original / encryptResult.size.encrypted,
    encryptionKeyHex,
    rsaKeyPair,
    // Include additional metadata for debugging
    usedBinaryFormat: !!options.useBinaryFormat,
    usedUltraSecure: !!options.useUltraSecure,
    rsaKeySize,
  };
}

/**
 * Decrypt data from an encrypted file with simplified options
 * @param filePath - Path to the encrypted file
 * @param encryptionKeyHex - Encryption key as hex string
 * @param rsaKeyPair - RSA key pair used for encryption
 * @param useUltraSecure - Whether the file was encrypted with ultra-secure encryption
 * @param useBinaryFormat - Whether the file was encrypted with binary format
 * @returns Promise resolving to decrypted data
 */
export async function decryptData(
  filePath: string,
  encryptionKeyHex: string,
  rsaKeyPair: RSAKeyPair,
  useUltraSecure: boolean = false,
  useBinaryFormat: boolean = false
): Promise<any> {
  // Convert hex key to Buffer
  const encryptionKey = Buffer.from(encryptionKeyHex, "hex");

  // Create FileGuardManager instance
  const fgm = new FileGuardManager(encryptionKeyHex);

  // Determine which decryption method to use
  if (useUltraSecure) {
    // Use ultra-secure decryption
    return await fgm.loadWithUltraSecureDecryption(
      filePath,
      encryptionKey,
      rsaKeyPair
    );
  } else if (useBinaryFormat) {
    // Use binary format decryption (the secure version)
    return await fgm.loadWithBinarySecureFormat(
      filePath,
      encryptionKey,
      rsaKeyPair
    );
  } else {
    // Use advanced decryption (most compatible)
    return await fgm.loadWithAdvancedDecryption(
      filePath,
      encryptionKey,
      rsaKeyPair
    );
  }
}
