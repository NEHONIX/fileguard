/**
 * Types and interfaces for the NEHONIX FileGuard library
 */

import { KeyObject } from "crypto";

/**
 * Security levels for encryption
 */
export type SecurityLevel = "standard" | "high" | "max";

/**
 * Compression levels
 */
export type CompressionLevel = "none" | "low" | "medium" | "high" | "maximum";

/**
 * Log levels
 */
export type LogLevel = "none" | "error" | "info" | "debug";

/**
 * Export Fortify types
 */
export * from "./fortify";

/**
 * RSA Key Pair
 */
export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Advanced encryption configuration
 */
export interface AdvancedEncryptionConfig {
  securityLevel: SecurityLevel;
  /**
   * Alternative property name for securityLevel used by UltraSecureEncryption
   * @default securityLevel
   */
  encryptLevel?: SecurityLevel;
  compressionLevel: CompressionLevel;
  layers?: number;
  useAlgorithmRotation?: boolean;
  blockSize?: number;
  addHoneypots?: boolean;
  customMetadata?: Record<string, any>;
}

/**
 * Decryption options
 */
export interface DecryptionOptions {
  disableFallbackMode?: boolean;
  logLevel?: LogLevel;
  allowProduction?: boolean;
}

/**
 * Encryption result
 */
export interface EncryptionResult {
  filepath: string;
  size: {
    original: number;
    encrypted: number;
  };
  header?: NXSFileHeader;
  metadata?: Record<string, any>;
  compressionRatio?: number;
}

/**
 * RSA Solution options
 */
export interface RSASolutionOptions {
  rsaKeysPath?: string;
}

/**
 * Encryption/Decryption utility options
 */
export interface EncryptDecryptOptions {
  encrypt?: "enable" | "disable";
  decrypt?: "enable" | "disable";
  filepath?: string;
  allowProduction?: boolean;
  logLevel?: LogLevel;
}

/**
 * NXS File Header
 */
export interface NXSFileHeader {
  magic: string; // 'NXSFILE'
  version: number;
  securityLevel: SecurityLevel;
  compressionLevel: CompressionLevel;
  layers: number;
  timestamp: number;
  metadata?: Record<string, any>;
  useAlgorithmRotation?: boolean;
  addHoneypots?: boolean;
  customMetadata?: Record<string, any>;
}

/**
 * File version metadata
 */
export interface VersionMetadata {
  version: number;
  timestamp: Date;
  author?: string;
  comment?: string;
}
