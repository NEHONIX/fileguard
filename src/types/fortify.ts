/**
 * Types for Fortify integration with FileGuardManager
 */

import { SecurityLevel, CompressionLevel } from './index';

/**
 * Fortify encryption options
 */
export interface FortifyEncryptionOptions {
  /**
   * Security level for encryption
   */
  securityLevel: SecurityLevel;
  
  /**
   * Compression level
   */
  compressionLevel: CompressionLevel;
  
  /**
   * Number of encryption layers
   */
  layers?: number;
  
  /**
   * Whether to use algorithm rotation
   */
  useAlgorithmRotation?: boolean;
  
  /**
   * Whether to use post-quantum encryption
   */
  usePostQuantum?: boolean;
  
  /**
   * Whether to use memory-hard key derivation
   */
  useMemoryHardKDF?: boolean;
  
  /**
   * Memory cost for memory-hard key derivation
   */
  memoryCost?: number;
  
  /**
   * Time cost for memory-hard key derivation
   */
  timeCost?: number;
  
  /**
   * Whether to add honeypots
   */
  addHoneypots?: boolean;
}

/**
 * Fortify encryption result
 */
export interface FortifyEncryptionResult {
  /**
   * Encrypted data
   */
  data: Buffer;
  
  /**
   * Encryption metadata
   */
  metadata: {
    /**
     * Algorithms used for encryption
     */
    algorithms: string[];
    
    /**
     * Whether post-quantum encryption was used
     */
    postQuantum?: boolean;
    
    /**
     * Whether memory-hard key derivation was used
     */
    memoryHardKDF?: boolean;
    
    /**
     * Key derivation parameters
     */
    kdfParams?: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
    };
    
    /**
     * Encryption time in milliseconds
     */
    encryptionTimeMs: number;
  };
}

/**
 * Fortify decryption options
 */
export interface FortifyDecryptionOptions {
  /**
   * Whether to disable fallback mode
   */
  disableFallbackMode?: boolean;
  
  /**
   * Log level
   */
  logLevel?: string;
}

/**
 * Fortify security parameters
 */
export interface FortifySecurityParams {
  /**
   * Encryption key
   */
  key: Buffer;
  
  /**
   * Salt for key derivation
   */
  salt?: Buffer;
  
  /**
   * Initialization vector
   */
  iv?: Buffer;
  
  /**
   * Authentication tag
   */
  authTag?: Buffer;
  
  /**
   * Additional authenticated data
   */
  aad?: Buffer;
  
  /**
   * Post-quantum key pair
   */
  postQuantumKeyPair?: {
    publicKey: string;
    privateKey: string;
  };
}
