/**
 * Types for Fortify security library
 */

/**
 * Security level for cryptographic operations
 */
export enum SecurityLevel {
  Low = 1,
  Standard = 2,
  Medium = 3,
  High = 4,
  Maximum = 5
}

/**
 * Security level type (for backward compatibility)
 */
export type SecurityLevelType = 1 | 2 | 3 | 4 | 5;

/**
 * Entropy source for random number generation
 */
export enum EntropySource {
  System = "system",
  Browser = "browser",
  Hybrid = "hybrid",
  CSPRNG = "csprng",
  MATH_RANDOM = "math_random"
}

/**
 * Crypto stats for performance tracking
 */
export interface CryptoStats {
  operationId?: string;
  operationType?: string;
  startTime?: number;
  endTime?: number;
  memoryUsedBytes?: number;
  timeTakenMs?: number;
  iterations?: number;
  success?: boolean;
  error?: string;
  
  // Additional stats fields used in StatsTracker
  tokensGenerated: number;
  hashesComputed: number;
  keysDerivated: number;
  averageEntropyBits: number;
  lastOperationTime: string;
  
  // Performance metrics
  performance: {
    tokenGenerationAvgMs: number;
    hashComputationAvgMs: number;
    keyDerivationAvgMs: number;
  };
  
  // Memory usage
  memory: {
    peakUsageBytes: number;
    currentUsageBytes?: number;
    averageUsageBytes?: number;
  };
}

/**
 * Options for Lamport signature key generation
 */
export interface LamportKeygenOptions {
  /**
   * Security level (1-5)
   */
  securityLevel?: SecurityLevel;

  /**
   * Hash algorithm to use
   */
  hashAlgorithm?: string;
}

/**
 * Lamport key pair
 */
export interface LamportKeyPair {
  /**
   * Public key
   */
  publicKey: string;

  /**
   * Private key
   */
  privateKey: string;

  /**
   * Key generation metadata
   */
  metadata?: {
    /**
     * Hash algorithm used
     */
    hashAlgorithm: string;

    /**
     * Security level
     */
    securityLevel: SecurityLevel;

    /**
     * Key generation time in milliseconds
     */
    generationTimeMs: number;
  };
}

/**
 * Options for Lamport signature generation
 */
export interface LamportSignOptions {
  /**
   * Hash algorithm to use
   */
  hashAlgorithm?: string;
}

/**
 * Lamport signature result
 */
export interface LamportSignature {
  /**
   * Signature value
   */
  signature: string;

  /**
   * Signature metadata
   */
  metadata?: {
    /**
     * Hash algorithm used
     */
    hashAlgorithm: string;

    /**
     * Message hash
     */
    messageHash: string;

    /**
     * Signature generation time in milliseconds
     */
    signTimeMs: number;
  };
}

/**
 * Options for Kyber key generation
 */
export interface KyberKeygenOptions {
  /**
   * Security level (1-5)
   */
  securityLevel?: SecurityLevel;
}

/**
 * Kyber key pair
 */
export interface KyberKeyPair {
  /**
   * Public key
   */
  publicKey: string;

  /**
   * Private key
   */
  privateKey: string;

  /**
   * Key generation metadata
   */
  metadata?: {
    /**
     * Security level
     */
    securityLevel: SecurityLevel;

    /**
     * Key generation time in milliseconds
     */
    generationTimeMs: number;
  };
}

/**
 * Options for Kyber encapsulation
 */
export interface KyberEncapsulateOptions {
  /**
   * Security level (1-5)
   */
  securityLevel?: SecurityLevel;
}

/**
 * Kyber encapsulation result
 */
export interface KyberEncapsulation {
  /**
   * Ciphertext
   */
  ciphertext: string;

  /**
   * Shared secret
   */
  sharedSecret: string;

  /**
   * Encapsulation metadata
   */
  metadata?: {
    /**
     * Security level
     */
    securityLevel: SecurityLevel;

    /**
     * Encapsulation time in milliseconds
     */
    encapsulationTimeMs: number;
  };
}

/**
 * Options for Kyber decapsulation
 */
export interface KyberDecapsulateOptions {
  /**
   * Security level (1-5)
   */
  securityLevel?: SecurityLevel;
}

/**
 * Kyber decapsulation result
 */
export interface KyberDecapsulation {
  /**
   * Shared secret
   */
  sharedSecret: string;

  /**
   * Decapsulation metadata
   */
  metadata?: {
    /**
     * Security level
     */
    securityLevel: SecurityLevel;

    /**
     * Decapsulation time in milliseconds
     */
    decapsulationTimeMs: number;
  };
}

/**
 * Options for Argon2 key derivation
 */
export interface Argon2Options {
  /**
   * Memory cost in KiB
   */
  memoryCost: number;

  /**
   * Time cost (iterations)
   */
  timeCost: number;

  /**
   * Parallelism factor
   */
  parallelism: number;

  /**
   * Output key length in bytes
   */
  keyLength: number;

  /**
   * Salt
   */
  salt: Uint8Array;

  /**
   * Associated data
   */
  associatedData?: Uint8Array;
}

/**
 * Result of key derivation
 */
export interface KDFResult {
  /**
   * Derived key
   */
  derivedKey: string;

  /**
   * Salt used
   */
  salt: string;

  /**
   * Performance metrics
   */
  metrics: {
    /**
     * Memory used in bytes
     */
    memoryUsedBytes: number;

    /**
     * Time taken in milliseconds
     */
    timeTakenMs: number;

    /**
     * Number of iterations
     */
    iterations: number;
  };
}
