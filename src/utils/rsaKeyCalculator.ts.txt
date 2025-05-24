/**
 * @author iDevo
 * Enhanced RSA Key Size Calculator
 * Calculates appropriate RSA key size based on data size with improved security and performance
 */

import * as crypto from "crypto";
import { logger } from "./logger";

// Constants for better maintainability
const HASH_SIZES = {
  sha1: 20,
  sha224: 28,
  sha256: 32,
  sha384: 48,
  sha512: 64,
} as const;

const STANDARD_RSA_KEY_SIZES = [2048, 3072, 4096, 7680, 8192, 15360] as const;
const MIN_SECURE_KEY_SIZE = 2048; // NIST recommendation
const DEFAULT_HASH_ALGORITHM = 'sha256';

type HashAlgorithm = keyof typeof HASH_SIZES;
type StandardKeySize = typeof STANDARD_RSA_KEY_SIZES[number];

interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
  keySize: number;
  maxDataSize: number;
  hashAlgorithm: HashAlgorithm;
}

interface RSATestResult {
  success: boolean;
  error?: string;
  encryptedSize?: number;
  decryptedMatches?: boolean;
  performanceMs?: number;
}

interface RSARecommendation {
  keySize: number;
  maxDataSize: number;
  securityLevel: 'minimal' | 'standard' | 'high' | 'maximum';
  recommendation: string;
}

/**
 * Calculate OAEP padding overhead for given hash algorithm
 */
function calculateOAEPOverhead(hashAlgorithm: HashAlgorithm): number {
  const hashSize = HASH_SIZES[hashAlgorithm];
  return 2 * hashSize + 2;
}

/**
 * Validate input parameters
 */
function validateInputs(dataSize: number, rsaKeySize?: number, hashAlgorithm?: string): void {
  if (!Number.isInteger(dataSize) || dataSize < 0) {
    throw new Error('Data size must be a non-negative integer');
  }
  
  if (dataSize > 1024 * 1024) { // 1MB limit for RSA
    logger.warn(`Large data size (${dataSize} bytes) - consider hybrid encryption instead`);
  }
  
  if (rsaKeySize !== undefined) {
    if (!Number.isInteger(rsaKeySize) || rsaKeySize < MIN_SECURE_KEY_SIZE) {
      throw new Error(`RSA key size must be at least ${MIN_SECURE_KEY_SIZE} bits for security`);
    }
    
    if (rsaKeySize % 8 !== 0) {
      throw new Error('RSA key size must be divisible by 8');
    }
  }
  
  if (hashAlgorithm && !(hashAlgorithm in HASH_SIZES)) {
    throw new Error(`Unsupported hash algorithm: ${hashAlgorithm}. Supported: ${Object.keys(HASH_SIZES).join(', ')}`);
  }
}

/**
 * Get security level based on key size
 */
function getSecurityLevel(keySize: number): RSARecommendation['securityLevel'] {
  if (keySize >= 8192) return 'maximum';
  if (keySize >= 4096) return 'high';
  if (keySize >= 3072) return 'standard';
  return 'minimal';
}

/**
 * Calculate the minimum RSA key size needed for the given data size
 * @param dataSize - Size of data to encrypt in bytes
 * @param hashAlgorithm - Hash algorithm for OAEP padding (default: sha256)
 * @param allowCustomSize - Allow non-standard key sizes (default: false)
 * @returns Recommended RSA key size in bits
 */
export function calculateRSAKeySize(
  dataSize: number, 
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
  allowCustomSize: boolean = false
): number {
  validateInputs(dataSize, undefined, hashAlgorithm);
  
  const oaepOverhead = calculateOAEPOverhead(hashAlgorithm);
  const requiredKeyBytes = dataSize + oaepOverhead;
  const requiredKeyBits = requiredKeyBytes * 8;
  
  // Find the smallest standard key size that can accommodate the data
  for (const keySize of STANDARD_RSA_KEY_SIZES) {
    const maxDataSize = Math.floor(keySize / 8) - oaepOverhead;
    if (dataSize <= maxDataSize) {
      logger.info(`Data size: ${dataSize} bytes, selected RSA key size: ${keySize} bits (max data: ${maxDataSize} bytes)`);
      return keySize;
    }
  }
  
  // Handle cases where data is too large for standard sizes
  if (!allowCustomSize) {
    const maxStandardSize = Math.max(...STANDARD_RSA_KEY_SIZES);
    const maxDataForLargest = Math.floor(maxStandardSize / 8) - oaepOverhead;
    throw new Error(
      `Data size ${dataSize} bytes exceeds maximum for standard RSA keys (max: ${maxDataForLargest} bytes). ` +
      `Consider using hybrid encryption (RSA + AES) or set allowCustomSize=true.`
    );
  }
  
  // Calculate custom size rounded up to nearest 1024 bits
  const customKeySize = Math.ceil(requiredKeyBits / 1024) * 1024;
  logger.warn(`Data size ${dataSize} bytes requires custom RSA key size: ${customKeySize} bits`);
  return customKeySize;
}

/**
 * Generate RSA key pair with appropriate size for the given data
 * @param dataSize - Size of data to encrypt in bytes
 * @param hashAlgorithm - Hash algorithm for OAEP padding
 * @param allowCustomSize - Allow non-standard key sizes
 * @returns RSA key pair with metadata
 */
export function generateRSAKeyPairForData(
  dataSize: number,
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
  allowCustomSize: boolean = false
): RSAKeyPair {
  validateInputs(dataSize, undefined, hashAlgorithm);
  
  const keySize = calculateRSAKeySize(dataSize, hashAlgorithm, allowCustomSize);
  const maxDataSize = getMaxDataSizeForRSAKey(keySize, hashAlgorithm);
  
  logger.info(`Generating RSA key pair with ${keySize} bits for data size ${dataSize} bytes`);
  
  try {
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: keySize,
      publicKeyEncoding: { 
        type: "spki", 
        format: "pem" 
      },
      privateKeyEncoding: { 
        type: "pkcs8", 
        format: "pem",
        cipher: undefined, // No password protection by default
        passphrase: undefined
      },
    });
    
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      keySize,
      maxDataSize,
      hashAlgorithm,
    };
  } catch (error: any) {
    logger.error(`Failed to generate RSA key pair: ${error.message}`);
    throw new Error(`RSA key generation failed: ${error.message}`);
  }
}

/**
 * Generate password-protected RSA key pair
 * @param dataSize - Size of data to encrypt in bytes
 * @param passphrase - Password to protect the private key
 * @param hashAlgorithm - Hash algorithm for OAEP padding
 * @returns Protected RSA key pair
 */
export function generateProtectedRSAKeyPairForData(
  dataSize: number,
  passphrase: string,
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM
): RSAKeyPair {
  validateInputs(dataSize, undefined, hashAlgorithm);
  
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters long');
  }
  
  const keySize = calculateRSAKeySize(dataSize, hashAlgorithm);
  const maxDataSize = getMaxDataSizeForRSAKey(keySize, hashAlgorithm);
  
  try {
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: keySize,
      publicKeyEncoding: { 
        type: "spki", 
        format: "pem" 
      },
      privateKeyEncoding: { 
        type: "pkcs8", 
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: passphrase
      },
    });
    
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      keySize,
      maxDataSize,
      hashAlgorithm,
    };
  } catch (error: any) {
    logger.error(`Failed to generate protected RSA key pair: ${error.message}`);
    throw new Error(`Protected RSA key generation failed: ${error.message}`);
  }
}

/**
 * Get maximum data size that can be encrypted with a given RSA key size
 * @param rsaKeySize - RSA key size in bits
 * @param hashAlgorithm - Hash algorithm used for OAEP
 * @returns Maximum data size in bytes
 */
export function getMaxDataSizeForRSAKey(
  rsaKeySize: number, 
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM
): number {
  validateInputs(0, rsaKeySize, hashAlgorithm);
  
  const oaepOverhead = calculateOAEPOverhead(hashAlgorithm);
  const keyBytes = Math.floor(rsaKeySize / 8);
  const maxDataSize = keyBytes - oaepOverhead;
  
  if (maxDataSize <= 0) {
    throw new Error(`RSA key size ${rsaKeySize} is too small for ${hashAlgorithm} OAEP padding`);
  }
  
  return maxDataSize;
}

/**
 * Validate if data can be encrypted with the given RSA key
 * @param dataSize - Size of data in bytes
 * @param rsaKeySize - RSA key size in bits
 * @param hashAlgorithm - Hash algorithm used for OAEP
 * @returns Validation result with details
 */
export function validateDataSizeForRSAKey(
  dataSize: number, 
  rsaKeySize: number, 
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM
): { valid: boolean; maxDataSize: number; recommendation?: string } {
  validateInputs(dataSize, rsaKeySize, hashAlgorithm);
  
  const maxDataSize = getMaxDataSizeForRSAKey(rsaKeySize, hashAlgorithm);
  const valid = dataSize <= maxDataSize;
  
  let recommendation: string | undefined;
  if (!valid) {
    const requiredKeySize = calculateRSAKeySize(dataSize, hashAlgorithm, true);
    recommendation = `Data size ${dataSize} bytes requires at least ${requiredKeySize} bits RSA key`;
  } else if (dataSize > 245) { // Typical AES key size
    recommendation = 'Consider using hybrid encryption (RSA + AES) for better performance with large data';
  }
  
  return { valid, maxDataSize, recommendation };
}

/**
 * Get RSA key size recommendations for different security levels
 * @param dataSize - Size of data to encrypt in bytes
 * @param hashAlgorithm - Hash algorithm for OAEP padding
 * @returns Array of recommendations
 */
export function getRSARecommendations(
  dataSize: number,
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM
): RSARecommendation[] {
  validateInputs(dataSize, undefined, hashAlgorithm);
  
  const recommendations: RSARecommendation[] = [];
  
  for (const keySize of STANDARD_RSA_KEY_SIZES) {
    const maxDataSize = getMaxDataSizeForRSAKey(keySize, hashAlgorithm);
    if (dataSize <= maxDataSize) {
      const securityLevel = getSecurityLevel(keySize);
      let recommendation = `${keySize}-bit RSA provides ${securityLevel} security`;
      
      if (keySize === 2048) {
        recommendation += ' (minimum recommended for new applications)';
      } else if (keySize >= 4096) {
        recommendation += ' (recommended for high-security applications)';
      }
      
      recommendations.push({
        keySize,
        maxDataSize,
        securityLevel,
        recommendation,
      });
    }
  }
  
  return recommendations;
}

/**
 * Test RSA encryption/decryption with performance monitoring
 * @param dataSize - Size of test data in bytes
 * @param rsaKeySize - RSA key size in bits
 * @param hashAlgorithm - Hash algorithm for OAEP padding
 * @param iterations - Number of test iterations for performance measurement
 * @returns Comprehensive test result
 */
export async function testRSAWithDataSize(
  dataSize: number, 
  rsaKeySize: number,
  hashAlgorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
  iterations: number = 1
): Promise<RSATestResult> {
  try {
    validateInputs(dataSize, rsaKeySize, hashAlgorithm);
    
    if (iterations < 1 || iterations > 1000) {
      throw new Error('Iterations must be between 1 and 1000');
    }
    
    // Generate test data
    const testData = crypto.randomBytes(dataSize);
    
    // Generate RSA key pair
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: rsaKeySize,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    
    const startTime = process.hrtime.bigint();
    let encryptedSize = 0;
    let allDecryptedMatch = true;
    
    // Run multiple iterations for performance testing
    for (let i = 0; i < iterations; i++) {
      // Test encryption
      const encrypted = crypto.publicEncrypt(
        {
          key: keyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: hashAlgorithm,
        },
        testData
      );
      
      encryptedSize = encrypted.length;
      
      // Test decryption
      const decrypted = crypto.privateDecrypt(
        {
          key: keyPair.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: hashAlgorithm,
        },
        encrypted
      );
      
      if (!testData.equals(decrypted)) {
        allDecryptedMatch = false;
        break;
      }
    }
    
    const endTime = process.hrtime.bigint();
    const performanceMs = Number(endTime - startTime) / 1_000_000 / iterations; // Average per iteration
    
    return {
      success: true,
      encryptedSize,
      decryptedMatches: allDecryptedMatch,
      performanceMs: Math.round(performanceMs * 100) / 100, // Round to 2 decimal places
    };
  } catch (error: any) {
    logger.error(`RSA test failed: ${error.message}`);
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Benchmark RSA performance across different key sizes
 * @param dataSize - Size of test data in bytes
 * @param keySizes - Array of key sizes to test
 * @param iterations - Number of iterations per key size
 * @returns Performance comparison results
 */
export async function benchmarkRSAPerformance(
  dataSize: number,
  keySizes: number[] = [...STANDARD_RSA_KEY_SIZES],
  iterations: number = 10
): Promise<Array<{ keySize: number; avgTimeMs: number; success: boolean; error?: string }>> {
  const results = [];
  
  for (const keySize of keySizes) {
    try {
      const validation = validateDataSizeForRSAKey(dataSize, keySize);
      if (!validation.valid) {
        results.push({
          keySize,
          avgTimeMs: 0,
          success: false,
          error: `Data too large for ${keySize}-bit key`,
        });
        continue;
      }
      
      const testResult = await testRSAWithDataSize(dataSize, keySize, DEFAULT_HASH_ALGORITHM, iterations);
      results.push({
        keySize,
        avgTimeMs: testResult.performanceMs || 0,
        success: testResult.success,
        error: testResult.error,
      });
    } catch (error: any) {
      results.push({
        keySize,
        avgTimeMs: 0,
        success: false,
        error: error.message,
      });
    }
  }
  
  return results;
}

/**
 * Utility to suggest hybrid encryption when RSA alone is inefficient
 * @param dataSize - Size of data to encrypt in bytes
 * @returns Suggestion for encryption approach
 */
export function getEncryptionSuggestion(dataSize: number): {
  approach: 'rsa' | 'hybrid';
  reason: string;
  details?: {
    aesKeySize: number;
    rsaKeySize: number;
    estimatedPerformanceGain?: string;
  };
} {
  validateInputs(dataSize);
  
  // Threshold where hybrid encryption becomes more efficient
  const hybridThreshold = 245; // Roughly AES-256 key size
  
  if (dataSize <= hybridThreshold) {
    return {
      approach: 'rsa',
      reason: 'Data size is small enough for direct RSA encryption',
    };
  }
  
  return {
    approach: 'hybrid',
    reason: 'Large data size - hybrid encryption (RSA + AES) recommended for better performance',
    details: {
      aesKeySize: 256, // AES-256 recommended
      rsaKeySize: 2048, // Minimum secure RSA size for key exchange
      estimatedPerformanceGain: '10-1000x faster encryption/decryption',
    },
  };
}