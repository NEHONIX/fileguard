/**
 * Encryption utilities for NEHONIX FileGuard
 */

import * as crypto from 'crypto';
import { FileGuardManager } from '../core/FileGuardManager';
import { createPersistentRSAFGM } from './rsaSolution';
import { EncryptDecryptOptions } from '../types';
import { logger } from './logger';

/**
 * Utility function to encrypt or decrypt data
 * @param data - Data to encrypt or decrypt
 * @param encryptionKey - Encryption key
 * @param options - Encryption/decryption options
 * @returns Promise resolving to the result
 */
export async function encryptOrDecryptNXS(
  data: any,
  encryptionKey: string | Buffer,
  options?: EncryptDecryptOptions
): Promise<any> {
  // Set default options
  const opts: Required<EncryptDecryptOptions> = {
    encrypt: options?.encrypt || 'enable',
    decrypt: options?.decrypt || 'enable',
    filepath: options?.filepath || './file.nxs',
    allowProduction: options?.allowProduction || false,
    logLevel: options?.logLevel || 'info'
  };
  
  // Set log level
  logger.setLogLevel(opts.logLevel);
  
  // Check if we're in production
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (isProduction && !opts.allowProduction) {
    logger.error(
      'encryptOrDecryptNXS is not recommended for production use. ' +
      'Use FileGuardManager methods directly or set allowProduction: true'
    );
    throw new Error('Not allowed in production');
  }
  
  // Convert string key to Buffer if needed
  const keyBuffer = Buffer.isBuffer(encryptionKey) 
    ? encryptionKey 
    : Buffer.from(encryptionKey);
  
  // Create FileGuardManager with persistent RSA keys
  const fgm = createPersistentRSAFGM(keyBuffer.toString('hex'));
  
  // Process based on options
  try {
    let result: any = data;
    
    // Encrypt if enabled
    if (opts.encrypt === 'enable') {
      logger.info(`Encrypting data to ${opts.filepath}`);
      
      result = await fgm.saveWithAdvancedEncryption(
        opts.filepath,
        data,
        keyBuffer,
        fgm.rsaKeyPair,
        {
          securityLevel: 'high', // Required property
          encryptLevel: 'high',
          compressionLevel: 'medium',
          layers: 3,
          useAlgorithmRotation: true,
          addHoneypots: true
        }
      );
    }
    
    // Decrypt if enabled
    if (opts.decrypt === 'enable') {
      logger.info(`Decrypting data from ${opts.filepath}`);
      
      result = await fgm.loadWithAdvancedDecryption(
        opts.filepath,
        keyBuffer,
        fgm.rsaKeyPair,
        {
          disableFallbackMode: isProduction,
          logLevel: opts.logLevel
        }
      );
    }
    
    return result;
  } catch (error) {
    logger.error('Error in encryptOrDecryptNXS', error);
    throw error;
  }
}

/**
 * Generate a random encryption key
 * @param length - Key length in bytes
 * @returns Random encryption key
 */
export function generateEncryptionKey(length: number = 32): Buffer {
  return crypto.randomBytes(length);
}

/**
 * Generate a secure password-based key
 * @param password - Password
 * @param salt - Salt
 * @param iterations - Number of iterations
 * @param keyLength - Key length in bytes
 * @returns Derived key
 */
export function deriveKeyFromPassword(
  password: string,
  salt: Buffer = crypto.randomBytes(16),
  iterations: number = 100000,
  keyLength: number = 32
): { key: Buffer; salt: Buffer } {
  const key = crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    keyLength,
    'sha512'
  );
  
  return { key, salt };
}

/**
 * Calculate the hash of data
 * @param data - Data to hash
 * @param algorithm - Hash algorithm
 * @returns Hash as hex string
 */
export function calculateHash(
  data: string | Buffer,
  algorithm: string = 'sha256'
): string {
  return crypto.createHash(algorithm).update(data).digest('hex');
}

/**
 * Verify the integrity of data using a hash
 * @param data - Data to verify
 * @param hash - Expected hash
 * @param algorithm - Hash algorithm
 * @returns Whether the data is valid
 */
export function verifyIntegrity(
  data: string | Buffer,
  hash: string,
  algorithm: string = 'sha256'
): boolean {
  const calculatedHash = calculateHash(data, algorithm);
  return calculatedHash === hash;
}
