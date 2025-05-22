/**
 * RSA Solution for NEHONIX FileGuard
 * Provides persistent RSA key management
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { FileGuardManager } from '../core/FileGuardManager';
import { RSAKeyPair, RSASolutionOptions } from '../types';
import { logger } from './logger';

// Default path for RSA keys
const DEFAULT_RSA_KEYS_PATH = path.join(process.cwd(), 'rsa_keys.json');

/**
 * Generate a new RSA key pair
 * @returns RSA key pair
 */
function generateRSAKeyPair(): RSAKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  
  return { publicKey, privateKey };
}

/**
 * Load RSA keys from file
 * @param filePath - Path to the RSA keys file
 * @returns RSA key pair or null if file doesn't exist
 */
function loadRSAKeys(filePath: string): RSAKeyPair | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const keys = JSON.parse(fileContent) as RSAKeyPair;
    
    // Validate keys
    if (!keys.publicKey || !keys.privateKey) {
      logger.warn(`Invalid RSA keys file: ${filePath}`);
      return null;
    }
    
    return keys;
  } catch (error) {
    logger.error(`Error loading RSA keys from ${filePath}`, error);
    return null;
  }
}

/**
 * Save RSA keys to file
 * @param keys - RSA key pair
 * @param filePath - Path to save the RSA keys
 */
function saveRSAKeys(keys: RSAKeyPair, filePath: string): void {
  try {
    // Create directory if it doesn't exist
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    // Write keys to file
    fs.writeFileSync(filePath, JSON.stringify(keys, null, 2));
    logger.info(`RSA keys saved to ${filePath}`);
  } catch (error) {
    logger.error(`Error saving RSA keys to ${filePath}`, error);
    throw error;
  }
}

/**
 * Create a FileGuardManager with persistent RSA keys
 * @param encryptionKey - Encryption key
 * @param options - RSA solution options
 * @returns FileGuardManager instance
 */
export function createPersistentRSAFGM(
  encryptionKey: string,
  options?: RSASolutionOptions
): FileGuardManager & { rsaKeyPair: RSAKeyPair } {
  // Determine the path for RSA keys
  const rsaKeysPath = options?.rsaKeysPath || DEFAULT_RSA_KEYS_PATH;
  
  // Try to load existing RSA keys
  let rsaKeyPair = loadRSAKeys(rsaKeysPath);
  
  // Generate new keys if none exist
  if (!rsaKeyPair) {
    logger.info(`Generating new RSA key pair`);
    rsaKeyPair = generateRSAKeyPair();
    saveRSAKeys(rsaKeyPair, rsaKeysPath);
  } else {
    logger.info(`Loaded existing RSA key pair from ${rsaKeysPath}`);
  }
  
  // Create FileGuardManager instance
  const fgm = new FileGuardManager(encryptionKey);
  
  // Return enhanced FileGuardManager with RSA key pair
  return Object.assign(fgm, { rsaKeyPair });
}
