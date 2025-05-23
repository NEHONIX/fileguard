/**
 * Security tests for NEHONIX FileGuard
 * These tests verify the security features of the library
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import { FileGuardManager } from '../../src/core/FileGuardManager';
import { createPersistentRSAFGM } from '../../src/utils/rsaSolution';
import {
  ensureTestDirectory,
  cleanupTestFiles,
  generateTestEncryptionKey,
  generateTestRSAKeyPair,
  generateTestData,
  getTestFilePath,
  TEST_DIR
} from '../utils/testUtils';

// Setup and teardown
beforeAll(() => {
  ensureTestDirectory();
});

afterAll(() => {
  cleanupTestFiles();
});

// Clean up after each test
afterEach(() => {
  cleanupTestFiles();
});

describe('Security Features', () => {
  let fgm: FileGuardManager;
  let encryptionKey: Buffer;
  let rsaKeyPair: ReturnType<typeof generateTestRSAKeyPair>;
  
  beforeEach(() => {
    // Set up test environment
    encryptionKey = generateTestEncryptionKey();
    rsaKeyPair = generateTestRSAKeyPair();
    fgm = new FileGuardManager(encryptionKey.toString('hex'));
    
    // Set NODE_ENV to test to enable fallback mode
    process.env.NODE_ENV = 'test';
  });
  
  describe('Tamper Protection', () => {
    test('should detect tampering with encrypted file', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('tamper-test');
      
      // Encrypt data
      await fgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: 'high',
          compressionLevel: 'medium',
        }
      );
      
      // Tamper with the file
      const fileContent = fs.readFileSync(filePath);
      // Modify a byte in the middle of the file
      const tamperedContent = Buffer.from(fileContent);
      tamperedContent[Math.floor(tamperedContent.length / 2)] ^= 0xFF; // Flip all bits in a byte
      fs.writeFileSync(filePath, tamperedContent);
      
      // Attempt to decrypt the tampered file
      await expect(
        fgm.loadWithAdvancedDecryption(filePath, encryptionKey, rsaKeyPair, {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        })
      ).rejects.toThrow();
    });
    
    test('should detect tampering with binary format file', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('tamper-binary-test');
      
      // Encrypt data
      await fgm.saveWithBinarySecureFormat(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          layers: 2,
          addRandomPadding: true,
        }
      );
      
      // Tamper with the file
      const fileContent = fs.readFileSync(filePath);
      // Modify a byte in the middle of the file
      const tamperedContent = Buffer.from(fileContent);
      tamperedContent[Math.floor(tamperedContent.length / 2)] ^= 0xFF; // Flip all bits in a byte
      fs.writeFileSync(filePath, tamperedContent);
      
      // Attempt to decrypt the tampered file
      await expect(
        fgm.loadWithBinarySecureFormat(filePath, encryptionKey, rsaKeyPair)
      ).rejects.toThrow();
    });
  });
  
  describe('Key Security', () => {
    test('should not decrypt with incorrect key', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('key-security-test');
      
      // Encrypt data
      await fgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: 'high',
          compressionLevel: 'medium',
        }
      );
      
      // Generate a different key
      const wrongKey = generateTestEncryptionKey();
      
      // Attempt to decrypt with the wrong key
      await expect(
        fgm.loadWithAdvancedDecryption(filePath, wrongKey, rsaKeyPair, {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        })
      ).rejects.toThrow();
    });
    
    test('should not decrypt with incorrect RSA key pair', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('rsa-security-test');
      
      // Encrypt data with max security (uses RSA)
      await fgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: 'max', // Max security uses RSA
          compressionLevel: 'medium',
        }
      );
      
      // Generate a different RSA key pair
      const wrongRSAKeyPair = generateTestRSAKeyPair();
      
      // Attempt to decrypt with the wrong RSA key pair
      await expect(
        fgm.loadWithAdvancedDecryption(filePath, encryptionKey, wrongRSAKeyPair, {
          disableFallbackMode: true, // Disable fallback to ensure we get the error
        })
      ).rejects.toThrow();
    });
  });
  
  describe('Production Mode', () => {
    test('should not use fallback mode when in production', async () => {
      // Set NODE_ENV to production
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      // Create a new FileGuardManager instance in production mode
      const prodFgm = new FileGuardManager(encryptionKey.toString('hex'));
      
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('production-test');
      
      // Encrypt data
      await prodFgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: 'high',
          compressionLevel: 'medium',
        }
      );
      
      // Tamper with the file
      const fileContent = fs.readFileSync(filePath);
      const tamperedContent = Buffer.from(fileContent);
      tamperedContent[Math.floor(tamperedContent.length / 2)] ^= 0xFF; // Flip all bits in a byte
      fs.writeFileSync(filePath, tamperedContent);
      
      // Attempt to decrypt the tampered file
      await expect(
        prodFgm.loadWithAdvancedDecryption(filePath, encryptionKey, rsaKeyPair)
      ).rejects.toThrow();
      
      // Restore NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    });
  });
  
  describe('Persistent RSA Keys', () => {
    test('should create and use persistent RSA keys', async () => {
      // RSA keys path
      const rsaKeysPath = getTestFilePath('test-rsa-keys', '.json');
      
      // Create a FileGuardManager with persistent RSA keys
      const persistentFgm = createPersistentRSAFGM(encryptionKey.toString('hex'), {
        rsaKeysPath
      });
      
      // Verify RSA key pair exists
      expect(persistentFgm.rsaKeyPair).toBeDefined();
      expect(persistentFgm.rsaKeyPair.publicKey).toBeDefined();
      expect(persistentFgm.rsaKeyPair.privateKey).toBeDefined();
      
      // Verify RSA keys file exists
      expect(fs.existsSync(rsaKeysPath)).toBe(true);
      
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('persistent-rsa-test');
      
      // Encrypt data
      await persistentFgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        persistentFgm.rsaKeyPair,
        {
          securityLevel: 'high',
          compressionLevel: 'medium',
        }
      );
      
      // Create a new instance with the same RSA keys path
      const newPersistentFgm = createPersistentRSAFGM(encryptionKey.toString('hex'), {
        rsaKeysPath
      });
      
      // Verify the new instance has the same RSA keys
      expect(newPersistentFgm.rsaKeyPair.publicKey).toBe(persistentFgm.rsaKeyPair.publicKey);
      expect(newPersistentFgm.rsaKeyPair.privateKey).toBe(persistentFgm.rsaKeyPair.privateKey);
      
      // Decrypt data with the new instance
      const decryptedData = await newPersistentFgm.loadWithAdvancedDecryption(
        filePath,
        encryptionKey,
        newPersistentFgm.rsaKeyPair
      );
      
      // Verify decrypted data
      expect(JSON.stringify(decryptedData)).toBe(JSON.stringify(testData));
    });
  });
});
