/**
 * Tests for the cryptUtils module
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  encryptData,
  decryptData,
  generateEncryptionKey,
  generateRSAKeyPair,
  ensureDirectoryExists
} from '../../src/utils/cryptUtils';
import { SecurityLevel, CompressionLevel } from '../../src/types';
import {
  ensureTestDirectory,
  cleanupTestFiles,
  generateTestData,
  generateLargeTestData,
  verifyDataIntegrity,
  getTestFilePath,
  TEST_DIR
} from '../utils/testUtils';

// Setup and teardown
beforeAll(() => {
  ensureTestDirectory();
  
  // Set NODE_ENV to test to enable fallback mode
  process.env.NODE_ENV = 'test';
});

afterAll(() => {
  cleanupTestFiles();
});

// Clean up after each test
afterEach(() => {
  cleanupTestFiles();
});

describe('cryptUtils', () => {
  describe('Utility Functions', () => {
    test('should generate encryption key', () => {
      const key = generateEncryptionKey();
      expect(key).toBeDefined();
      expect(key.length).toBe(32); // 32 bytes = 256 bits
    });
    
    test('should generate RSA key pair', () => {
      const keyPair = generateRSAKeyPair();
      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(keyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    });
    
    test('should ensure directory exists', () => {
      const testDir = path.join(TEST_DIR, 'ensure-dir-test');
      
      // Directory should not exist initially
      if (fs.existsSync(testDir)) {
        fs.rmdirSync(testDir);
      }
      expect(fs.existsSync(testDir)).toBe(false);
      
      // Create directory
      ensureDirectoryExists(testDir);
      expect(fs.existsSync(testDir)).toBe(true);
      
      // Should not throw when directory already exists
      expect(() => ensureDirectoryExists(testDir)).not.toThrow();
      
      // Clean up
      fs.rmdirSync(testDir);
    });
  });
  
  describe('Encryption and Decryption', () => {
    test('should encrypt and decrypt data with default options', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('default-options');
      
      // Encrypt data
      const encryptResult = await encryptData(testData, filePath);
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filePath).toBe(filePath);
      expect(encryptResult.originalSize).toBeGreaterThan(0);
      expect(encryptResult.encryptedSize).toBeGreaterThan(0);
      expect(encryptResult.encryptionKeyHex).toBeDefined();
      expect(encryptResult.rsaKeyPair).toBeDefined();
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await decryptData(
        filePath,
        encryptResult.encryptionKeyHex,
        encryptResult.rsaKeyPair!
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should encrypt and decrypt data with custom options', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('custom-options');
      
      // Custom metadata
      const metadata = {
        author: 'Test Author',
        createdAt: new Date().toISOString(),
        tags: ['test', 'custom', 'options']
      };
      
      // Encrypt data with custom options
      const encryptResult = await encryptData(testData, filePath, {
        securityLevel: 'high',
        compressionLevel: 'high',
        layers: 3,
        useAlgorithmRotation: true,
        addHoneypots: true,
        metadata
      });
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filePath).toBe(filePath);
      
      // Decrypt data
      const decryptedData = await decryptData(
        filePath,
        encryptResult.encryptionKeyHex,
        encryptResult.rsaKeyPair!
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should encrypt and decrypt with binary format', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('binary-format');
      
      // Encrypt data with binary format
      const encryptResult = await encryptData(testData, filePath, {
        useBinaryFormat: true,
        securityLevel: 'high',
        compressionLevel: 'medium',
        layers: 2
      });
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filePath).toBe(filePath);
      
      // Decrypt data
      const decryptedData = await decryptData(
        filePath,
        encryptResult.encryptionKeyHex,
        encryptResult.rsaKeyPair!,
        false, // not ultra secure
        true   // is binary format
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should handle large data', async () => {
      // Generate large test data (100KB)
      const testData = generateLargeTestData(100);
      
      // File path
      const filePath = getTestFilePath('large-data');
      
      // Encrypt data
      const encryptResult = await encryptData(testData, filePath, {
        compressionLevel: 'maximum' // Use maximum compression for large data
      });
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filePath).toBe(filePath);
      
      // Expect compression to reduce size
      expect(encryptResult.encryptedSize).toBeLessThan(encryptResult.originalSize);
      
      // Decrypt data
      const decryptedData = await decryptData(
        filePath,
        encryptResult.encryptionKeyHex,
        encryptResult.rsaKeyPair!
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
  });
});
