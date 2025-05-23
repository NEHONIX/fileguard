/**
 * Tests for the binary format classes
 */

import * as fs from 'fs';
import { BinarySecureFormat } from '../../src/core/BinarySecureFormat';
import { SimpleBinaryFormat } from '../../src/core/SimpleBinaryFormat';
import { FileGuardManager } from '../../src/core/FileGuardManager';
import {
  ensureTestDirectory,
  cleanupTestFiles,
  generateTestEncryptionKey,
  generateTestRSAKeyPair,
  generateTestData,
  generateLargeTestData,
  verifyDataIntegrity,
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

describe('Binary Formats', () => {
  let encryptionKey: Buffer;
  let rsaKeyPair: ReturnType<typeof generateTestRSAKeyPair>;
  let fgm: FileGuardManager;
  
  beforeEach(() => {
    // Set up test environment
    encryptionKey = generateTestEncryptionKey();
    rsaKeyPair = generateTestRSAKeyPair();
    fgm = new FileGuardManager(encryptionKey.toString('hex'));
  });
  
  describe('SimpleBinaryFormat', () => {
    test('should encrypt and decrypt data directly with SimpleBinaryFormat', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('simple-binary-direct');
      
      // Encrypt data
      await SimpleBinaryFormat.encrypt(
        testData,
        encryptionKey,
        filePath
      );
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await SimpleBinaryFormat.decrypt(
        filePath,
        encryptionKey
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should encrypt and decrypt data with FileGuardManager using SimpleBinaryFormat', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('simple-binary-fgm');
      
      // Encrypt data
      const encryptResult = await fgm.saveWithSimpleBinaryFormat(
        filePath,
        testData,
        encryptionKey
      );
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filepath).toBe(filePath);
      
      // Decrypt data
      const decryptedData = await fgm.loadWithSimpleBinaryFormat(
        filePath,
        encryptionKey
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should handle large data with SimpleBinaryFormat', async () => {
      // Generate large test data (100KB)
      const testData = generateLargeTestData(100);
      
      // File path
      const filePath = getTestFilePath('simple-binary-large');
      
      // Encrypt data
      await SimpleBinaryFormat.encrypt(
        testData,
        encryptionKey,
        filePath
      );
      
      // Decrypt data
      const decryptedData = await SimpleBinaryFormat.decrypt(
        filePath,
        encryptionKey
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
  });
  
  describe('BinarySecureFormat', () => {
    test('should encrypt and decrypt data directly with BinarySecureFormat', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('binary-secure-direct');
      
      // Encrypt data
      await BinarySecureFormat.encrypt(
        testData,
        encryptionKey,
        rsaKeyPair,
        filePath,
        {
          layers: 3,
          addRandomPadding: true,
        }
      );
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await BinarySecureFormat.decrypt(
        filePath,
        encryptionKey,
        rsaKeyPair
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should encrypt and decrypt data with FileGuardManager using BinarySecureFormat', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('binary-secure-fgm');
      
      // Encrypt data
      const encryptResult = await fgm.saveWithBinarySecureFormat(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          layers: 3,
          addRandomPadding: true,
        }
      );
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filepath).toBe(filePath);
      
      // Decrypt data
      const decryptedData = await fgm.loadWithBinarySecureFormat(
        filePath,
        encryptionKey,
        rsaKeyPair
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should handle different layer configurations', async () => {
      // Test different layer configurations
      const layerConfigs = [1, 2, 3, 5];
      
      for (const layers of layerConfigs) {
        // Test data
        const testData = generateTestData();
        
        // File path
        const filePath = getTestFilePath(`binary-secure-layers-${layers}`);
        
        // Encrypt data
        await BinarySecureFormat.encrypt(
          testData,
          encryptionKey,
          rsaKeyPair,
          filePath,
          {
            layers,
            addRandomPadding: true,
          }
        );
        
        // Decrypt data
        const decryptedData = await BinarySecureFormat.decrypt(
          filePath,
          encryptionKey,
          rsaKeyPair
        );
        
        // Verify decrypted data
        expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
      }
    });
    
    test('should handle large data with BinarySecureFormat', async () => {
      // Generate large test data (100KB)
      const testData = generateLargeTestData(100);
      
      // File path
      const filePath = getTestFilePath('binary-secure-large');
      
      // Encrypt data
      await BinarySecureFormat.encrypt(
        testData,
        encryptionKey,
        rsaKeyPair,
        filePath,
        {
          layers: 2, // Use fewer layers for large data to speed up test
          addRandomPadding: true,
        }
      );
      
      // Decrypt data
      const decryptedData = await BinarySecureFormat.decrypt(
        filePath,
        encryptionKey,
        rsaKeyPair
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
  });
});
