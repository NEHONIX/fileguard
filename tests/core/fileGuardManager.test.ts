/**
 * Tests for the FileGuardManager class
 */

import * as fs from 'fs';
import * as path from 'path';
import { FileGuardManager } from '../../src/core/FileGuardManager';
import { SecurityLevel, CompressionLevel } from '../../src/types';
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

describe('FileGuardManager', () => {
  let fgm: FileGuardManager;
  let encryptionKey: Buffer;
  let rsaKeyPair: ReturnType<typeof generateTestRSAKeyPair>;
  
  beforeEach(() => {
    // Set up test environment
    encryptionKey = generateTestEncryptionKey();
    rsaKeyPair = generateTestRSAKeyPair();
    fgm = new FileGuardManager(encryptionKey.toString('hex'));
  });
  
  describe('Initialization', () => {
    test('should initialize correctly', () => {
      expect(fgm).toBeInstanceOf(FileGuardManager);
    });
    
    test('should be in fallback mode when NODE_ENV is test', () => {
      // This is testing a private property, so we need to use any
      expect((fgm as any).fallbackMode).toBe(true);
    });
    
    test('should not be in fallback mode when NODE_ENV is production', () => {
      // Save original NODE_ENV
      const originalNodeEnv = process.env.NODE_ENV;
      
      // Set NODE_ENV to production
      process.env.NODE_ENV = 'production';
      
      // Create a new FileGuardManager
      const prodFgm = new FileGuardManager(encryptionKey.toString('hex'));
      
      // Check fallback mode
      expect((prodFgm as any).fallbackMode).toBe(false);
      
      // Restore NODE_ENV
      process.env.NODE_ENV = originalNodeEnv;
    });
  });
  
  describe('Advanced Encryption and Decryption', () => {
    test('should encrypt and decrypt data with advanced encryption', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('advanced');
      
      // Encrypt data
      const encryptResult = await fgm.saveWithAdvancedEncryption(
        filePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: 'high',
          compressionLevel: 'medium',
          layers: 2,
          useAlgorithmRotation: true,
        }
      );
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filepath).toBe(filePath);
      expect(encryptResult.size.original).toBeGreaterThan(0);
      expect(encryptResult.size.encrypted).toBeGreaterThan(0);
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await fgm.loadWithAdvancedDecryption(
        filePath,
        encryptionKey,
        rsaKeyPair
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should handle different security levels', async () => {
      // Test security levels
      const securityLevels: SecurityLevel[] = ['standard', 'high', 'max'];
      
      for (const level of securityLevels) {
        // Test data
        const testData = {
          title: `${level} Security Test`,
          content: `This is a test with ${level} security level.`,
        };
        
        // File path
        const filePath = getTestFilePath(`security-${level}`);
        
        // Encrypt data
        await fgm.saveWithAdvancedEncryption(
          filePath,
          testData,
          encryptionKey,
          rsaKeyPair,
          {
            securityLevel: level,
            compressionLevel: 'medium',
          }
        );
        
        // Decrypt data
        const decryptedData = await fgm.loadWithAdvancedDecryption(
          filePath,
          encryptionKey,
          rsaKeyPair
        );
        
        // Verify decrypted data
        expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
      }
    });
    
    test('should handle different compression levels', async () => {
      // Test compression levels
      const compressionLevels: CompressionLevel[] = ['none', 'low', 'medium', 'high', 'maximum'];
      
      for (const level of compressionLevels) {
        // Test data - use larger data for compression testing
        const testData = generateLargeTestData(10); // 10KB
        
        // File path
        const filePath = getTestFilePath(`compression-${level}`);
        
        // Encrypt data
        const encryptResult = await fgm.saveWithAdvancedEncryption(
          filePath,
          testData,
          encryptionKey,
          rsaKeyPair,
          {
            securityLevel: 'standard',
            compressionLevel: level,
          }
        );
        
        // Decrypt data
        const decryptedData = await fgm.loadWithAdvancedDecryption(
          filePath,
          encryptionKey,
          rsaKeyPair
        );
        
        // Verify decrypted data
        expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
        
        // For compression levels other than 'none', expect some compression
        if (level !== 'none') {
          expect(encryptResult.size.encrypted).toBeLessThan(encryptResult.size.original);
        }
      }
    });
  });
  
  describe('Binary Format Encryption and Decryption', () => {
    test('should encrypt and decrypt data with binary secure format', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('binary-secure');
      
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
      expect(encryptResult.size.original).toBeGreaterThan(0);
      expect(encryptResult.size.encrypted).toBeGreaterThan(0);
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await fgm.loadWithBinarySecureFormat(
        filePath,
        encryptionKey,
        rsaKeyPair
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
    
    test('should encrypt and decrypt data with simple binary format', async () => {
      // Test data
      const testData = generateTestData();
      
      // File path
      const filePath = getTestFilePath('simple-binary');
      
      // Encrypt data
      const encryptResult = await fgm.saveWithSimpleBinaryFormat(
        filePath,
        testData,
        encryptionKey
      );
      
      // Verify encryption result
      expect(encryptResult).toBeDefined();
      expect(encryptResult.filepath).toBe(filePath);
      expect(encryptResult.size.original).toBeGreaterThan(0);
      expect(encryptResult.size.encrypted).toBeGreaterThan(0);
      
      // Verify file exists
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Decrypt data
      const decryptedData = await fgm.loadWithSimpleBinaryFormat(
        filePath,
        encryptionKey
      );
      
      // Verify decrypted data
      expect(verifyDataIntegrity(testData, decryptedData)).toBe(true);
    });
  });
});
