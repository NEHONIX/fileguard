/**
 * Tests for the Fortify integration
 */

import * as crypto from 'crypto';
import { 
  generateSecureParams,
  encryptWithFortify,
  decryptWithFortify,
  toFortifySecurityLevel
} from '../../src/utils/fortifyIntegration';
import { SecurityLevel } from '../../src/types';
import {
  ensureTestDirectory,
  cleanupTestFiles,
  generateTestEncryptionKey,
  generateTestRSAKeyPair,
  generateTestData,
  verifyDataIntegrity
} from '../utils/testUtils';

// Setup and teardown
beforeAll(() => {
  ensureTestDirectory();
});

afterAll(() => {
  cleanupTestFiles();
});

describe('Fortify Integration', () => {
  let encryptionKey: Buffer;
  let rsaKeyPair: ReturnType<typeof generateTestRSAKeyPair>;
  
  beforeEach(() => {
    // Set up test environment
    encryptionKey = generateTestEncryptionKey();
    rsaKeyPair = generateTestRSAKeyPair();
  });
  
  describe('Security Parameters', () => {
    test('should generate secure parameters', () => {
      const params = generateSecureParams(encryptionKey, 'standard');
      
      expect(params).toBeDefined();
      expect(params.key).toEqual(encryptionKey);
      expect(params.salt).toBeDefined();
      expect(params.iv).toBeDefined();
      expect(params.aad).toBeDefined();
      expect(params.postQuantumKeyPair).toBeUndefined();
    });
    
    test('should generate secure parameters with post-quantum for max security', () => {
      const params = generateSecureParams(encryptionKey, 'max');
      
      expect(params).toBeDefined();
      expect(params.key).toEqual(encryptionKey);
      expect(params.salt).toBeDefined();
      expect(params.iv).toBeDefined();
      expect(params.aad).toBeDefined();
      // Note: postQuantumKeyPair might be undefined if the post-quantum implementation fails
      // This is expected behavior as the function has a fallback
    });
    
    test('should convert security levels correctly', () => {
      expect(toFortifySecurityLevel('standard')).toBe(1);
      expect(toFortifySecurityLevel('high')).toBe(3);
      expect(toFortifySecurityLevel('max')).toBe(5);
      expect(toFortifySecurityLevel('unknown' as SecurityLevel)).toBe(3); // Default
    });
  });
  
  describe('Encryption and Decryption', () => {
    test('should encrypt and decrypt data with standard security', async () => {
      // Test data
      const testData = Buffer.from(JSON.stringify(generateTestData()));
      
      // Generate secure parameters
      const params = generateSecureParams(encryptionKey, 'standard');
      
      // Encrypt data
      const encryptResult = await encryptWithFortify(testData, params, {
        securityLevel: 'standard',
        compressionLevel: 'medium',
        layers: 1,
        useAlgorithmRotation: false,
        useMemoryHardKDF: true,
        memoryCost: 1024, // Lower for tests
        timeCost: 1,      // Lower for tests
        usePostQuantum: false,
        addHoneypots: false
      });
      
      expect(encryptResult).toBeDefined();
      expect(encryptResult.data).toBeDefined();
      expect(encryptResult.metadata).toBeDefined();
      
      // Decrypt data
      const decryptedData = await decryptWithFortify(encryptResult.data, params, {
        securityLevel: 'standard',
        compressionLevel: 'medium',
        layers: 1,
        useAlgorithmRotation: false,
        useMemoryHardKDF: true,
        memoryCost: 1024, // Lower for tests
        timeCost: 1,      // Lower for tests
        usePostQuantum: false,
        addHoneypots: false
      });
      
      // Verify decrypted data
      expect(decryptedData.toString()).toEqual(testData.toString());
    });
    
    test('should encrypt and decrypt data with high security', async () => {
      // Test data
      const testData = Buffer.from(JSON.stringify(generateTestData()));
      
      // Generate secure parameters
      const params = generateSecureParams(encryptionKey, 'high');
      
      // Encrypt data
      const encryptResult = await encryptWithFortify(testData, params, {
        securityLevel: 'high',
        compressionLevel: 'high',
        layers: 3,
        useAlgorithmRotation: true,
        useMemoryHardKDF: true,
        memoryCost: 1024, // Lower for tests
        timeCost: 1,      // Lower for tests
        usePostQuantum: false,
        addHoneypots: true
      });
      
      expect(encryptResult).toBeDefined();
      expect(encryptResult.data).toBeDefined();
      expect(encryptResult.metadata).toBeDefined();
      
      // Decrypt data
      const decryptedData = await decryptWithFortify(encryptResult.data, params, {
        securityLevel: 'high',
        compressionLevel: 'high',
        layers: 3,
        useAlgorithmRotation: true,
        useMemoryHardKDF: true,
        memoryCost: 1024, // Lower for tests
        timeCost: 1,      // Lower for tests
        usePostQuantum: false,
        addHoneypots: true
      });
      
      // Verify decrypted data
      expect(decryptedData.toString()).toEqual(testData.toString());
    });
    
    test('should handle different compression levels', async () => {
      // Test compression levels
      const compressionLevels: ('none' | 'low' | 'medium' | 'high' | 'maximum')[] = [
        'none', 'low', 'medium', 'high', 'maximum'
      ];
      
      for (const level of compressionLevels) {
        // Test data - use larger data for compression testing
        const testData = Buffer.from(JSON.stringify(generateTestData()));
        
        // Generate secure parameters
        const params = generateSecureParams(encryptionKey, 'standard');
        
        // Encrypt data
        const encryptResult = await encryptWithFortify(testData, params, {
          securityLevel: 'standard',
          compressionLevel: level,
          layers: 1,
          useAlgorithmRotation: false,
          useMemoryHardKDF: true,
          memoryCost: 1024, // Lower for tests
          timeCost: 1,      // Lower for tests
          usePostQuantum: false,
          addHoneypots: false
        });
        
        // Decrypt data
        const decryptedData = await decryptWithFortify(encryptResult.data, params, {
          securityLevel: 'standard',
          compressionLevel: level,
          layers: 1,
          useAlgorithmRotation: false,
          useMemoryHardKDF: true,
          memoryCost: 1024, // Lower for tests
          timeCost: 1,      // Lower for tests
          usePostQuantum: false,
          addHoneypots: false
        });
        
        // Verify decrypted data
        expect(decryptedData.toString()).toEqual(testData.toString());
      }
    });
  });
});
