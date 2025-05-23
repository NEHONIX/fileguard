/**
 * Performance tests for NEHONIX FileGuard
 * These tests measure the performance of different encryption methods
 */

import * as fs from 'fs';
import { FileGuardManager } from '../../src/core/FileGuardManager';
import { BinarySecureFormat } from '../../src/core/BinarySecureFormat';
import { SimpleBinaryFormat } from '../../src/core/SimpleBinaryFormat';
import { encryptData, decryptData } from '../../src/utils/cryptUtils';
import { SecurityLevel, CompressionLevel } from '../../src/types';
import {
  ensureTestDirectory,
  cleanupTestFiles,
  generateTestEncryptionKey,
  generateTestRSAKeyPair,
  generateLargeTestData,
  verifyDataIntegrity,
  getTestFilePath,
  measureExecutionTime,
  TEST_DIR
} from '../utils/testUtils';

// Setup and teardown
beforeAll(() => {
  ensureTestDirectory();
  
  // Set NODE_ENV to test to enable fallback mode
  process.env.NODE_ENV = 'test';
  
  // Increase Jest timeout for performance tests
  jest.setTimeout(60000); // 60 seconds
});

afterAll(() => {
  cleanupTestFiles();
});

// Clean up after each test
afterEach(() => {
  cleanupTestFiles();
});

describe('Performance Tests', () => {
  let fgm: FileGuardManager;
  let encryptionKey: Buffer;
  let rsaKeyPair: ReturnType<typeof generateTestRSAKeyPair>;
  
  beforeEach(() => {
    // Set up test environment
    encryptionKey = generateTestEncryptionKey();
    rsaKeyPair = generateTestRSAKeyPair();
    fgm = new FileGuardManager(encryptionKey.toString('hex'));
  });
  
  describe('Encryption Performance', () => {
    test('should measure performance of different encryption methods', async () => {
      // Generate test data of different sizes
      const smallData = generateLargeTestData(10);  // 10KB
      const mediumData = generateLargeTestData(100); // 100KB
      const largeData = generateLargeTestData(1000); // 1MB
      
      // Test configurations
      const configs = [
        { name: 'Advanced Encryption (Standard)', securityLevel: 'standard' as SecurityLevel, compressionLevel: 'medium' as CompressionLevel },
        { name: 'Advanced Encryption (High)', securityLevel: 'high' as SecurityLevel, compressionLevel: 'medium' as CompressionLevel },
        { name: 'Advanced Encryption (Max)', securityLevel: 'max' as SecurityLevel, compressionLevel: 'medium' as CompressionLevel },
        { name: 'Binary Secure Format', useBinaryFormat: true },
        { name: 'Simple Binary Format', useSimpleBinary: true }
      ];
      
      // Results object
      const results: Record<string, Record<string, { encrypt: number, decrypt: number, ratio: number }>> = {};
      
      // Test each configuration with each data size
      for (const config of configs) {
        results[config.name] = {};
        
        // Test with small data
        const smallFilePath = getTestFilePath(`perf-${config.name.toLowerCase().replace(/\s+/g, '-')}-small`);
        const smallResult = await testEncryptionPerformance(smallData, smallFilePath, config);
        results[config.name]['Small (10KB)'] = smallResult;
        
        // Test with medium data
        const mediumFilePath = getTestFilePath(`perf-${config.name.toLowerCase().replace(/\s+/g, '-')}-medium`);
        const mediumResult = await testEncryptionPerformance(mediumData, mediumFilePath, config);
        results[config.name]['Medium (100KB)'] = mediumResult;
        
        // Test with large data only for faster methods
        if (config.name !== 'Advanced Encryption (Max)') {
          const largeFilePath = getTestFilePath(`perf-${config.name.toLowerCase().replace(/\s+/g, '-')}-large`);
          const largeResult = await testEncryptionPerformance(largeData, largeFilePath, config);
          results[config.name]['Large (1MB)'] = largeResult;
        }
      }
      
      // Log results in a table format
      console.table(results);
      
      // Verify that all tests completed successfully
      expect(Object.keys(results).length).toBeGreaterThan(0);
    });
    
    /**
     * Test encryption performance for a specific configuration
     */
    async function testEncryptionPerformance(
      data: any,
      filePath: string,
      config: any
    ): Promise<{ encrypt: number, decrypt: number, ratio: number }> {
      let encryptTime = 0;
      let decryptTime = 0;
      let encryptedSize = 0;
      let originalSize = 0;
      
      if (config.useSimpleBinary) {
        // Test SimpleBinaryFormat
        const encryptResult = await measureExecutionTime(async () => {
          return await SimpleBinaryFormat.encrypt(data, encryptionKey, filePath);
        });
        encryptTime = encryptResult.executionTimeMs;
        
        const decryptResult = await measureExecutionTime(async () => {
          return await SimpleBinaryFormat.decrypt(filePath, encryptionKey);
        });
        decryptTime = decryptResult.executionTimeMs;
        
        // Get file size
        encryptedSize = fs.statSync(filePath).size;
        originalSize = Buffer.from(JSON.stringify(data)).length;
      } else if (config.useBinaryFormat) {
        // Test BinarySecureFormat
        const encryptResult = await measureExecutionTime(async () => {
          return await BinarySecureFormat.encrypt(
            data,
            encryptionKey,
            rsaKeyPair,
            filePath,
            {
              layers: 2,
              addRandomPadding: true,
            }
          );
        });
        encryptTime = encryptResult.executionTimeMs;
        
        const decryptResult = await measureExecutionTime(async () => {
          return await BinarySecureFormat.decrypt(filePath, encryptionKey, rsaKeyPair);
        });
        decryptTime = decryptResult.executionTimeMs;
        
        // Get file size
        encryptedSize = fs.statSync(filePath).size;
        originalSize = Buffer.from(JSON.stringify(data)).length;
      } else {
        // Test Advanced Encryption
        const encryptResult = await measureExecutionTime(async () => {
          return await fgm.saveWithAdvancedEncryption(
            filePath,
            data,
            encryptionKey,
            rsaKeyPair,
            {
              securityLevel: config.securityLevel,
              compressionLevel: config.compressionLevel,
              layers: config.securityLevel === 'standard' ? 1 : (config.securityLevel === 'high' ? 2 : 3),
              useAlgorithmRotation: config.securityLevel !== 'standard',
            }
          );
        });
        encryptTime = encryptResult.executionTimeMs;
        originalSize = encryptResult.result.size.original;
        encryptedSize = encryptResult.result.size.encrypted;
        
        const decryptResult = await measureExecutionTime(async () => {
          return await fgm.loadWithAdvancedDecryption(filePath, encryptionKey, rsaKeyPair);
        });
        decryptTime = decryptResult.executionTimeMs;
      }
      
      return {
        encrypt: encryptTime,
        decrypt: decryptTime,
        ratio: originalSize / encryptedSize
      };
    }
  });
  
  describe('Simplified API Performance', () => {
    test('should measure performance of simplified API', async () => {
      // Generate test data
      const testData = generateLargeTestData(100); // 100KB
      
      // File path
      const filePath = getTestFilePath('simplified-api-perf');
      
      // Measure encryption time
      const encryptResult = await measureExecutionTime(async () => {
        return await encryptData(testData, filePath, {
          securityLevel: 'high',
          compressionLevel: 'medium',
          layers: 2,
          useAlgorithmRotation: true,
        });
      });
      
      // Measure decryption time
      const decryptResult = await measureExecutionTime(async () => {
        return await decryptData(
          filePath,
          encryptResult.result.encryptionKeyHex,
          encryptResult.result.rsaKeyPair!
        );
      });
      
      // Log results
      console.log('Simplified API Performance:');
      console.log(`Encryption time: ${encryptResult.executionTimeMs}ms`);
      console.log(`Decryption time: ${decryptResult.executionTimeMs}ms`);
      console.log(`Original size: ${encryptResult.result.originalSize} bytes`);
      console.log(`Encrypted size: ${encryptResult.result.encryptedSize} bytes`);
      if (encryptResult.result.compressionRatio) {
        console.log(`Compression ratio: ${encryptResult.result.compressionRatio.toFixed(2)}`);
      }
      
      // Verify that the test completed successfully
      expect(encryptResult.executionTimeMs).toBeGreaterThan(0);
      expect(decryptResult.executionTimeMs).toBeGreaterThan(0);
      expect(verifyDataIntegrity(testData, decryptResult.result)).toBe(true);
    });
  });
});
