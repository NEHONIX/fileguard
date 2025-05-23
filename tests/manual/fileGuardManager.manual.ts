/**
 * Manual test for FileGuardManager
 * Run with: npx ts-node tests/manual/fileGuardManager.manual.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { FileGuardManager } from '../../dist/core/FileGuardManager';
import { SecurityLevel, CompressionLevel } from '../../dist/types';

// Create output directory
const TEST_DIR = path.join(__dirname, '..', 'output');
if (!fs.existsSync(TEST_DIR)) {
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

// Generate a test file path
function getTestFilePath(prefix: string = 'test', extension: string = '.nxs'): string {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  return path.join(TEST_DIR, `${prefix}-${timestamp}-${random}${extension}`);
}

// Generate a random encryption key
function generateTestEncryptionKey(): Buffer {
  return crypto.randomBytes(32);
}

// Generate an RSA key pair
function generateTestRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  
  return { publicKey, privateKey };
}

// Generate test data
function generateTestData(): any {
  return {
    title: 'Test Document',
    timestamp: new Date().toISOString(),
    content: 'This is a test document with some content for encryption testing.',
    numbers: [1, 2, 3, 4, 5],
    nested: {
      field1: 'value1',
      field2: 123,
      field3: true,
      deepNested: {
        array: ['a', 'b', 'c'],
        date: new Date().toISOString(),
      }
    },
    boolean: true,
    nullValue: null,
    metadata: {
      author: 'Test Author',
      tags: ['test', 'encryption', 'security'],
      version: '1.0.0',
    }
  };
}

// Verify data integrity
function verifyDataIntegrity(original: any, decrypted: any): boolean {
  const normalizedOriginal = JSON.parse(JSON.stringify(original));
  const normalizedDecrypted = JSON.parse(JSON.stringify(decrypted));
  
  return JSON.stringify(normalizedOriginal) === JSON.stringify(normalizedDecrypted);
}

// Measure execution time
async function measureExecutionTime<T>(fn: () => Promise<T>): Promise<{ result: T, executionTimeMs: number }> {
  const startTime = Date.now();
  const result = await fn();
  const endTime = Date.now();
  return {
    result,
    executionTimeMs: endTime - startTime
  };
}

// Run the test
async function runTest() {
  console.log('=== Manual Test: FileGuardManager ===\n');
  
  try {
    // Generate encryption key and RSA key pair
    const encryptionKey = generateTestEncryptionKey();
    const rsaKeyPair = generateTestRSAKeyPair();
    
    // Create FileGuardManager instance
    const fgm = new FileGuardManager(encryptionKey.toString('hex'));
    console.log('Created FileGuardManager instance');
    
    // Test 1: Advanced Encryption
    console.log('\nTest 1: Advanced Encryption');
    const testData = generateTestData();
    const filePath = getTestFilePath('advanced');
    
    console.log('Encrypting data with advanced encryption...');
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
    
    console.log('Advanced encryption successful!');
    console.log(`File saved to: ${encryptResult.filepath}`);
    console.log(`Original size: ${encryptResult.size.original} bytes`);
    console.log(`Encrypted size: ${encryptResult.size.encrypted} bytes`);
    
    if (encryptResult.compressionRatio !== undefined) {
      console.log(`Compression ratio: ${encryptResult.compressionRatio.toFixed(2)}`);
    }
    
    // Add a small delay to ensure file system operations are complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify the file exists
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log(`\nFile exists at ${filePath}, size: ${fs.statSync(filePath).size} bytes`);
    
    console.log('\nDecrypting data with advanced decryption...');
    const decryptedData = await fgm.loadWithAdvancedDecryption(
      filePath,
      encryptionKey,
      rsaKeyPair
    );
    
    console.log('Advanced decryption successful!');
    
    // Verify data integrity
    const isEqual = verifyDataIntegrity(testData, decryptedData);
    console.log(`Data integrity check: ${isEqual ? 'PASSED ✓' : 'FAILED ✗'}`);
    
    // Test 2: Binary Secure Format
    console.log('\nTest 2: Binary Secure Format');
    const binaryFilePath = getTestFilePath('binary-secure');
    
    console.log('Encrypting data with binary secure format...');
    const binaryEncryptResult = await fgm.saveWithBinarySecureFormat(
      binaryFilePath,
      testData,
      encryptionKey,
      rsaKeyPair,
      {
        layers: 3,
        addRandomPadding: true,
      }
    );
    
    console.log('Binary secure encryption successful!');
    console.log(`File saved to: ${binaryEncryptResult.filepath}`);
    console.log(`Original size: ${binaryEncryptResult.size.original} bytes`);
    console.log(`Encrypted size: ${binaryEncryptResult.size.encrypted} bytes`);
    
    // Add a small delay to ensure file system operations are complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify the file exists
    if (!fs.existsSync(binaryFilePath)) {
      throw new Error(`File not found: ${binaryFilePath}`);
    }
    
    console.log(`\nFile exists at ${binaryFilePath}, size: ${fs.statSync(binaryFilePath).size} bytes`);
    
    console.log('\nDecrypting data with binary secure format...');
    const binaryDecryptedData = await fgm.loadWithBinarySecureFormat(
      binaryFilePath,
      encryptionKey,
      rsaKeyPair
    );
    
    console.log('Binary secure decryption successful!');
    
    // Verify data integrity
    const binaryIsEqual = verifyDataIntegrity(testData, binaryDecryptedData);
    console.log(`Binary data integrity check: ${binaryIsEqual ? 'PASSED ✓' : 'FAILED ✗'}`);
    
    // Test 3: Simple Binary Format
    console.log('\nTest 3: Simple Binary Format');
    const simpleBinaryFilePath = getTestFilePath('simple-binary');
    
    console.log('Encrypting data with simple binary format...');
    const simpleBinaryEncryptResult = await fgm.saveWithSimpleBinaryFormat(
      simpleBinaryFilePath,
      testData,
      encryptionKey
    );
    
    console.log('Simple binary encryption successful!');
    console.log(`File saved to: ${simpleBinaryEncryptResult.filepath}`);
    console.log(`Original size: ${simpleBinaryEncryptResult.size.original} bytes`);
    console.log(`Encrypted size: ${simpleBinaryEncryptResult.size.encrypted} bytes`);
    
    // Add a small delay to ensure file system operations are complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify the file exists
    if (!fs.existsSync(simpleBinaryFilePath)) {
      throw new Error(`File not found: ${simpleBinaryFilePath}`);
    }
    
    console.log(`\nFile exists at ${simpleBinaryFilePath}, size: ${fs.statSync(simpleBinaryFilePath).size} bytes`);
    
    console.log('\nDecrypting data with simple binary format...');
    const simpleBinaryDecryptedData = await fgm.loadWithSimpleBinaryFormat(
      simpleBinaryFilePath,
      encryptionKey
    );
    
    console.log('Simple binary decryption successful!');
    
    // Verify data integrity
    const simpleBinaryIsEqual = verifyDataIntegrity(testData, simpleBinaryDecryptedData);
    console.log(`Simple binary data integrity check: ${simpleBinaryIsEqual ? 'PASSED ✓' : 'FAILED ✗'}`);
    
    // Test 4: Security Levels
    console.log('\nTest 4: Security Levels');
    
    // Test different security levels
    const securityLevels: SecurityLevel[] = ['standard', 'high', 'max'];
    
    for (const level of securityLevels) {
      console.log(`\nTesting security level: ${level}`);
      
      const securityFilePath = getTestFilePath(`security-${level}`);
      
      console.log(`Encrypting data with ${level} security...`);
      const securityEncryptResult = await fgm.saveWithAdvancedEncryption(
        securityFilePath,
        testData,
        encryptionKey,
        rsaKeyPair,
        {
          securityLevel: level,
          compressionLevel: 'medium',
          layers: level === 'standard' ? 1 : (level === 'high' ? 2 : 3),
          useAlgorithmRotation: level !== 'standard',
        }
      );
      
      console.log(`${level} security encryption successful!`);
      
      // Add a small delay to ensure file system operations are complete
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      console.log(`Decrypting data with ${level} security...`);
      const securityDecryptedData = await fgm.loadWithAdvancedDecryption(
        securityFilePath,
        encryptionKey,
        rsaKeyPair
      );
      
      console.log(`${level} security decryption successful!`);
      
      // Verify data integrity
      const securityIsEqual = verifyDataIntegrity(testData, securityDecryptedData);
      console.log(`${level} security data integrity check: ${securityIsEqual ? 'PASSED ✓' : 'FAILED ✗'}`);
    }
    
    console.log('\n=== All tests completed successfully! ===');
    return true;
  } catch (error) {
    console.error('\nTest failed with error:', error);
    return false;
  }
}

// Run the test
runTest()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
  });
