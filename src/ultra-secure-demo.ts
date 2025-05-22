/**
 * Ultra-Secure Demo for NEHONIX FileGuard
 * Demonstrates the ultra-secure encryption capabilities
 */

import * as crypto from 'crypto';
import { 
  FileGuardManager, 
  createPersistentRSAFGM,
  logger,
  ProgressTracker,
  OperationType
} from './index';

// Set log level to debug for detailed output
logger.setLogLevel('debug');

/**
 * Run the ultra-secure demo
 */
async function runUltraSecureDemo() {
  console.log('\n🔒 NEHONIX FileGuard Ultra-Secure Demo 🔒\n');
  
  // Generate an encryption key
  const key = crypto.randomBytes(32);
  console.log(`Generated encryption key: ${key.toString('hex').slice(0, 16)}...`);
  
  // Create a FileGuardManager with persistent RSA keys
  console.log('\n📝 Creating FileGuardManager with persistent RSA keys...');
  const fgm = createPersistentRSAFGM(key.toString('hex'), {
    rsaKeysPath: './demo-files/ultra-secure-rsa-keys.json'
  });
  
  // Data to encrypt
  const data = {
    title: 'Top Secret Document',
    content: 'This is extremely sensitive content that needs the highest level of protection.',
    metadata: {
      author: 'Security Officer',
      date: new Date().toISOString(),
      classification: 'TOP SECRET',
      tags: ['classified', 'sensitive', 'top-secret']
    }
  };
  
  console.log('\n📋 Data to encrypt:');
  console.log(JSON.stringify(data, null, 2));
  
  // Demo ultra-secure encryption
  console.log('\n🔐 Ultra-Secure Encryption Demo');
  await ultraSecureEncryptionDemo('./demo-files/ultra-secure.nxs', data, key, fgm.rsaKeyPair);
  
  console.log('\n✅ Ultra-Secure Demo completed successfully!');
}

/**
 * Ultra-secure encryption demo
 */
async function ultraSecureEncryptionDemo(
  filepath: string,
  data: any,
  key: Buffer,
  rsaKeyPair: { publicKey: string; privateKey: string }
) {
  // Create a FileGuardManager
  const fgm = new FileGuardManager(key.toString('hex'));
  
  // Configure encryption with maximum security
  const config = {
    securityLevel: 'max' as const, // Required property
    encryptLevel: 'max' as const,
    compressionLevel: 'maximum' as const,
    layers: 5,
    useAlgorithmRotation: true,
    addHoneypots: true
  };
  
  console.log(`Encrypting with ultra-secure protection...`);
  console.log(`Configuration: ${JSON.stringify(config)}`);
  
  // Encrypt the data with ultra-secure protection
  console.log('\nStep 1: Encrypting with ultra-secure protection...');
  const encryptResult = await fgm.saveWithUltraSecureEncryption(
    filepath,
    data,
    key,
    rsaKeyPair,
    config
  );
  
  console.log(`\nEncryption result: ${JSON.stringify(encryptResult, null, 2)}`);
  
  // Decrypt the data with ultra-secure decryption
  console.log('\nStep 2: Decrypting with ultra-secure protection...');
  const decryptedData = await fgm.loadWithUltraSecureDecryption(
    filepath,
    key,
    rsaKeyPair
  );
  
  console.log(`\nDecryption successful: ${JSON.stringify(decryptedData) === JSON.stringify(data)}`);
  
  // Compare original and decrypted data
  console.log('\nOriginal data:');
  console.log(JSON.stringify(data, null, 2));
  
  console.log('\nDecrypted data:');
  console.log(JSON.stringify(decryptedData, null, 2));
  
  // Show security features
  console.log('\n🛡️ Security Features Used:');
  console.log('- Memory-hard key derivation (resistant to hardware attacks)');
  console.log('- Post-quantum cryptography (resistant to quantum computers)');
  console.log('- Multiple encryption layers with algorithm rotation');
  console.log('- Honeypot data to confuse attackers');
  console.log('- Secure random number generation');
  
  // Show file size comparison
  const compressionRatio = encryptResult.size.original / encryptResult.size.encrypted;
  console.log('\n📊 File Size:');
  console.log(`- Original: ${encryptResult.size.original} bytes`);
  console.log(`- Encrypted: ${encryptResult.size.encrypted} bytes`);
  console.log(`- Compression ratio: ${compressionRatio.toFixed(2)}`);
  
  // Show metadata
  console.log('\n📋 Metadata:');
  console.log(JSON.stringify(encryptResult.metadata, null, 2));
}

// Run the demo
runUltraSecureDemo().catch(error => {
  console.error('Demo failed:', error);
});
