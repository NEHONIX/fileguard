# NEHONIX FileGuard - Binary Format Integration Guide

This document provides detailed information about the integrated binary format in the NEHONIX FileGuard library, which makes data completely unreadable by humans or other systems except by the FileGuardManager class itself.

## Binary Format Features

The integrated binary format implements the highest possible security standards:

1. **Fully Binary Format**: The entire file, including headers and metadata, is encrypted in binary format
2. **Multi-Layer Encryption**: Data is protected with multiple layers of encryption
3. **Algorithm Rotation**: Different encryption algorithms for each layer
4. **RSA Encryption Layer**: Asymmetric encryption for additional security
5. **Secure Key Derivation**: Memory-hard key derivation functions
6. **Binary Obfuscation**: No readable text or JSON in the file
7. **Magic Bytes**: Hidden binary identifier for file format verification

## Using the Binary Format in Your Application

The binary format is fully integrated into the FileGuardManager class, making it easy to use in your application:

```typescript
import { FileGuardManager, createPersistentRSAFGM } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

// Create a FileGuardManager with persistent RSA keys
const fgm = createPersistentRSAFGM(key.toString("hex"), {
  rsaKeysPath: "./secure-keys.json",
});

// Data to encrypt
const sensitiveData = {
  title: "TOP SECRET",
  content:
    "This is extremely sensitive content that requires the highest possible security protection.",
  credentials: {
    username: "admin",
    apiKey: "your-very-sensitive-api-key",
    accessToken: "your-very-sensitive-token",
  },
};

// Encrypt with binary format
await fgm.saveWithBinarySecureFormat(
  "path/to/secure-file.nxs",
  sensitiveData,
  key,
  fgm.rsaKeyPair,
  {
    layers: 5,
    addRandomPadding: true,
    compressionLevel: 9,
  }
);

// Later, decrypt the data
const decryptedData = await fgm.loadWithBinarySecureFormat(
  "path/to/secure-file.nxs",
  key,
  fgm.rsaKeyPair
);
```

## Binary Format Options

When using the binary format, you can customize the security level with these options:

- **layers**: Number of encryption layers (default: 3)
- **addRandomPadding**: Add random padding to the encrypted file to make size analysis more difficult (default: false)
- **compressionLevel**: Compression level from 0 (no compression) to 9 (maximum compression) (default: 9)

## Binary Format Structure

The binary file format uses the following structure:

```
[Magic Bytes (6)] [IV (16)] [Salt (16)] [Encrypted Size (4)] [Encrypted Content]
```

Where:

- **Magic Bytes**: Binary identifier "NXSBIN" (not human-readable)
- **IV**: Initialization Vector for encryption
- **Salt**: Salt for key derivation
- **Encrypted Size**: Size of the encrypted content (4 bytes)
- **Encrypted Content**: The encrypted data with multiple layers

The encrypted content itself contains multiple layers of encryption, each with its own metadata that is also encrypted.

## Running the Binary Format Demo

To see the binary format in action, run:

```bash
npm run demo:binary-format
```

The demo will:

1. Generate a cryptographically secure encryption key
2. Create a FileGuardManager with persistent RSA keys
3. Encrypt sample top-secret data using the binary format
4. Show the encrypted data (which is completely unreadable)
5. Decrypt the data and verify it matches the original

## Technical Details

The binary format implementation uses:

- **Encryption Algorithms**: AES-256-GCM, Camellia-256-CBC, AES-256-CTR, ARIA-256-GCM, AES-256-CBC
- **Key Derivation**: PBKDF2 with SHA-512, 10,000+ iterations
- **Asymmetric Encryption**: RSA with OAEP padding
- **Compression**: DEFLATE algorithm with maximum compression
- **Binary Obfuscation**: No readable text or JSON in the file

## Security Guarantees

With proper implementation, the binary format provides:

- **Confidentiality**: Data is completely unreadable without the correct keys
- **Integrity**: Any tampering with the encrypted data is detectable
- **Authentication**: Only authorized users with the correct keys can access the data
- **Forward Secrecy**: Compromise of one file doesn't compromise others

Remember that the security of the system depends on keeping the encryption keys secure. The encrypted data is only as secure as the key management system.
