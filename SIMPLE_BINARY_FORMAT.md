# NEHONIX FileGuard - Simple Binary Format Guide

This document provides detailed information about the simple binary format in the NEHONIX FileGuard library, which makes data completely unreadable by humans or other systems.

## Simple Binary Format Features

The simple binary format implements strong security standards:

1. **Fully Binary Format**: The entire file, including headers and metadata, is encrypted in binary format
2. **AES-256-GCM Encryption**: Data is protected with authenticated encryption
3. **Secure Key Derivation**: PBKDF2 with SHA-512 for key derivation
4. **Binary Obfuscation**: No readable text or JSON in the file
5. **Magic Bytes**: Hidden binary identifier for file format verification

## Using the Simple Binary Format in Your Application

The simple binary format is easy to use in your application:

```typescript
import { SimpleBinaryFormat } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

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

// Encrypt with simple binary format
await SimpleBinaryFormat.encrypt(sensitiveData, key, "path/to/secure-file.nxs");

// Later, decrypt the data
const decryptedData = await SimpleBinaryFormat.decrypt(
  "path/to/secure-file.nxs",
  key
);
```

## Simple Binary Format Structure

The simple binary file format uses the following structure:

```
[Magic Bytes (6)] [IV (16)] [Salt (16)] [Encrypted Size (4)] [Encrypted Content]
```

Where:

- **Magic Bytes**: Binary identifier "NXSBIN" (not human-readable)
- **IV**: Initialization Vector for encryption
- **Salt**: Salt for key derivation
- **Encrypted Size**: Size of the encrypted content (4 bytes)
- **Encrypted Content**: The encrypted data with auth tag

The encrypted content itself contains:

- **Auth Tag (16 bytes)**: Authentication tag for GCM mode
- **Encrypted Data**: The encrypted header and data

## Running the Simple Binary Format Demo

To see the simple binary format in action, run:

```bash
npm run demo:simple-binary
```

The demo will:

1. Generate a cryptographically secure encryption key
2. Encrypt sample top-secret data using the simple binary format
3. Show the encrypted data (which is completely unreadable)
4. Decrypt the data and verify it matches the original

## Technical Details

The simple binary format implementation uses:

- **Encryption Algorithm**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Derivation**: PBKDF2 with SHA-512, 10,000 iterations
- **Initialization Vector**: 16 random bytes
- **Salt**: 16 random bytes
- **Authentication Tag**: 16 bytes
- **Associated Data**: "simple-binary-format" string

## Security Guarantees

With proper implementation, the simple binary format provides:

- **Confidentiality**: Data is completely unreadable without the correct key
- **Integrity**: Any tampering with the encrypted data is detectable
- **Authentication**: Only authorized users with the correct key can access the data

Remember that the security of the system depends on keeping the encryption key secure. The encrypted data is only as secure as the key management system.
