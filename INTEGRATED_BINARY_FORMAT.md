# NEHONIX FileGuard - Integrated Binary Format Guide

This document provides detailed information about the integrated binary format in the NEHONIX FileGuard library, which makes data completely unreadable by humans or other systems.

## Integrated Binary Format Features

The integrated binary format implements strong security standards:

1. **Fully Binary Format**: The entire file, including headers and metadata, is encrypted in binary format
2. **AES-256-GCM Encryption**: Data is protected with authenticated encryption
3. **Secure Key Derivation**: PBKDF2 with SHA-512 for key derivation
4. **Binary Obfuscation**: No readable text or JSON in the file
5. **Magic Bytes**: Hidden binary identifier for file format verification

## Using the Integrated Binary Format in Your Application

The integrated binary format is fully integrated into the FileGuardManager class, making it easy to use in your application:

```typescript
import { FileGuardManager } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

// Create a FileGuardManager
const fgm = new FileGuardManager(key.toString("hex"));

// Data to encrypt
const sensitiveData = {
  title: "TOP SECRET",
  content: "This is extremely sensitive content that requires the highest possible security protection.",
  credentials: {
    username: "admin",
    apiKey: "your-very-sensitive-api-key",
    accessToken: "your-very-sensitive-token"
  }
};

// Encrypt with integrated binary format
const result = await fgm.saveWithSimpleBinaryFormat(
  "path/to/secure-file.nxs",
  sensitiveData,
  key
);

// Later, decrypt the data
const decryptedData = await fgm.loadWithSimpleBinaryFormat(
  "path/to/secure-file.nxs",
  key
);
```

## Integrated Binary Format Structure

The integrated binary file format uses the following structure:

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

## Running the Integrated Binary Format Demo

To see the integrated binary format in action, run:

```bash
npm run demo:integrated-binary
```

The demo will:

1. Generate a cryptographically secure encryption key
2. Create a FileGuardManager instance
3. Encrypt sample top-secret data using the integrated binary format
4. Show the encrypted data (which is completely unreadable)
5. Decrypt the data and verify it matches the original

## Technical Details

The integrated binary format implementation uses:

- **Encryption Algorithm**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Derivation**: PBKDF2 with SHA-512, 10,000 iterations
- **Initialization Vector**: 16 random bytes
- **Salt**: 16 random bytes
- **Authentication Tag**: 16 bytes
- **Associated Data**: "simple-binary-format" string

## Security Guarantees

With proper implementation, the integrated binary format provides:

- **Confidentiality**: Data is completely unreadable without the correct key
- **Integrity**: Any tampering with the encrypted data is detectable
- **Authentication**: Only authorized users with the correct key can access the data

Remember that the security of the system depends on keeping the encryption key secure. The encrypted data is only as secure as the key management system.
