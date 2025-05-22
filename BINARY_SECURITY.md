# NEHONIX FileGuard - Binary Security Guide

This document provides detailed information about the binary security format of the NEHONIX FileGuard library, which makes data completely unreadable by humans or other systems except by the FileGuardManager class itself.

## Binary Security Features

The binary security format implements the highest possible security standards:

1. **Fully Binary Format**: The entire file, including headers and metadata, is encrypted in binary format
2. **Multi-Layer Encryption**: Data is protected with multiple layers of encryption
3. **Algorithm Rotation**: Different encryption algorithms for each layer
4. **RSA Encryption Layer**: Asymmetric encryption for additional security
5. **Secure Key Derivation**: Memory-hard key derivation functions
6. **Binary Obfuscation**: No readable text or JSON in the file
7. **Magic Bytes**: Hidden binary identifier for file format verification

## Running the Binary Security Demo

To see these security features in action, run:

```bash
npm run demo:binary
```

The demo will:

1. Generate a cryptographically secure encryption key
2. Create a FileGuardManager with persistent RSA keys
3. Encrypt sample top-secret data using the binary format
4. Show the encrypted data (which is completely unreadable)
5. Decrypt the data and verify it matches the original

## Binary File Format Structure

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

## Implementation in Your Code

To implement the binary security format in your application:

```typescript
import { BinarySecureFormat } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

// Create RSA key pair
const rsaKeyPair = {
  publicKey: "...", // Your RSA public key
  privateKey: "..." // Your RSA private key
};

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

// Encrypt with binary format
await BinarySecureFormat.encrypt(
  sensitiveData,
  key,
  rsaKeyPair,
  "path/to/secure-file.nxs"
);

// Later, decrypt the data
const decryptedData = await BinarySecureFormat.decrypt(
  "path/to/secure-file.nxs",
  key,
  rsaKeyPair
);
```

## Security Best Practices

For maximum security:

1. **Key Management**: Store encryption keys securely, never in plain text
2. **Use Multiple Layers**: Always use multiple encryption layers
3. **Algorithm Rotation**: Use different algorithms for each layer
4. **Secure Memory**: Clear sensitive data from memory after use
5. **Regular Key Rotation**: Change encryption keys periodically
6. **Physical Security**: Protect the devices where encrypted files are stored
7. **Access Control**: Limit who can access the encryption keys

## Technical Details

The binary security implementation uses:

- **Encryption Algorithms**: AES-256-GCM, Camellia-256-CBC, AES-256-CTR
- **Key Derivation**: PBKDF2 with SHA-512, 10,000+ iterations
- **Asymmetric Encryption**: RSA with OAEP padding
- **Compression**: DEFLATE algorithm with maximum compression
- **Binary Obfuscation**: No readable text or JSON in the file

## Security Guarantees

With proper implementation, the binary security format provides:

- **Confidentiality**: Data is completely unreadable without the correct keys
- **Integrity**: Any tampering with the encrypted data is detectable
- **Authentication**: Only authorized users with the correct keys can access the data
- **Forward Secrecy**: Compromise of one file doesn't compromise others

Remember that the security of the system depends on keeping the encryption keys secure. The encrypted data is only as secure as the key management system.
