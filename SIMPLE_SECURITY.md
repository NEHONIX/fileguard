# NEHONIX FileGuard - Simple Security Guide

This document provides a quick guide to using the NEHONIX FileGuard library for secure file encryption, making data completely unreadable by humans or other systems except by the FileGuardManager class itself.

## Key Security Features

NEHONIX FileGuard implements high security standards:

1. **Strong Encryption**: Uses AES-256-GCM (Authenticated Encryption with Associated Data)
2. **Secure Key Management**: RSA key pairs for additional protection
3. **Data Compression**: Reduces file size and adds another layer of obfuscation
4. **Integrity Verification**: Ensures data hasn't been tampered with
5. **Secure Random Generation**: All cryptographic operations use secure random number generation

## Running the Simple Security Demo

To see these security features in action, run:

```bash
npm run demo:simple
```

The demo will:

1. Generate a cryptographically secure encryption key
2. Create a FileGuardManager with persistent RSA keys
3. Encrypt sample confidential data
4. Show the encrypted data (which is unreadable)
5. Decrypt the data and verify it matches the original

## Implementation in Your Code

To implement secure encryption in your application:

```typescript
import { createPersistentRSAFGM } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

// Create a FileGuardManager with persistent RSA keys
const fgm = createPersistentRSAFGM(key.toString("hex"), {
  rsaKeysPath: "./secure-keys.json",
});

// Data to encrypt
const sensitiveData = {
  title: "Confidential Document",
  content: "This is sensitive content that requires strong protection.",
  metadata: {
    author: "Security Team",
    classification: "CONFIDENTIAL",
    created: new Date().toISOString(),
  },
};

// Encrypt the data
const result = await fgm.saveWithAdvancedEncryption(
  "path/to/secure-file.nxs",
  sensitiveData,
  key,
  fgm.rsaKeyPair,
  {
    securityLevel: "high",
    compressionLevel: "high",
    layers: 1,
    useAlgorithmRotation: false,
    addHoneypots: false,
  }
);

// Later, decrypt the data
const decryptedData = await fgm.loadWithAdvancedDecryption(
  "path/to/secure-file.nxs",
  key,
  fgm.rsaKeyPair
);
```

## Security Best Practices

For maximum security:

1. **Key Management**: Store encryption keys securely, never in plain text
2. **Use High Security Level**: Always use 'high' or 'max' security level for sensitive data
3. **Secure Memory**: Clear sensitive data from memory after use
4. **Regular Key Rotation**: Change encryption keys periodically
5. **Physical Security**: Protect the devices where encrypted files are stored
6. **Access Control**: Limit who can access the encryption keys

## Technical Details

The simple security implementation uses:

- **Encryption**: AES-256-GCM (Galois/Counter Mode)
- **Authentication**: GCM authentication tags
- **Compression**: DEFLATE algorithm with high compression
- **Key Storage**: RSA key pairs for secure key management

## Security Guarantees

With proper implementation, NEHONIX FileGuard provides:

- **Confidentiality**: Data is unreadable without the correct keys
- **Integrity**: Any tampering with the encrypted data is detectable
- **Authentication**: Only authorized users with the correct keys can access the data

Remember that the security of the system depends on keeping the encryption keys secure. The encrypted data is only as secure as the key management system.
