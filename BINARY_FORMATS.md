# NEHONIX FileGuard - Binary Formats Guide

This document provides an overview of the binary formats available in the NEHONIX FileGuard library, which make data completely unreadable by humans or other systems.

## Available Binary Formats

NEHONIX FileGuard offers three binary format options with different security levels:

1. **Simple Binary Format**: Basic binary format with AES-256-GCM encryption
2. **Integrated Binary Format**: Binary format integrated into the FileGuardManager class
3. **Advanced Binary Format**: Multi-layer encryption with RSA for maximum security

## Choosing the Right Binary Format

| Feature        | Simple Binary Format | Integrated Binary Format | Advanced Binary Format |
| -------------- | -------------------- | ------------------------ | ---------------------- |
| Encryption     | AES-256-GCM          | AES-256-GCM              | Multiple layers + RSA  |
| Key Management | Manual               | Via FileGuardManager     | Via FileGuardManager   |
| Complexity     | Low                  | Medium                   | High                   |
| Security Level | High                 | High                     | Maximum                |
| Performance    | Fast                 | Fast                     | Slower                 |
| File Size      | Small                | Small                    | Larger                 |

## Simple Binary Format

The Simple Binary Format is a standalone implementation that provides strong security with minimal complexity:

```typescript
import { SimpleBinaryFormat } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

// Encrypt data
await SimpleBinaryFormat.encrypt(data, key, "path/to/file.nxs");

// Decrypt data
const decryptedData = await SimpleBinaryFormat.decrypt("path/to/file.nxs", key);
```

[Learn more about Simple Binary Format](./SIMPLE_BINARY_FORMAT.md)

## Integrated Binary Format

The Integrated Binary Format is built into the FileGuardManager class, making it easy to use with the rest of the library:

```typescript
import { FileGuardManager } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

// Create a FileGuardManager
const fgm = new FileGuardManager(key.toString("hex"));

// Encrypt data
await fgm.saveWithSimpleBinaryFormat("path/to/file.nxs", data, key);

// Decrypt data
const decryptedData = await fgm.loadWithSimpleBinaryFormat(
  "path/to/file.nxs",
  key
);
```

[Learn more about Integrated Binary Format](./INTEGRATED_BINARY_FORMAT.md)

## Advanced Binary Format

The Advanced Binary Format provides the highest level of security with multiple encryption layers and RSA asymmetric encryption:

```typescript
import { FileGuardManager, createPersistentRSAFGM } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = Random.getRandomBytes(32);

// Create a FileGuardManager with RSA keys
const fgm = createPersistentRSAFGM(key.toString("hex"), {
  rsaKeysPath: "./secure-keys.json",
});

// Encrypt data
await fgm.saveWithBinarySecureFormat(
  "path/to/file.nxs",
  data,
  key,
  fgm.rsaKeyPair,
  {
    layers: 5,
    addRandomPadding: true,
  }
);

// Decrypt data
const decryptedData = await fgm.loadWithBinarySecureFormat(
  "path/to/file.nxs",
  key,
  fgm.rsaKeyPair
);
```

[Learn more about Advanced Binary Format](./BINARY_SECURITY.md)

## Binary Format Structure

All binary formats use a similar structure:

```
[Magic Bytes (6)] [IV (16)] [Salt (16)] [Encrypted Size (4)] [Encrypted Content]
```

The magic bytes "NXSBIN" identify the file as a NEHONIX binary format file, but are stored in binary form to prevent easy identification.

## Security Best Practices

For maximum security with any binary format:

1. **Key Management**: Store encryption keys securely, never in plain text
2. **Secure Memory**: Clear sensitive data from memory after use
3. **Regular Key Rotation**: Change encryption keys periodically
4. **Physical Security**: Protect the devices where encrypted files are stored
5. **Access Control**: Limit who can access the encryption keys

## Running the Demos

To see the binary formats in action, run:

```bash
# Simple Binary Format
npm run demo:simple-binary

# Integrated Binary Format
npm run demo:integrated-binary

# Advanced Binary Format
npm run demo:binary-format
```

## Technical Comparison

| Feature               | Simple Binary Format       | Integrated Binary Format   | Advanced Binary Format         |
| --------------------- | -------------------------- | -------------------------- | ------------------------------ |
| Encryption Algorithm  | AES-256-GCM                | AES-256-GCM                | Multiple (AES, Camellia, etc.) |
| Key Derivation        | PBKDF2 (10,000 iterations) | PBKDF2 (10,000 iterations) | PBKDF2 (100,000 iterations)    |
| Asymmetric Encryption | No                         | No                         | Yes (RSA)                      |
| Encryption Layers     | 1                          | 1                          | 3-7                            |
| Authentication        | GCM Auth Tag               | GCM Auth Tag               | Multiple Auth Tags + HMAC      |
| Anti-Tampering        | Basic                      | Basic                      | Advanced                       |
| Random Padding        | No                         | No                         | Optional                       |
| Compression           | No                         | No                         | Yes                            |

## Conclusion

NEHONIX FileGuard's binary formats provide a range of security options to meet different needs. Choose the format that best balances security, performance, and complexity for your application.
