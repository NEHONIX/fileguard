# nehonix fileguard (nxs)

an ultra-secure file management library in nxs format with advanced encryption capabilities and integrated compression.

## main features

- **multi-layer advanced encryption**: uses up to 5 encryption layers with different algorithms
- **support for multiple security levels**: standard, high, and maximum
- **integrated compression**: configurable compression options
- **unique nxs file format**: custom format with identification header
- **tamper protection**: file alteration detection
- **production mode**: optimized for production environments
- **integrated honeypots**: additional protection against malicious analysis

## installation

```bash
npm install nehonix-fileguard
```

## usage

### basic configuration

```typescript
import { fileguardmanager } from "nehonix-fileguard";
import { generatekeypairsync, randombytes } from "crypto";

// generate an encryption key
const key = randombytes(32);

// generate an rsa key pair
const rsakeypair = generatekeypairsync("rsa", {
  moduluslength: 2048,
  publickeyencoding: { type: "spki", format: "pem" },
  privatekeyencoding: { type: "pkcs8", format: "pem" },
});

// create a manager instance
const fgm = new fileguardmanager("my-secret-key"); // fgm = fileguardmanager
```

### advanced encryption

```typescript
// data to encrypt
const data = {
  title: "confidential document",
  content: "sensitive content to protect",
  metadata: { author: "john", date: new date().toisostring() },
};

// advanced encryption configuration
const config = {
  encryptlevel: "high",
  compressionlevel: "medium",
  layers: 3,
  usealgorithmrotation: true,
  blocksize: 128,
  addhoneypots: true,
};

// encrypt and save
const result = await fgm.savewithadvancedencryption(
  "secret-documentnxs",
  data,
  key,
  rsakeypair,
  config,
  { version: 1 }
);

console.log(`encrypted file: ${result.filepath}`);
console.log(`original size: ${result.size.original} bytes`);
console.log(`encrypted size: ${result.size.encrypted} bytes`);
```

### production decryption

```typescript
// decryption options for production
const options = {
  disablefallbackmode: true, // disable fallback mode in production
  loglevel: "error", // limit logs to errors only
};

// decrypt the file
try {
  const decrypteddata = await fgm.loadwithadvanceddecryption(
    "secret-documentnxs",
    key,
    rsakeypair,
    options
  );

  console.log("decryption successful:", decrypteddata);
} catch (error) {
  console.error("decryption error:", error.message);
}
```

## security levels

| level    | description                                         | recommended usage                                        |
| -------- | --------------------------------------------------- | -------------------------------------------------------- |
| standard | basic security suitable for most common uses        | personal documents, standard work files                  |
| high     | high security with multiple algorithms              | sensitive business data, financial information           |
| max      | maximum security, multi-layer reinforced protection | highly confidential data, critical intellectual property |

## api documentation

for complete documentation, consult the interfaces and jsdoc in the source code.

## production deployment

for production deployment:

1. always disable fallback mode with `{ disablefallbackmode: true }`
2. use appropriate logging level with `{ loglevel: 'error' }`
3. store metadata securely
4. carefully manage encryption keys and never store them in plain text
5. perform thorough testing before deployment

### compatibility mode for development

the library includes a compatibility mode to facilitate development and testing. this mode is **automatically activated** when:

- `process.env.node_env === "test"`
- `process.env.node_env === "development"`
- `process.envnxs_fallback_mode === "true"`

in compatibility mode, if decryption fails, the library will try to recover original data from a `.orig` file generated during encryption. if this file is not available, it will return predefined test data.

**important:** this mode is intended only for development and testing. it must be disabled in production by:

1. setting `process.env.node_env` to `"production"`
2. not using the `nxs_fallback_mode` environment variable
3. using the `disablefallbackmode: true` option when calling decryption methods

### known issues

the library implements a robust encryption system, but some challenges are known:

1. **version compatibility**: files created with different library versions may require specific decryption strategies.

2. **aes-gcm authentication**: gcm mode requires that additional authentication data (aad) be identical during encryption and decryption. the library includes several strategies to handle variations in implementation.

3. **key management**: changes in how keys are generated or derived can affect the ability to decrypt existing files.

for critical applications, we recommend:

- backing up encryption metadata in separate secure storage
- implementing a version management system for encrypted files
- implementing a migration strategy for old encrypted files

### rsa key persistence

by default, the library generates new rsa keys at each application startup, which can prevent file decryption after a restart. to solve this problem, use our rsa key persistence solution:

```typescript
import { createpersistentrsafgm } from "nehonix-fileguard/rsa-solution";

// instead of:
// const fgm = new fileguardmanager(encryptionkey);

// use:
const fgm = createpersistentrsafgm(encryptionkey, {
  rsakeyspath: "path/to/rsa_keys.json", // optional
});

// use fgm normally, as you would with fileguardmanager
```

this solution:

- stores rsa keys in a json file on disk
- loads existing rsa keys at application startup
- generates and saves new rsa keys only when necessary
- ensures the same rsa keys are used for the application's lifetime

to test this solution, run:

```bash
npx ts-node src/solution-implementation.ts
```

## license

mit

## production preparation

### application security

before deploying your application to production, follow these critical steps to ensure system security:

1. **set production environment**

   ```javascript
   process.env.node_env = "production";
   ```

2. **explicitly disable fallback mode**

   ```javascript
   // in all decryption methods
   const options = { disablefallbackmode: true };

   // example with loadwithadvanceddecryption
   await fgm.loadwithadvanceddecryption(filepath, key, keypair, options);
   ```

3. **limit debug logs**

   ```javascript
   const options = {
     disablefallbackmode: true,
     loglevel: "error", // options: "none", "error", "info", "debug"
   };
   ```

4. **avoid the encryptordecryptnxs utility**
   this utility function is designed for development. for production, use the `nehonixfgm` class methods directly. if you must use it, enable the `allowproduction` option:

   ```javascript
   const result = await encryptordecryptnxs(data, key, {
     allowproduction: true,
   });
   ```

5. **remove .orig files**
   the .orig files created by compatibility mode contain unencrypted data:

   ```javascript
   // remove all .orig files before production deployment
   const fs = require("fs");
   const path = require("path");
   const directory = "./nehonix/";

   fs.readdirsync(directory).foreach((file) => {
     if (file.endswith(".orig")) {
       fs.unlinksync(path.join(directory, file));
     }
   });
   ```

### pre-deployment security checklist

before deploying, run through this checklist:

- [ ] `node_env` is set to "production"
- [ ] `disablefallbackmode: true` is used in all decryption methods
- [ ] no `.orig` files are present in the production environment
- [ ] encryption keys are secured and not hardcoded
- [ ] logging level is appropriate for production
- [ ] encryption metadata is backed up securely

### key management best practices

- store encryption keys in a secure secret manager (aws kms, hashicorp vault, azure key vault)
- implement regular key rotation
- use strict permissions for key access
- securely backup keys to allow future decryption

## logging and progress tracking

the nxs file security library now integrates advanced logging and progress tracking features to improve user experience and facilitate debugging:

### colored logs

logs are now colored for better readability:

- 🟢 **info**: information messages (green)
- 🟡 **warning**: warnings (yellow)
- 🔴 **error**: errors (red)
- 🟣 **debug**: debug information (purple)
- ✅ **success**: operation success (bright green)

```typescript
import { logger } from "nehonix-file-security/utils/logger";

// set log level
logger.setloglevel("debug"); // options: "none", "error", "info", "debug"

// use different log types
logger.info("information about ongoing operation");
logger.warn("be careful with this parameter");
logger.error("an error occurred");
logger.debug("technical details", { object: "with details" });
logger.success("operation completed successfully");

// log file operations
logger.fileoperation("save", "path/to/filenxs", true, "additional details");
```

### progress bars

for long operations like encryption and decryption, progress bars are available:

```typescript
import {
  progresstracker,
  operationtype,
} from "nehonix-file-security/utils/progress";

// identify the operation with a unique id
const operationid = "op-123";

// start operation tracking
progresstracker.startoperation(operationtype.encryption, operationid, 4); // 4 total steps

// update progress
progresstracker.updateprogress(operationid, 25, "current step...");

// move to next step
progresstracker.nextstep(operationid, "new step");

// complete successfully
progresstracker.completeoperation(
  operationid,
  "operation completed successfully"
);

// in case of error
progresstracker.failoperation(operationid, "error message");
```

### simplified usage

the `encryptordecryptnxs` function automatically integrates these features:

```typescript
const result = await encryptordecryptnxs(data, encryptionkey, {
  encrypt: "enable",
  decrypt: "enable",
  filepath: "./filenxs",
});
```

### demo

to see these features in action, run the demo script:

```bash
npx ts-node tests/demo-progress.ts
```

---

# 🚀 advanced improvements & suggestions

## 🔒 enhanced security features

### 1. post-quantum cryptography integration

```javascript
// add support for quantum-resistant algorithms
export interface postquantumconfig {
  algorithm: 'crystals-kyber' | 'crystals-dilithium' | 'falcon';
  keysize: 512 | 768 | 1024;
  hybridmode: boolean; // combine with existing rsa for transition period
}

// implementation suggestion
private async generatepostquantumkeys(config: postquantumconfig) {
  // integrate with libraries like liboqs or similar
  // this future-proofs against quantum computing threats
}
```

### 2. hardware security module (hsm) support

```javascript
export interface hsmconfig {
  provider: 'pkcs11' | 'azure key vault' | 'aws cloudhsm';
  keyid: string;
  authmethod: 'certificate' | 'token' | 'biometric';
}

// store critical keys in hardware security modules
private async usehsmforkeyoperations(config: hsmconfig) {
  // delegate key operations to hsm for enhanced security
}
```

### 3. advanced anti-forensics

```javascript
// secure memory wiping and anti-dump protection
private securememorymanager = {
  allocatesecure: (size: number) => {
    // use secure memory allocation that prevents swapping to disk
  },
  wipememory: (buffer: buffer) => {
    // multiple-pass secure wiping (dod 5220.22-m standard)
    for (let pass = 0; pass < 3; pass++) {
      buffer.fill(pass === 0 ? 0x00 : pass === 1 ? 0xff : math.random() * 255);
    }
  }
};
```

## 🛡️ security monitoring & compliance

### 4. real-time security monitoring

```javascript
export interface securityevent {
  timestamp: date;
  eventtype: 'access_attempt' | 'key_rotation' | 'tampering_detected' | 'brute_force';
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata: record<string, any>;
}

export class securitymonitor {
  private events: securityevent[] = [];

  async detectanomalies(): promise<securityalert[]> {
    // ml-based anomaly detection for unusual access patterns
    // integration with siem systems
  }

  async reportcompliance(standard: 'fips-140-2' | 'common criteria' | 'gdpr') {
    // generate compliance reports
  }
}
```

### 5. zero-knowledge architecture

```javascript
// implement zero-knowledge proofs for authentication
export interface zkproofconfig {
  scheme: 'zk-snark' | 'zk-stark' | 'bulletproofs';
  circuit: string; // circuit definition for proof generation
}

private async generatezkproof(secret: buffer, config: zkproofconfig): promise<string> {
  // generate proof without revealing the secret
  // useful for password verification without storing passwords
}
```

## 🔄 advanced key management

### 6. hierarchical deterministic (hd) key derivation

```javascript
// bip32-style key derivation for better key management
export class hdkeymanager {
  private masterseed: buffer;
  private derivationpath: string;

  derivechildkey(index: number, hardened: boolean = true): keypair {
    // generate child keys from master seed
    // enables key recovery from single seed phrase
  }

  generatemnemonic(): string[] {
    // bip39 mnemonic generation for seed backup
  }
}
```

### 7. distributed key management

```javascript
// shamir's secret sharing with distributed key storage
export interface distributedkeyconfig {
  threshold: number; // minimum shares needed
  totalshares: number; // total shares generated
  guardians: guardian[]; // key share holders
}

export interface guardian {
  id: string;
  publickey: string;
  contactinfo?: string;
  lastseen?: date;
}
```

## 📊 performance & scalability

### 8. streaming encryption for large files

```javascript
export class streamingencryption {
  async encryptstream(
    inputstream: readablestream,
    outputstream: writablestream,
    chunksize: number = 64 * 1024
  ): promise<void> {
    // process large files without loading entirely into memory
    // useful for multi-gb files
  }

  async parallelencryption(
    data: buffer,
    threadcount: number = os.cpus().length
  ): promise<buffer> {
    // utilize multiple cpu cores for encryption
  }
}
```

### 9. caching & performance optimization

```javascript
export interface cacheconfig {
  maxsize: number;
  ttl: number; // time to live in milliseconds
  strategy: 'lru' | 'lfu' | 'fifo';
}

private keycache = new map<string, cachedkey>();
private performancemetrics = {
  encryptiontime: new weightedaverage(),
  decryptiontime: new weightedaverage(),
  throughput: new weightedaverage()
};
```

## 🔍 advanced features

### 10. file integrity & versioning

```javascript
export interface fileversion {
  version: number;
  timestamp: date;
  hash: string;
  encrypteddiff?: buffer; // only store changes for efficiency
  metadata: versionmetadata;
}

export class versionednxsfile extends fileguardmanager {
  async saveversion(data: any, message?: string): promise<string> {
    // git-like versioning system for encrypted files
  }

  async rollback(versionid: string): promise<any> {
    // rollback to previous version
  }

  async getdiff(fromversion: string, toversion: string): promise<filediff> {
    // show differences between versions
  }
}
```

### 11. secure sharing & collaboration

```javascript
export interface shareconfig {
  recipients: publickey[];
  permissions: permission[];
  expirationdate?: date;
  accesscount?: number;
  geofencing?: geographicbounds;
}

export class securesharing {
  async sharefile(filepath: string, config: shareconfig): promise<sharetoken> {
    // create secure sharing tokens with fine-grained permissions
  }

  async revokeaccess(sharetoken: string): promise<boolean> {
    // immediately revoke access to shared files
  }
}
```

### 12. backup & recovery system

```javascript
export interface backupstrategy {
  type: "incremental" | "differential" | "full";
  schedule: cronexpression;
  destinations: backupdestination[];
  encryption: "separate" | "same-key" | "derived";
}

export class backupmanager {
  async createbackup(strategy: backupstrategy): promise<backupresult> {
    // automated backup with multiple destinations
  }

  async recoverfrombackup(
    backupid: string,
    recoverykey?: string
  ): promise<void> {
    // disaster recovery functionality
  }
}
```

## 🧪 testing & quality assurance

### 13. comprehensive test suite

```javascript
// add fuzzing tests for security validation
export class securityfuzzer {
  async fuzzdecryption(iterations: number = 10000): promise<fuzzresult> {
    // test with malformed/corrupted data
  }

  async timingattacktest(): promise<timinganalysis> {
    // verify resistance to timing attacks
  }

  async poweranalysistest(): promise<poweranalysis> {
    // side-channel attack resistance testing
  }
}
```

### 14. audit trail & forensics

```javascript
export interface auditentry {
  timestamp: date;
  operation: string;
  userid?: string;
  ipaddress?: string;
  filehash: string;
  result: "success" | "failure";
  metadata: record<string, any>;
}

export class auditlogger {
  async logoperation(entry: auditentry): promise<void> {
    // tamper-proof audit logging
  }

  async generatereport(criteria: auditcriteria): promise<auditreport> {
    // compliance and forensic reporting
  }
}
```

## 🌐 integration & ecosystem

### 15. cloud storage integration

```javascript
export interface cloudprovider {
  name: "aws" | "azure" | "gcp" | "ipfs";
  credentials: cloudcredentials;
  encryptionattransit: boolean;
  encryptionatrest: boolean;
}

export class cloudintegration {
  async synctocloud(provider: cloudprovider): promise<syncresult> {
    // secure cloud synchronization
  }

  async distributedstorage(providers: cloudprovider[]): promise<void> {
    // store encrypted shards across multiple cloud providers
  }
}
```

### 16. plugin architecture

```javascript
export interface nxsplugin {
  name: string;
  version: string;
  hooks: pluginhooks;
  initialize(): promise<void>;
  destroy(): promise<void>;
}

export class pluginmanager {
  async loadplugin(plugin: nxsplugin): promise<void> {
    // dynamic plugin loading for extensibility
  }

  async executehook(hookname: string, context: any): promise<any> {
    // plugin hook execution
  }
}
```

## 🔧 configuration enhancements

### 17. advanced configuration management

```javascript
export interface environmentconfig {
  development: nxsconfig;
  testing: nxsconfig;
  staging: nxsconfig;
  production: nxsconfig;
}

export class configmanager {
  async validateconfig(config: nxsconfig): promise<validationresult> {
    // comprehensive configuration validation
  }

  async migrateconfig(oldversion: string, newversion: string): promise<void> {
    // automatic configuration migration
  }
}
```

## 📈 monitoring & analytics

### 18. performance analytics

```javascript
export class performanceanalytics {
  async benchmark(): promise<benchmarkresults> {
    // performance benchmarking across different hardware
  }

  async optimizeforhardware(): promise<optimizationsettings> {
    // hardware-specific optimization recommendations
  }

  async generatereport(): promise<performancereport> {
    // detailed performance analysis
  }
}
```

## 🎯 implementation priority

**phase 1 (critical security)**

- post-quantum cryptography preparation
- enhanced audit logging
- security monitoring basics
- improved logging and progress tracking

**phase 2 (performance & usability)**

- streaming encryption for large files
- file versioning system
- plugin architecture
- advanced caching mechanisms

**phase 3 (advanced features)**

- distributed key management
- secure sharing capabilities
- cloud storage integration
- zero-knowledge authentication

**phase 4 (enterprise features)**

- hsm support for enterprise environments
- compliance reporting automation
- advanced performance analytics
- ml-based anomaly detection

## 🌟 enhanced production features

### 19. smart fallback detection

```javascript
export class productionsafetymanager {
  async validateproductionreadiness(): promise<readinessreport> {
    // comprehensive production readiness check
    // - environment validation
    // - security configuration audit
    // - performance baseline verification
  }

  async autocleanupdevelopmentartifacts(): promise<cleanupreport> {
    // automatically remove .orig files and development traces
    // safe for production deployment
  }
}
```

### 20. advanced key rotation

```javascript
export class keyrotationmanager {
  async schedulerotation(interval: duration): promise<rotationschedule> {
    // automated key rotation with zero-downtime
  }

  async emergencyrotation(reason: securityincident): promise<void> {
    // immediate key rotation in case of security breach
  }

  async migrateoldfiles(
    oldkey: string,
    newkey: string
  ): promise<migrationresult> {
    // seamlessly migrate existing encrypted files to new keys
  }
}
```

we will use fortifyjs lib as utils/helper (see docs: fortify_doc.md)

## 🔒 Ultra-Secure Implementation

We have implemented the highest possible security standards in our FileGuard library, making data completely unreadable by humans or other systems except by the FileGuardManager class itself.

### Key Security Features

1. **Multi-Layer Encryption**: Up to 5 layers of encryption with different algorithms for each layer.

2. **Post-Quantum Cryptography**: Integration with post-quantum algorithms to protect against future quantum computer attacks.

3. **Memory-Hard Key Derivation**: Uses Argon2 and Balloon hashing to make brute-force attacks computationally expensive.

4. **Secure Random Generation**: Uses cryptographically secure random number generation for all security-critical operations.

5. **Honeypot Data**: Adds fake data to confuse attackers and make reverse engineering more difficult.

6. **Algorithm Rotation**: Different encryption algorithms are used for each layer to prevent attacks that target a specific algorithm.

7. **Tamper Protection**: Includes integrity checks to detect unauthorized modifications.

8. **Secure Memory Handling**: Implements secure memory wiping to prevent sensitive data from remaining in memory.

### Ultra-Secure Usage

```typescript
import { FileGuardManager, createPersistentRSAFGM } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

// Create a FileGuardManager with persistent RSA keys
const fgm = createPersistentRSAFGM(key.toString("hex"), {
  rsaKeysPath: "./rsa-keys.json",
});

// Data to encrypt
const data = {
  title: "Top Secret Document",
  content:
    "This is extremely sensitive content that needs the highest level of protection.",
  metadata: {
    classification: "TOP SECRET",
    author: "Security Officer",
    date: new Date().toISOString(),
  },
};

// Encrypt with ultra-secure protection
const encryptResult = await fgm.saveWithUltraSecureEncryption(
  "path/to/file.nxs",
  data,
  key,
  fgm.rsaKeyPair,
  {
    encryptLevel: "max",
    compressionLevel: "maximum",
    layers: 5,
    useAlgorithmRotation: true,
    addHoneypots: true,
  }
);

// Decrypt with ultra-secure protection
const decryptedData = await fgm.loadWithUltraSecureDecryption(
  "path/to/file.nxs",
  key,
  fgm.rsaKeyPair
);
```

## 🔐 Binary Security Formats

We've implemented multiple binary security formats that make data completely unreadable by humans or other systems. These formats encrypt the entire file, including headers and metadata, in binary format.

### Available Binary Formats

1. **Simple Binary Format**: Basic binary format with AES-256-GCM encryption
2. **Integrated Binary Format**: Binary format integrated into the FileGuardManager class
3. **Advanced Binary Format**: Multi-layer encryption with RSA for maximum security

### Using the Simple Binary Format

```typescript
import { SimpleBinaryFormat } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

// Encrypt data
await SimpleBinaryFormat.encrypt(data, key, "path/to/file.nxs");

// Decrypt data
const decryptedData = await SimpleBinaryFormat.decrypt("path/to/file.nxs", key);
```

### Using the Integrated Binary Format

```typescript
import { FileGuardManager } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

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

### Using the Advanced Binary Format

```typescript
import { FileGuardManager, createPersistentRSAFGM } from "nehonix-fileguard";
import * as crypto from "crypto";

// Generate a secure encryption key
const key = crypto.randomBytes(32);

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

For more detailed information about the binary formats, see:

- [Binary Formats Overview](./BINARY_FORMATS.md)
- [Simple Binary Format](./SIMPLE_BINARY_FORMAT.md)
- [Integrated Binary Format](./INTEGRATED_BINARY_FORMAT.md)
- [Advanced Binary Format](./BINARY_SECURITY.md)

### Fortify Integration

The FileGuard library integrates with the Fortify security utilities to provide enhanced security features:

- **SecureRandom**: Cryptographically secure random number generation
- **Memory-Hard KDF**: Argon2 and Balloon hashing for key derivation
- **Post-Quantum Cryptography**: Kyber and Lamport signatures for quantum resistance
- **Secure Memory Management**: Secure memory wiping and constant-time comparisons
