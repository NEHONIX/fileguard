/**
 * Binary Secure Format for NEHONIX FileGuard
 *
 * Implements a fully binary encryption format that makes data
 * completely unreadable by humans or other systems except by the
 * FileGuardManager class itself.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as zlib from "zlib";
import { promisify } from "util";
import { logger } from "../utils/logger";
import { secureWipe } from "../utils/secureMemory";
import { ProgressTracker, OperationType } from "../utils/progress";

// Enhanced magic bytes with version info
const MAGIC_BYTES = Buffer.from([
  0x4e, 0x58, 0x53, 0x42, 0x49, 0x4e, 0x02, 0x01,
]); // "NXSBIN" + version 2.1
const INTEGRITY_MARKER = Buffer.from([0xde, 0xad, 0xbe, 0xef]);

// Promisify zlib functions
const deflatePromise = promisify(zlib.deflate);
const inflatePromise = promisify(zlib.inflate);

interface SecureParams {
  key: Buffer;
  iv: Buffer;
  salt: Buffer;
  aad: Buffer;
  masterSalt: Buffer;
  integrityKey: Buffer;
}

interface EncryptionOptions {
  layers?: number;
  addRandomPadding?: boolean;
  compressionLevel?: number;
  integrityChecks?: boolean;
  antiTampering?: boolean;
  keyDerivationRounds?: number;
}

interface FileHeader {
  timestamp: number;
  dataType: string;
  version: number;
  layers: number;
  compressionLevel: number;
  flags: number;
  checksum: string;
  keyDerivationRounds: number;
}

/**
 * Binary Secure Format implementation
 */
export class BinarySecureFormat {
  private static readonly MIN_KEY_SIZE = 32;
  private static readonly MAX_LAYERS = 7;
  private static readonly DEFAULT_KDF_ROUNDS = 100000;

  // Enhanced encryption algorithms with better security
  private static readonly ENCRYPTION_ALGORITHMS = [
    "aes-256-gcm",
    "chacha20-poly1305", // If available
    "aes-256-ocb", // If available
    "aes-256-ccm",
    "aria-256-gcm",
    "camellia-256-gcm",
    "aes-256-ctr",
  ];

  /**
   * Enhanced encrypt method with improved security
   */
  static async encrypt(
    data: any,
    key: Buffer,
    rsaKeyPair: { publicKey: string; privateKey: string },
    outputPath: string,
    options: EncryptionOptions = {}
  ): Promise<{
    success: boolean;
    filepath: string;
    size: number;
    integrity: string;
  }> {
    // Validate inputs
    this.validateInputs(data, key, rsaKeyPair, options);

    const operationId = crypto.randomBytes(16).toString("hex");
    const layers = Math.min(options.layers || 5, this.MAX_LAYERS);
    const kdfRounds = options.keyDerivationRounds || this.DEFAULT_KDF_ROUNDS;

    ProgressTracker.startOperation(
      OperationType.Encryption,
      operationId,
      layers + 3
    );

    try {
      // Convert and validate data
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      if (dataString.length === 0) {
        throw new Error("Cannot encrypt empty data");
      }

      // Generate enhanced secure parameters
      const secureParams = this.generateSecureParams(key, kdfRounds);

      // Create enhanced header with integrity information
      const dataChecksum = crypto
        .createHash("sha3-256")
        .update(dataString)
        .digest("hex");
      const header: FileHeader = {
        timestamp: Date.now(),
        dataType: typeof data,
        version: 2,
        layers,
        compressionLevel: options.compressionLevel || 9,
        flags: this.generateFlags(options),
        checksum: dataChecksum,
        keyDerivationRounds: kdfRounds,
      };

      ProgressTracker.updateProgress(operationId, 10, "Preparing data...");

      // Step 1: Compress with integrity check
      const compressedData = await this.compressDataWithIntegrity(
        dataString,
        options.compressionLevel || 9
      );

      // Step 2: Create file content with header
      const headerBuffer = Buffer.from(JSON.stringify(header));
      const headerLength = Buffer.alloc(4);
      headerLength.writeUInt32BE(headerBuffer.length, 0);

      const fileContent = Buffer.concat([
        headerLength,
        headerBuffer,
        compressedData,
      ]);

      // Step 3: Multi-layer encryption with enhanced security
      ProgressTracker.updateProgress(
        operationId,
        30,
        "Encrypting with multiple layers..."
      );
      const encryptedContent = await this.encryptContentEnhanced(
        fileContent,
        secureParams,
        layers,
        operationId
      );

      // Step 4: Add RSA hybrid encryption
      ProgressTracker.updateProgress(
        operationId,
        70,
        "Applying RSA hybrid encryption..."
      );
      const rsaEncrypted = await this.addEnhancedRSAEncryption(
        encryptedContent,
        rsaKeyPair.publicKey
      );

      // Step 5: Add anti-tampering measures
      let finalContent = rsaEncrypted;
      if (options.antiTampering !== false) {
        finalContent = await this.addAntiTamperingLayer(
          rsaEncrypted,
          secureParams
        );
      }

      // Step 6: Add random padding with pattern obfuscation
      if (options.addRandomPadding !== false) {
        finalContent = this.addObfuscatedPadding(finalContent);
      }

      // Step 7: Create final file structure with integrity verification
      ProgressTracker.updateProgress(
        operationId,
        85,
        "Creating secure file structure..."
      );
      const fileBuffer = this.createSecureFileStructure(
        finalContent,
        secureParams
      );

      // Step 8: Write with atomic operation
      ProgressTracker.updateProgress(
        operationId,
        95,
        "Writing encrypted file..."
      );
      await this.atomicFileWrite(outputPath, fileBuffer);

      // Generate integrity hash for verification
      const integrityHash = crypto
        .createHash("sha3-512")
        .update(fileBuffer)
        .digest("hex");

      // Secure cleanup
      this.secureCleanup([fileContent, encryptedContent, rsaEncrypted]);

      ProgressTracker.completeOperation(
        operationId,
        `File encrypted with ${layers} layers: ${outputPath}`
      );

      return {
        success: true,
        filepath: outputPath,
        size: fileBuffer.length,
        integrity: integrityHash,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      ProgressTracker.failOperation(
        operationId,
        `Encryption failed: ${errorMessage}`
      );
      logger.error("Binary secure format encryption failed", error);
      throw error;
    }
  }

  /**
   * Enhanced decrypt method with integrity verification
   */
  static async decrypt(
    filePath: string,
    key: Buffer,
    rsaKeyPair: { publicKey: string; privateKey: string },
    expectedIntegrity?: string
  ): Promise<any> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const operationId = crypto.randomBytes(16).toString("hex");
    ProgressTracker.startOperation(OperationType.Decryption, operationId, 8);

    try {
      // Step 1: Read and verify file integrity
      ProgressTracker.updateProgress(
        operationId,
        10,
        "Reading and verifying file..."
      );
      const fileBuffer = fs.readFileSync(filePath);

      if (expectedIntegrity) {
        const currentIntegrity = crypto
          .createHash("sha3-512")
          .update(fileBuffer)
          .digest("hex");

        if (currentIntegrity !== expectedIntegrity) {
          throw new Error(
            "File integrity verification failed - file may be corrupted or tampered"
          );
        }
      }

      // Step 2: Parse secure file structure
      ProgressTracker.updateProgress(
        operationId,
        20,
        "Parsing file structure..."
      );
      const { content, secureParams } =
        this.parseSecureFileStructure(fileBuffer);

      // Step 3: Remove anti-tampering layer
      ProgressTracker.updateProgress(
        operationId,
        30,
        "Removing security layers..."
      );

      // Ensure secureParams has all required properties and create them if missing
      secureParams.key = key;

      // Create a default masterSalt if not available
      if (!secureParams.masterSalt) {
        secureParams.masterSalt = crypto.randomBytes(16);
      }

      // Create integrity key
      secureParams.integrityKey = crypto.pbkdf2Sync(
        key,
        Buffer.concat([secureParams.masterSalt, Buffer.from("integrity")]),
        this.DEFAULT_KDF_ROUNDS,
        32,
        "sha512"
      );

      const withoutTampering = await this.removeAntiTamperingLayer(
        content,
        secureParams as Partial<SecureParams> & { integrityKey: Buffer }
      );

      // Step 4: Remove RSA encryption
      ProgressTracker.updateProgress(
        operationId,
        40,
        "Decrypting RSA layer..."
      );
      const rsaDecrypted = await this.removeEnhancedRSAEncryption(
        withoutTampering,
        rsaKeyPair.privateKey
      );

      // Step 5: Multi-layer decryption
      ProgressTracker.updateProgress(
        operationId,
        50,
        "Decrypting multiple layers..."
      );

      // Ensure secureParams has all required properties
      if (!secureParams.key || !secureParams.masterSalt) {
        throw new Error("Missing required secure parameters for decryption");
      }

      const decryptedContent = await this.decryptContentEnhanced(
        rsaDecrypted,
        key,
        secureParams as Partial<SecureParams> & {
          key: Buffer;
          masterSalt: Buffer;
        },
        operationId
      );

      // Step 6: Parse header and extract data
      ProgressTracker.updateProgress(
        operationId,
        70,
        "Parsing decrypted content..."
      );
      const headerLength = decryptedContent.readUInt32BE(0);
      const headerBuffer = decryptedContent.subarray(4, 4 + headerLength);
      const header: FileHeader = JSON.parse(headerBuffer.toString("utf8"));

      // Step 7: Extract and decompress data
      ProgressTracker.updateProgress(operationId, 80, "Decompressing data...");
      const compressedData = decryptedContent.subarray(4 + headerLength);
      const decompressedData = await this.decompressDataWithIntegrity(
        compressedData
      );

      // Step 8: Verify data integrity
      ProgressTracker.updateProgress(
        operationId,
        90,
        "Verifying data integrity..."
      );
      const dataString = decompressedData.toString("utf8");
      const dataChecksum = crypto
        .createHash("sha3-256")
        .update(dataString)
        .digest("hex");

      if (dataChecksum !== header.checksum) {
        throw new Error(
          "Data integrity verification failed - decrypted data is corrupted"
        );
      }

      // Parse final result
      let result;
      if (header.dataType === "object") {
        result = JSON.parse(dataString);
      } else {
        result = dataString;
      }

      ProgressTracker.completeOperation(
        operationId,
        "File decrypted and verified successfully"
      );
      return result;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      ProgressTracker.failOperation(
        operationId,
        `Decryption failed: ${errorMessage}`
      );
      logger.error("Binary secure format decryption failed", error);
      throw error;
    }
  }

  /**
   * Validate inputs for security
   */
  private static validateInputs(
    data: any,
    key: Buffer,
    rsaKeyPair: any,
    options: EncryptionOptions
  ): void {
    if (!data) throw new Error("Data cannot be null or undefined");
    if (!key || key.length < this.MIN_KEY_SIZE) {
      throw new Error(`Key must be at least ${this.MIN_KEY_SIZE} bytes`);
    }
    if (!rsaKeyPair?.publicKey || !rsaKeyPair?.privateKey) {
      throw new Error("Valid RSA key pair required");
    }
    if (options.layers && options.layers > this.MAX_LAYERS) {
      throw new Error(`Maximum ${this.MAX_LAYERS} encryption layers allowed`);
    }
  }

  /**
   * Generate enhanced secure parameters
   */
  private static generateSecureParams(
    key: Buffer,
    kdfRounds: number
  ): SecureParams {
    const masterSalt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(32);
    const aad = crypto.randomBytes(64);

    // Derive integrity key separately
    const integrityKey = crypto.pbkdf2Sync(
      key,
      Buffer.concat([masterSalt, Buffer.from("integrity")]),
      kdfRounds,
      32,
      "sha512"
    );

    return { key, iv, salt, aad, masterSalt, integrityKey };
  }

  /**
   * Generate option flags
   */
  private static generateFlags(options: EncryptionOptions): number {
    let flags = 0;
    if (options.addRandomPadding !== false) flags |= 0x01;
    if (options.integrityChecks !== false) flags |= 0x02;
    if (options.antiTampering !== false) flags |= 0x04;
    return flags;
  }

  /**
   * Compress data with integrity verification
   */
  private static async compressDataWithIntegrity(
    data: string,
    level: number
  ): Promise<Buffer> {
    const input = Buffer.from(data, "utf8");
    const compressed = await deflatePromise(input, {
      level,
      strategy: zlib.constants.Z_DEFAULT_STRATEGY,
    });

    // Add compression integrity check
    const checksum = crypto.createHash("sha256").update(compressed).digest();
    return Buffer.concat([checksum, compressed]);
  }

  /**
   * Decompress data with integrity verification
   */
  private static async decompressDataWithIntegrity(
    data: Buffer
  ): Promise<Buffer> {
    const checksum = data.subarray(0, 32);
    const compressed = data.subarray(32);

    // Verify compression integrity
    const expectedChecksum = crypto
      .createHash("sha256")
      .update(compressed)
      .digest();
    if (!checksum.equals(expectedChecksum)) {
      throw new Error("Compressed data integrity check failed");
    }

    return await inflatePromise(compressed);
  }

  /**
   * Enhanced multi-layer encryption
   */
  private static async encryptContentEnhanced(
    content: Buffer,
    params: SecureParams,
    layers: number,
    operationId: string
  ): Promise<Buffer> {
    let currentData = content;

    for (let i = 0; i < layers; i++) {
      ProgressTracker.updateProgress(
        operationId,
        30 + (i * 40) / layers,
        `Applying encryption layer ${i + 1}/${layers}...`
      );

      const algorithm = this.getAlgorithmForLayer(i);
      const layerKey = this.deriveLayerKey(params.key, params.masterSalt, i);
      const layerIV = crypto.randomBytes(this.getIVLength(algorithm));

      const cipher = crypto.createCipheriv(algorithm, layerKey, layerIV);

      // Set AAD for authenticated encryption
      const aadData = Buffer.concat([
        params.aad,
        Buffer.from(`layer-${i}-enhanced`),
      ]);

      if (this.isAuthenticatedAlgorithm(algorithm)) {
        (cipher as any).setAAD(aadData);
      }

      const encrypted = Buffer.concat([
        cipher.update(currentData),
        cipher.final(),
      ]);

      // Get auth tag for authenticated algorithms
      let authTag = Buffer.alloc(0);
      if (this.isAuthenticatedAlgorithm(algorithm)) {
        authTag = (cipher as any).getAuthTag();
      }

      // Create layer metadata with enhanced security info
      const layerMetadata = {
        algorithm,
        iv: layerIV.toString("base64"),
        authTag: authTag.toString("base64"),
        layer: i,
        keyDerivationInfo: crypto
          .createHash("sha256")
          .update(layerKey)
          .digest("hex")
          .substring(0, 16),
      };

      const metadataBuffer = Buffer.from(JSON.stringify(layerMetadata));
      const metadataLength = Buffer.alloc(4);
      metadataLength.writeUInt32BE(metadataBuffer.length, 0);

      currentData = Buffer.concat([metadataLength, metadataBuffer, encrypted]);
    }

    return currentData;
  }

  /**
   * Enhanced multi-layer decryption
   */
  private static async decryptContentEnhanced(
    content: Buffer,
    key: Buffer,
    params: Partial<SecureParams> & { key: Buffer; masterSalt: Buffer },
    operationId: string
  ): Promise<Buffer> {
    let currentData = content;
    const layers = this.countEncryptionLayers(currentData);

    for (let i = layers - 1; i >= 0; i--) {
      ProgressTracker.updateProgress(
        operationId,
        50 + ((layers - 1 - i) * 20) / layers,
        `Decrypting layer ${layers - i}/${layers}...`
      );

      // Parse layer metadata
      const metadataLength = currentData.readUInt32BE(0);
      const metadataBuffer = currentData.subarray(4, 4 + metadataLength);
      const metadata = JSON.parse(metadataBuffer.toString("utf8"));

      // Extract encrypted data
      const encryptedData = currentData.subarray(4 + metadataLength);

      // Derive layer key and verify
      const layerKey = this.deriveLayerKey(
        key,
        params.masterSalt,
        metadata.layer
      );
      const expectedKeyHash = crypto
        .createHash("sha256")
        .update(layerKey)
        .digest("hex")
        .substring(0, 16);

      if (expectedKeyHash !== metadata.keyDerivationInfo) {
        throw new Error(
          `Layer ${metadata.layer} key derivation verification failed`
        );
      }

      // Decrypt layer
      const iv = Buffer.from(metadata.iv, "base64");
      const decipher = crypto.createDecipheriv(
        metadata.algorithm,
        layerKey,
        iv
      );

      // Set auth tag and AAD for authenticated algorithms
      if (this.isAuthenticatedAlgorithm(metadata.algorithm)) {
        const authTag = Buffer.from(metadata.authTag, "base64");
        const aadData = Buffer.concat([
          params.aad || Buffer.from("default-aad"),
          Buffer.from(`layer-${metadata.layer}-enhanced`),
        ]);

        (decipher as any).setAuthTag(authTag);
        (decipher as any).setAAD(aadData);
      }

      currentData = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final(),
      ]);
    }

    return currentData;
  }

  /**
   * Enhanced RSA hybrid encryption
   */
  private static async addEnhancedRSAEncryption(
    data: Buffer,
    publicKey: string
  ): Promise<Buffer> {
    // Generate strong AES key
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // Use AES-256-GCM for hybrid encryption
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    const aadString = "enhanced-rsa-hybrid-layer";
    (cipher as any).setAAD(Buffer.from(aadString));

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = (cipher as any).getAuthTag();

    // Encrypt AES key with RSA-OAEP
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha512",
      },
      aesKey
    );

    const metadata = {
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedKey: encryptedKey.toString("base64"),
      algorithm: "aes-256-gcm",
      oaepHash: "sha512",
    };

    const metadataBuffer = Buffer.from(JSON.stringify(metadata));
    const metadataLength = Buffer.alloc(4);
    metadataLength.writeUInt32BE(metadataBuffer.length, 0);

    return Buffer.concat([metadataLength, metadataBuffer, encrypted]);
  }

  /**
   * Remove enhanced RSA encryption
   */
  private static async removeEnhancedRSAEncryption(
    data: Buffer,
    privateKey: string
  ): Promise<Buffer> {
    const metadataLength = data.readUInt32BE(0);
    const metadataBuffer = data.subarray(4, 4 + metadataLength);
    const metadata = JSON.parse(metadataBuffer.toString("utf8"));

    const encryptedData = data.subarray(4 + metadataLength);

    // Decrypt AES key
    const encryptedKey = Buffer.from(metadata.encryptedKey, "base64");
    const paddingOptions = {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: metadata.oaepHash || "sha256",
    };

    const aesKey = crypto.privateDecrypt(paddingOptions, encryptedKey);

    // Decrypt data
    const iv = Buffer.from(metadata.iv, "base64");
    const authTag = Buffer.from(metadata.authTag, "base64");
    const decipher = crypto.createDecipheriv(metadata.algorithm, aesKey, iv);

    (decipher as any).setAuthTag(authTag);
    (decipher as any).setAAD(Buffer.from("enhanced-rsa-hybrid-layer"));

    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }

  /**
   * Add anti-tampering layer
   */
  private static async addAntiTamperingLayer(
    data: Buffer,
    params: SecureParams
  ): Promise<Buffer> {
    // Create HMAC for integrity
    const hmac = crypto.createHmac("sha3-512", params.integrityKey);
    hmac.update(data);
    const integrityHash = hmac.digest();

    // Add integrity marker and hash
    return Buffer.concat([INTEGRITY_MARKER, integrityHash, data]);
  }

  /**
   * Remove anti-tampering layer
   */
  private static async removeAntiTamperingLayer(
    data: Buffer,
    params: Partial<SecureParams> & { integrityKey: Buffer }
  ): Promise<Buffer> {
    // Check for integrity marker
    const marker = data.subarray(0, 4);
    if (!marker.equals(INTEGRITY_MARKER)) {
      throw new Error(
        "Anti-tampering verification failed - integrity marker not found"
      );
    }

    // Extract and verify HMAC
    const storedHash = data.subarray(4, 68); // SHA3-512 = 64 bytes
    const actualData = data.subarray(68);

    const hmac = crypto.createHmac("sha3-512", params.integrityKey);
    hmac.update(actualData);
    const expectedHash = hmac.digest();

    if (!storedHash.equals(expectedHash)) {
      throw new Error(
        "Anti-tampering verification failed - data has been modified"
      );
    }

    return actualData;
  }

  /**
   * Add obfuscated padding
   */
  private static addObfuscatedPadding(data: Buffer): Buffer {
    const paddingSize = Math.floor(Math.random() * 512) + 64; // 64-576 bytes
    const pattern = crypto.randomBytes(16);

    // Create patterned padding to obfuscate file size analysis
    const padding = Buffer.alloc(paddingSize);
    for (let i = 0; i < paddingSize; i++) {
      padding[i] = pattern[i % pattern.length] ^ (i & 0xff);
    }

    const paddingSizeBuffer = Buffer.alloc(4);
    paddingSizeBuffer.writeUInt32BE(paddingSize, 0);

    return Buffer.concat([data, paddingSizeBuffer, padding]);
  }

  /**
   * Create secure file structure
   */
  private static createSecureFileStructure(
    content: Buffer,
    params: SecureParams
  ): Buffer {
    // Calculate total file size
    const totalSize = MAGIC_BYTES.length + 16 + 32 + 32 + 4 + content.length;
    const fileBuffer = Buffer.alloc(totalSize);

    let offset = 0;

    // Magic bytes
    MAGIC_BYTES.copy(fileBuffer, offset);
    offset += MAGIC_BYTES.length;

    // IV
    params.iv.copy(fileBuffer, offset);
    offset += 16;

    // Master salt
    params.masterSalt.copy(fileBuffer, offset);
    offset += 32;

    // Salt
    params.salt.copy(fileBuffer, offset);
    offset += 32;

    // Content size
    fileBuffer.writeUInt32BE(content.length, offset);
    offset += 4;

    // Encrypted content
    content.copy(fileBuffer, offset);

    return fileBuffer;
  }

  /**
   * Parse secure file structure
   */
  private static parseSecureFileStructure(fileBuffer: Buffer): {
    content: Buffer;
    secureParams: Partial<SecureParams>;
  } {
    // Verify magic bytes
    const magicBytes = fileBuffer.subarray(0, MAGIC_BYTES.length);
    if (!magicBytes.equals(MAGIC_BYTES)) {
      throw new Error("Invalid file format or corrupted file");
    }

    let offset = MAGIC_BYTES.length;

    // Extract parameters
    const iv = fileBuffer.subarray(offset, offset + 16);
    offset += 16;

    const masterSalt = fileBuffer.subarray(offset, offset + 32);
    offset += 32;

    const salt = fileBuffer.subarray(offset, offset + 32);
    offset += 32;

    const contentSize = fileBuffer.readUInt32BE(offset);
    offset += 4;

    const content = fileBuffer.subarray(offset, offset + contentSize);

    return {
      content,
      secureParams: { iv, masterSalt, salt },
    };
  }

  /**
   * Atomic file write
   */
  private static async atomicFileWrite(
    outputPath: string,
    data: Buffer
  ): Promise<void> {
    const tempPath = `${outputPath}.tmp.${crypto
      .randomBytes(8)
      .toString("hex")}`;
    const dir = path.dirname(outputPath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    try {
      fs.writeFileSync(tempPath, data);
      fs.renameSync(tempPath, outputPath);
    } catch (error) {
      // Cleanup temp file if it exists
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      throw error;
    }
  }

  /**
   * Helper methods
   */
  private static getAlgorithmForLayer(layer: number): string {
    // Check algorithm availability and fallback gracefully
    const preferredAlgorithm =
      this.ENCRYPTION_ALGORITHMS[layer % this.ENCRYPTION_ALGORITHMS.length];

    try {
      // Test if algorithm is available
      const testCipher = crypto.createCipheriv(
        preferredAlgorithm,
        crypto.randomBytes(32),
        crypto.randomBytes(this.getIVLength(preferredAlgorithm))
      );
      testCipher.destroy();
      return preferredAlgorithm;
    } catch (error) {
      // Fallback to AES-256-GCM if preferred algorithm is not available
      logger.warn(
        `Algorithm ${preferredAlgorithm} not available, falling back to AES-256-GCM`
      );
      return "aes-256-gcm";
    }
  }

  private static isAuthenticatedAlgorithm(algorithm: string): boolean {
    return (
      algorithm.includes("gcm") ||
      algorithm.includes("ccm") ||
      algorithm.includes("poly1305")
    );
  }

  private static getIVLength(algorithm: string): number {
    if (algorithm.includes("chacha20")) return 12;
    if (algorithm.includes("ccm")) return 12;
    return 16;
  }

  private static deriveLayerKey(
    masterKey: Buffer,
    salt: Buffer,
    layer: number
  ): Buffer {
    return crypto.pbkdf2Sync(
      masterKey,
      Buffer.concat([salt, Buffer.from(`enhanced-layer-${layer}`)]),
      50000 + layer * 10000, // Increasing rounds per layer
      32,
      "sha512"
    );
  }

  private static countEncryptionLayers(data: Buffer): number {
    let layers = 0;
    let tempData = data;

    while (tempData.length > 4) {
      try {
        const metadataLength = tempData.readUInt32BE(0);
        if (metadataLength > tempData.length - 4 || metadataLength > 4096)
          break;

        const metadataBuffer = tempData.subarray(4, 4 + metadataLength);
        const metadata = JSON.parse(metadataBuffer.toString("utf8"));

        if (metadata.layer !== undefined) {
          layers = Math.max(layers, metadata.layer + 1);
        }

        tempData = tempData.subarray(4 + metadataLength);
      } catch (e) {
        break;
      }
    }

    return layers;
  }

  private static secureCleanup(buffers: Buffer[]): void {
    buffers.forEach((buffer) => {
      if (buffer) secureWipe(buffer);
    });
  }
}
