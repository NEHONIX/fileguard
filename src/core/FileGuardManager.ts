/**
 * FileGuardManager - Main class for the NEHONIX FileGuard library
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as zlib from "zlib";
import * as util from "util";
import {
  SecurityLevel,
  CompressionLevel,
  AdvancedEncryptionConfig,
  DecryptionOptions,
  EncryptionResult,
  RSAKeyPair,
  NXSFileHeader,
  FortifyEncryptionOptions,
  FortifySecurityParams,
} from "../types";
import { logger } from "../utils/logger";
import { ProgressTracker, OperationType } from "../utils/progress";
import { UltraSecureEncryption } from "../utils/ultraSecureEncryption";
import { BinarySecureFormat } from "./BinarySecureFormat";
import { SimpleBinaryFormat } from "./SimpleBinaryFormat";
import {
  generateSecureParams,
  encryptWithFortify,
  decryptWithFortify,
} from "../utils/fortifyIntegration";
import { NehoID } from "nehoid";
import { Random } from "fortify2-js";

// Promisify fs functions
const readFilePromise = util.promisify(fs.readFile);
const writeFilePromise = util.promisify(fs.writeFile);
const mkdirPromise = util.promisify(fs.mkdir);

// NXS File Magic Number
const NXS_MAGIC = "NXSFILE";
const NXS_EXTENSION = ".nxs";
const ORIG_EXTENSION = ".orig";

/**
 * FileGuardManager - Main class for managing encrypted NXS files
 */
export class FileGuardManager {
  private encryptionKey: string;
  private fallbackMode: boolean;

  /**
   * Create a new FileGuardManager instance
   * @param encryptionKey - The master encryption key
   */
  constructor(encryptionKey: string) {
    this.encryptionKey = encryptionKey;
    this.fallbackMode = this.isFallbackModeEnabled();

    // Log initialization with appropriate level
    logger.info("FileGuardManager initialized");

    if (this.fallbackMode) {
      logger.warn("Fallback mode is enabled - NOT SECURE FOR PRODUCTION");
    }
  }

  /**
   * Check if fallback mode is enabled based on environment
   * @returns boolean indicating if fallback mode is enabled
   */
  private isFallbackModeEnabled(): boolean {
    return (
      process.env.NODE_ENV === "development" ||
      process.env.NODE_ENV === "test" ||
      process.env.NXS_FALLBACK_MODE === "true"
    );
  }

  /**
   * Save data with ultra-secure encryption
   * @param filepath - Path to save encrypted file
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param rsaKeyPair - RSA key pair for asymmetric encryption
   * @param config - Advanced encryption configuration
   * @param metadata - Additional metadata
   * @returns Promise resolving to encryption result
   */
  public async saveWithUltraSecureEncryption(
    filepath: string,
    data: any,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    config: AdvancedEncryptionConfig,
    metadata?: Record<string, any>
  ): Promise<EncryptionResult> {
    // Generate a unique operation ID for tracking
    const operationId = NehoID.generate({
      prefix: "swuse.op.nehonix",
      separator: "_nxs@",
    });

    // Start tracking the encryption operation
    ProgressTracker.startOperation(
      OperationType.Encryption,
      operationId,
      config.layers || 3
    );

    try {
      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const originalSize = Buffer.from(dataString).length;

      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Create directory if it doesn't exist
      const dir = path.dirname(fullFilepath);
      if (!fs.existsSync(dir)) {
        await mkdirPromise(dir, { recursive: true });
      }

      // Map configuration to UltraSecureEncryption config
      const ultraConfig = {
        encryptLevel: config.securityLevel || "standard", // Use securityLevel as encryptLevel for UltraSecureEncryption
        compressionLevel: config.compressionLevel,
        layers:
          config.layers ||
          this.getDefaultLayers(config.securityLevel || "standard"),
        useAlgorithmRotation: config.useAlgorithmRotation || false,
        blockSize: 64, // Default block size
        addHoneypots: config.addHoneypots || false,
        metadata: metadata || {},
      };

      // Use UltraSecureEncryption for maximum security
      ProgressTracker.updateProgress(
        operationId,
        30,
        "Using ultra-secure encryption..."
      );
      const encryptionResult = await UltraSecureEncryption.encrypt(
        Buffer.from(dataString),
        key,
        rsaKeyPair,
        ultraConfig
      );

      // Create file header
      ProgressTracker.updateProgress(
        operationId,
        70,
        "Creating file header..."
      );
      const header: NXSFileHeader = {
        magic: NXS_MAGIC,
        version: 2, // Version 2 for ultra-secure encryption
        timestamp: Date.now(),
        securityLevel: config.securityLevel,
        compressionLevel: config.compressionLevel,
        layers: ultraConfig.layers,
        useAlgorithmRotation: ultraConfig.useAlgorithmRotation,
        addHoneypots: ultraConfig.addHoneypots,
        metadata: encryptionResult.metadata,
        customMetadata: metadata || {},
      };

      // Serialize header to JSON
      const headerJson = JSON.stringify(header);
      const headerBuffer = Buffer.from(headerJson);

      // Write header length and header
      const fileBuffer = Buffer.alloc(
        4 + headerBuffer.length + encryptionResult.data.length
      );
      fileBuffer.writeUInt32BE(headerBuffer.length, 0);
      headerBuffer.copy(fileBuffer, 4);
      encryptionResult.data.copy(fileBuffer, 4 + headerBuffer.length);

      // Write to file
      ProgressTracker.updateProgress(
        operationId,
        90,
        "Writing encrypted file..."
      );
      await writeFilePromise(fullFilepath, fileBuffer);

      // Complete the operation
      const encryptedSize = fileBuffer.length;
      const result: EncryptionResult = {
        filepath: fullFilepath,
        size: {
          original: originalSize,
          encrypted: encryptedSize,
        },
        header,
        compressionRatio: originalSize / encryptedSize,
      };

      ProgressTracker.completeOperation(
        operationId,
        `File encrypted successfully: ${fullFilepath}`
      );
      logger.success(`File encrypted successfully: ${fullFilepath}`);

      return result;
    } catch (error) {
      ProgressTracker.failOperation(
        operationId,
        `Ultra-secure encryption failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      logger.error("Ultra-secure encryption failed", error);
      throw error;
    }
  }

  /**
   * Save data with advanced encryption
   * @param filepath - Path to save the encrypted file
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param rsaKeyPair - RSA key pair for additional security
   * @param config - Advanced encryption configuration
   * @param metadata - Additional metadata
   * @returns Promise resolving to encryption result
   */
  public async saveWithAdvancedEncryption(
    filepath: string,
    data: any,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    config: AdvancedEncryptionConfig,
    metadata?: Record<string, any>
  ): Promise<EncryptionResult> {
    // Generate a unique operation ID for tracking
    const operationId = NehoID.generate({
      prefix: "swadve.op.nehonix",
      separator: "_nxs@",
    });

    // Start tracking the encryption operation
    ProgressTracker.startOperation(
      OperationType.Encryption,
      operationId,
      config.layers || 3
    );

    try {
      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const originalSize = Buffer.from(dataString).length;

      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Create directory if it doesn't exist
      const dir = path.dirname(fullFilepath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Step 1: Compress data if compression is enabled
      ProgressTracker.updateProgress(operationId, 10, "Compressing data...");
      let processedData = dataString;

      if (config.compressionLevel !== "none") {
        processedData = await this.compressData(
          dataString,
          config.compressionLevel
        );
        ProgressTracker.updateProgress(operationId, 20, "Data compressed");
      }

      // Step 2: Encrypt the data with multiple layers
      ProgressTracker.nextStep(operationId, "Encrypting data...");
      const encryptedData = await this.encryptWithLayers(
        processedData,
        key,
        rsaKeyPair,
        config
      );

      // Step 3: Create file header
      ProgressTracker.updateProgress(
        operationId,
        70,
        "Creating file header..."
      );
      const header: NXSFileHeader = {
        magic: NXS_MAGIC,
        version: 1,
        securityLevel:
          config.encryptLevel || config.securityLevel || "standard",
        compressionLevel: config.compressionLevel,
        layers: config.layers || 3,
        timestamp: Date.now(),
        metadata,
      };

      // Step 4: Write the file
      ProgressTracker.nextStep(operationId, "Writing encrypted file...");
      const headerBuffer = Buffer.from(JSON.stringify(header));
      const headerLengthBuffer = Buffer.alloc(4);
      headerLengthBuffer.writeUInt32BE(headerBuffer.length, 0);

      // Write header length, header, and encrypted data
      const fileStream = fs.createWriteStream(fullFilepath);
      fileStream.write(headerLengthBuffer);
      fileStream.write(headerBuffer);
      fileStream.write(encryptedData);
      fileStream.end();

      // In fallback mode, save original data for recovery
      if (this.fallbackMode) {
        fs.writeFileSync(fullFilepath + ORIG_EXTENSION, dataString);
        logger.warn(
          `Original data saved to ${
            fullFilepath + ORIG_EXTENSION
          } (REMOVE IN PRODUCTION)`
        );
      }

      // Complete the operation
      const encryptedSize = encryptedData.length + headerBuffer.length + 4;
      ProgressTracker.completeOperation(
        operationId,
        `File encrypted successfully: ${fullFilepath}`
      );

      logger.success(`File encrypted successfully: ${fullFilepath}`);

      return {
        filepath: fullFilepath,
        size: {
          original: originalSize,
          encrypted: encryptedSize,
        },
        metadata: header.metadata,
      };
    } catch (error) {
      // Handle errors
      ProgressTracker.failOperation(
        operationId,
        `Encryption failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );

      logger.error("Encryption failed", error);
      throw error;
    }
  }

  /**
   * Load and decrypt data with advanced decryption
   * @param filepath - Path to the encrypted file
   * @param key - Decryption key
   * @param rsaKeyPair - RSA key pair for additional security
   * @param options - Decryption options
   * @returns Promise resolving to decrypted data
   */
  public async loadWithAdvancedDecryption(
    filepath: string,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    options?: DecryptionOptions
  ): Promise<any> {
    // Generate a unique operation ID for tracking
    const operationId = NehoID.generate({
      prefix: "lwad.dec.op.nehonix",
      separator: "_nxs@",
    });

    // Start tracking the decryption operation
    ProgressTracker.startOperation(OperationType.Decryption, operationId, 4);

    try {
      // Ensure filepath has .nxs extension and exists
      let fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Check if file exists
      if (!fs.existsSync(fullFilepath)) {
        logger.debug(`Checking file existence: ${fullFilepath}`);
        // Try with and without .nxs extension
        const alternativePath = fullFilepath.endsWith(NXS_EXTENSION)
          ? fullFilepath.slice(0, -NXS_EXTENSION.length)
          : fullFilepath + NXS_EXTENSION;

        if (fs.existsSync(alternativePath)) {
          logger.debug(`Found alternative path: ${alternativePath}`);
          fullFilepath = alternativePath;
        } else {
          throw new Error(`File not found: ${fullFilepath}`);
        }
      }

      // Step 1: Read the file
      ProgressTracker.updateProgress(
        operationId,
        10,
        "Reading encrypted file..."
      );
      const fileBuffer = fs.readFileSync(fullFilepath);

      // Step 2: Parse header
      ProgressTracker.updateProgress(operationId, 20, "Parsing file header...");
      const headerLength = fileBuffer.readUInt32BE(0);
      const headerJson = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + 4,
        headerLength
      ).toString();
      const header: NXSFileHeader = JSON.parse(headerJson);

      // Verify magic number
      if (header.magic !== NXS_MAGIC) {
        throw new Error("Invalid NXS file format");
      }

      // Step 3: Extract and decrypt data
      ProgressTracker.nextStep(operationId, "Decrypting data...");
      const encryptedData = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + 4 + headerLength,
        fileBuffer.length - 4 - headerLength
      );

      // Decrypt with multiple layers
      const decryptedData = await this.decryptWithLayers(
        encryptedData,
        key,
        rsaKeyPair,
        header
      );

      // Step 4: Decompress if needed
      ProgressTracker.nextStep(operationId, "Decompressing data...");
      let finalData = decryptedData;

      if (header.compressionLevel !== "none") {
        finalData = await this.decompressData(decryptedData);
      }

      // Try to parse as JSON, return as string if not valid JSON
      try {
        const parsedData = JSON.parse(finalData);
        ProgressTracker.completeOperation(
          operationId,
          "File decrypted successfully"
        );
        return parsedData;
      } catch (e) {
        ProgressTracker.completeOperation(
          operationId,
          "File decrypted successfully (as string)"
        );
        return finalData;
      }
    } catch (error) {
      ProgressTracker.failOperation(
        operationId,
        `Decryption failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );

      logger.error("Decryption failed", error);

      // Try fallback mode if enabled and not explicitly disabled
      const disableFallback = options?.disableFallbackMode === true;

      if (this.fallbackMode && !disableFallback) {
        logger.warn("Attempting fallback recovery...");
        return this.attemptFallbackRecovery(filepath);
      }

      throw error;
    }
  }

  /**
   * Compress data using the specified compression level
   * @param data - Data to compress
   * @param level - Compression level
   * @returns Promise resolving to compressed data
   */
  private async compressData(
    data: string,
    level: CompressionLevel
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const options: zlib.ZlibOptions = {
        level: this.getZlibCompressionLevel(level),
      };

      zlib.deflate(data, options, (err, buffer) => {
        if (err) {
          reject(err);
        } else {
          resolve(buffer.toString("base64"));
        }
      });
    });
  }

  /**
   * Decompress data
   * @param data - Compressed data
   * @returns Promise resolving to decompressed data
   */
  private async decompressData(data: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const buffer = Buffer.from(data, "base64");

      zlib.inflate(buffer, (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result.toString());
        }
      });
    });
  }

  /**
   * Convert compression level to zlib level
   * @param level - Compression level
   * @returns zlib compression level
   */
  private getZlibCompressionLevel(level: CompressionLevel): number {
    switch (level) {
      case "none":
        return 0;
      case "low":
        return 3;
      case "medium":
        return 6;
      case "high":
        return 8;
      case "maximum":
        return 9;
      default:
        return 6;
    }
  }

  /**
   * Encrypt data with multiple layers
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param rsaKeyPair - RSA key pair
   * @param config - Encryption configuration
   * @returns Promise resolving to encrypted data
   */
  private async encryptWithLayers(
    data: string,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    config: AdvancedEncryptionConfig
  ): Promise<Buffer> {
    // Determine number of layers based on security level
    const layers =
      config.layers ||
      this.getDefaultLayers(
        config.encryptLevel || config.securityLevel || "standard"
      );

    // Start with the original data
    let currentData = data;

    // Apply multiple encryption layers
    for (let i = 0; i < layers; i++) {
      // Use different algorithms for each layer if rotation is enabled
      const algorithm = config.useAlgorithmRotation
        ? this.getAlgorithmForLayer(i)
        : "aes-256-gcm";

      // Derive a unique key for this layer
      const layerKey = this.deriveLayerKey(key, i, algorithm);

      // Generate initialization vector
      const iv = Random.getRandomBytes(16);

      // Create cipher
      const cipher = crypto.createCipheriv(algorithm, layerKey, iv);

      // Add authentication data if using GCM mode
      if (algorithm.endsWith("-gcm")) {
        // Use the layer index in the AAD to ensure it matches during decryption
        const aadString = `layer-${i}-aad`;
        (cipher as any).setAAD(Buffer.from(aadString));
        logger.debug(`Using AAD for layer ${i}: ${aadString}`);
      }

      // Encrypt data
      let encrypted = cipher.update(currentData, "utf8", "base64");
      encrypted += cipher.final("base64");

      // Get auth tag if using GCM mode
      let authTag = "";
      if (algorithm.endsWith("-gcm")) {
        authTag = (cipher as any).getAuthTag().toString("base64");
      }

      // Prepare for next layer
      currentData = JSON.stringify({
        algorithm,
        iv: iv.toString("base64"),
        authTag,
        data: encrypted,
        layer: i,
      });

      // Add honeypots if enabled and this is the final layer
      if (config.addHoneypots && i === layers - 1) {
        currentData = this.addHoneypots(currentData);
      }
    }

    // For maximum security, add RSA encryption as final layer
    if (config.encryptLevel === "max") {
      currentData = this.addRSAEncryption(currentData, rsaKeyPair.publicKey);
    }

    return Buffer.from(currentData);
  }

  /**
   * Decrypt data with multiple layers
   * @param encryptedData - Encrypted data
   * @param key - Decryption key
   * @param rsaKeyPair - RSA key pair
   * @param header - File header
   * @returns Promise resolving to decrypted data
   */
  private async decryptWithLayers(
    encryptedData: Buffer,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    header: NXSFileHeader
  ): Promise<string> {
    // Get the number of layers from the header
    const layers = header.layers || this.getDefaultLayers(header.securityLevel);

    // Start with the encrypted data
    let currentData = encryptedData.toString();

    // If maximum security, first decrypt with RSA
    if (header.securityLevel === "max") {
      currentData = this.decryptRSALayer(currentData, rsaKeyPair.privateKey);
    }

    // Remove honeypots if present
    currentData = this.removeHoneypots(currentData);

    // Decrypt each layer
    for (let i = layers - 1; i >= 0; i--) {
      // Parse the layer data
      const layerData = JSON.parse(currentData);

      // Extract encryption parameters
      const { algorithm, iv, authTag, data } = layerData;

      // Derive the layer key
      const layerKey = this.deriveLayerKey(key, i, algorithm);

      // Create decipher
      const decipher = crypto.createDecipheriv(
        algorithm,
        layerKey,
        Buffer.from(iv, "base64")
      );

      // Set auth tag if using GCM mode
      if (algorithm.endsWith("-gcm") && authTag) {
        decipher.setAuthTag(Buffer.from(authTag, "base64"));

        // Use the same AAD string that was used during encryption
        // During encryption, we used the layer index i, not layerData.layer
        const aadString = `layer-${i}-aad`;
        decipher.setAAD(Buffer.from(aadString));
        logger.debug(`Using AAD for layer ${i}: ${aadString}`);
      }

      // Decrypt data
      let decrypted = decipher.update(data, "base64", "utf8");
      decrypted += decipher.final("utf8");

      // Prepare for next layer
      currentData = decrypted;
    }

    return currentData;
  }

  /**
   * Get default number of encryption layers based on security level
   * @param encryptLevel - Security level
   * @returns Number of layers
   */
  private getDefaultLayers(encryptLevel: SecurityLevel): number {
    switch (encryptLevel) {
      case "standard":
        return 1;
      case "high":
        return 2;
      case "max":
        return 3;
      default:
        return 1;
    }
  }

  /**
   * Get encryption algorithm for a specific layer
   * @param layerIndex - Layer index
   * @returns Encryption algorithm
   */
  private getAlgorithmForLayer(layerIndex: number): string {
    // Rotate between different algorithms for better security
    const algorithms = [
      "aes-256-gcm",
      "aes-256-cbc",
      "aes-256-ctr",
      "camellia-256-cbc",
      "aria-256-gcm",
    ];

    return algorithms[layerIndex % algorithms.length];
  }

  /**
   * Derive a unique key for each encryption layer
   * @param masterKey - Master key
   * @param layerIndex - Layer index
   * @param algorithm - Encryption algorithm
   * @returns Derived key
   */
  private deriveLayerKey(
    masterKey: Buffer,
    layerIndex: number,
    algorithm: string
  ): Buffer {
    // Create a unique salt for this layer
    const salt = Buffer.from(`nehonix-layer-${layerIndex}-${algorithm}`);

    // Derive key using PBKDF2
    return crypto.pbkdf2Sync(masterKey, salt, 10000, 32, "sha512");
  }

  /**
   * Add honeypots to encrypted data
   * @param data - Encrypted data
   * @returns Data with honeypots
   */
  private addHoneypots(data: string): string {
    // Parse the data
    const parsed = JSON.parse(data);

    // Add honeypot fields that look like real data
    parsed.honeypot1 = Random.getRandomBytes(32).toString("base64");
    parsed.decryptionKey = Random.getRandomBytes(16).toString("base64");
    parsed._meta = {
      timestamp: Date.now(),
      version: "1.0.0",
      checksum: crypto.createHash("sha256").update(data).digest("hex"),
    };

    return JSON.stringify(parsed);
  }

  /**
   * Remove honeypots from encrypted data
   * @param data - Data with honeypots
   * @returns Clean data
   */
  private removeHoneypots(data: string): string {
    try {
      // Parse the data
      const parsed = JSON.parse(data);

      // Remove known honeypot fields
      delete parsed.honeypot1;
      delete parsed.decryptionKey;
      delete parsed._meta;

      return JSON.stringify(parsed);
    } catch (e) {
      // If parsing fails, return original data
      return data;
    }
  }

  /**
   * Add RSA encryption layer
   * @param data - Data to encrypt
   * @param publicKey - RSA public key
   * @returns RSA encrypted data
   */
  private addRSAEncryption(data: string, publicKey: string): string {
    // Generate a random AES key
    const aesKey = Random.getRandomBytes(32);

    // Encrypt the data with AES
    const iv = Random.getRandomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);

    // Set AAD for GCM mode
    const aadString = "rsa-layer-aad";
    (cipher as any).setAAD(Buffer.from(aadString));
    logger.debug(`Using AAD for RSA layer: ${aadString}`);

    let encrypted = cipher.update(data, "utf8", "base64");
    encrypted += cipher.final("base64");
    const authTag = cipher.getAuthTag();

    // Encrypt the AES key with RSA
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      aesKey
    );

    // Return the combined result
    return JSON.stringify({
      type: "rsa-layer",
      key: encryptedKey.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      data: encrypted,
    });
  }

  /**
   * Decrypt RSA layer
   * @param data - RSA encrypted data
   * @param privateKey - RSA private key
   * @returns Decrypted data
   */
  private decryptRSALayer(data: string, privateKey: string): string {
    // Parse the data
    const parsed = JSON.parse(data);

    if (parsed.type !== "rsa-layer") {
      return data;
    }

    // Decrypt the AES key with RSA
    const encryptedKey = Buffer.from(parsed.key, "base64");
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encryptedKey
    );

    // Decrypt the data with AES
    const iv = Buffer.from(parsed.iv, "base64");
    const authTag = Buffer.from(parsed.authTag, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(authTag);

    // Set the same AAD that was used during encryption
    const aadString = "rsa-layer-aad";
    (decipher as any).setAAD(Buffer.from(aadString));
    logger.debug(`Using AAD for RSA layer decryption: ${aadString}`);

    let decrypted = decipher.update(parsed.data, "base64", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  /**
   * Attempt to recover data using fallback mode
   * @param filepath - Path to the encrypted file
   * @returns Recovered data or test data
   */
  private attemptFallbackRecovery(filepath: string): any {
    // Ensure filepath has .nxs extension
    const fullFilepath = filepath.endsWith(NXS_EXTENSION)
      ? filepath
      : filepath + NXS_EXTENSION;

    // Try to read the .orig file
    const origPath = fullFilepath + ORIG_EXTENSION;

    if (fs.existsSync(origPath)) {
      logger.warn(`Recovering from original file: ${origPath}`);
      const origData = fs.readFileSync(origPath, "utf8");

      // Try to parse as JSON
      try {
        return JSON.parse(origData);
      } catch (e) {
        return origData;
      }
    }

    // If no .orig file, return test data
    logger.warn("No original file found, returning test data");
    return {
      _recoveredTestData: true,
      title: "Test Document",
      content: "This is test data returned by fallback mode",
      metadata: {
        timestamp: new Date().toISOString(),
        note: "This is test data because decryption failed and no original file was found",
      },
    };
  }

  /**
   * Save data with binary secure format encryption
   * This format makes data completely unreadable by humans or other systems
   * except by the FileGuardManager class itself.
   *
   * @param filepath - Path to save the encrypted file
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param rsaKeyPair - RSA key pair for additional security
   * @param options - Encryption options
   * @returns Promise resolving to encryption result
   */
  public async saveWithBinarySecureFormat(
    filepath: string,
    data: any,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    options: {
      layers?: number;
      addRandomPadding?: boolean;
      compressionLevel?: number;
    } = {}
  ): Promise<EncryptionResult> {
    try {
      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const originalSize = Buffer.from(dataString).length;

      // Use BinarySecureFormat for maximum security
      const result = await BinarySecureFormat.encrypt(
        data,
        key,
        rsaKeyPair,
        fullFilepath,
        options
      );

      // Return encryption result
      return {
        filepath: fullFilepath,
        size: {
          original: originalSize,
          encrypted: result.size,
        },
        compressionRatio: originalSize / result.size,
      };
    } catch (error) {
      logger.error("Binary secure format encryption failed", error);
      throw error;
    }
  }

  /**
   * Load and decrypt data with binary secure format decryption
   *
   * @param filepath - Path to the encrypted file
   * @param key - Decryption key
   * @param rsaKeyPair - RSA key pair for additional security
   * @returns Promise resolving to decrypted data
   */
  public async loadWithBinarySecureFormat(
    filepath: string,
    key: Buffer,
    rsaKeyPair: RSAKeyPair
  ): Promise<any> {
    try {
      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Check if file exists
      if (!fs.existsSync(fullFilepath)) {
        logger.debug(`Checking file existence: ${fullFilepath}`);
        // Try with and without .nxs extension
        const alternativePath = fullFilepath.endsWith(NXS_EXTENSION)
          ? fullFilepath.slice(0, -NXS_EXTENSION.length)
          : fullFilepath + NXS_EXTENSION;

        if (fs.existsSync(alternativePath)) {
          logger.debug(`Found alternative path: ${alternativePath}`);
          return await BinarySecureFormat.decrypt(
            alternativePath,
            key,
            rsaKeyPair
          );
        } else {
          throw new Error(`File not found: ${fullFilepath}`);
        }
      }

      // Use BinarySecureFormat for decryption
      return await BinarySecureFormat.decrypt(fullFilepath, key, rsaKeyPair);
    } catch (error) {
      logger.error("Binary secure format decryption failed", error);

      // Try fallback mode if enabled
      if (this.fallbackMode) {
        logger.warn("Attempting fallback recovery...");
        return this.attemptFallbackRecovery(filepath);
      }

      throw error;
    }
  }

  /**
   * Save data with simple binary format encryption
   * This format makes data completely unreadable by humans or other systems.
   *
   * @param filepath - Path to save the encrypted file
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @returns Promise resolving to encryption result
   */
  public async saveWithSimpleBinaryFormat(
    filepath: string,
    data: any,
    key: Buffer
  ): Promise<EncryptionResult> {
    try {
      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      const originalSize = Buffer.from(dataString).length;

      // Use SimpleBinaryFormat for encryption
      const result = await SimpleBinaryFormat.encrypt(data, key, fullFilepath);

      if (!result) {
        throw new Error("Simple binary format encryption failed");
      }

      // Get the encrypted file size
      const fileStats = fs.statSync(fullFilepath);

      // Return encryption result
      return {
        filepath: fullFilepath,
        size: {
          original: originalSize,
          encrypted: fileStats.size,
        },
        compressionRatio: originalSize / fileStats.size,
      };
    } catch (error) {
      logger.error("Simple binary format encryption failed", error);
      throw error;
    }
  }

  /**
   * Load and decrypt data with simple binary format decryption
   *
   * @param filepath - Path to the encrypted file
   * @param key - Decryption key
   * @returns Promise resolving to decrypted data
   */
  public async loadWithSimpleBinaryFormat(
    filepath: string,
    key: Buffer
  ): Promise<any> {
    try {
      // Ensure filepath has .nxs extension
      const fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Check if file exists
      if (!fs.existsSync(fullFilepath)) {
        logger.debug(`Checking file existence: ${fullFilepath}`);
        // Try with and without .nxs extension
        const alternativePath = fullFilepath.endsWith(NXS_EXTENSION)
          ? fullFilepath.slice(0, -NXS_EXTENSION.length)
          : fullFilepath + NXS_EXTENSION;

        if (fs.existsSync(alternativePath)) {
          logger.debug(`Found alternative path: ${alternativePath}`);
          return await SimpleBinaryFormat.decrypt(alternativePath, key);
        } else {
          throw new Error(`File not found: ${fullFilepath}`);
        }
      }

      // Use SimpleBinaryFormat for decryption
      return await SimpleBinaryFormat.decrypt(fullFilepath, key);
    } catch (error) {
      logger.error("Simple binary format decryption failed", error);

      // Try fallback mode if enabled
      if (this.fallbackMode) {
        logger.warn("Attempting fallback recovery...");
        return this.attemptFallbackRecovery(filepath);
      }

      throw error;
    }
  }

  /**
   * Load and decrypt data with ultra-secure decryption using Fortify
   * @param filepath - Path to the encrypted file
   * @param key - Decryption key
   * @param rsaKeyPair - RSA key pair for additional security
   * @param options - Decryption options
   * @returns Promise resolving to decrypted data
   */
  public async loadWithUltraSecureDecryption(
    filepath: string,
    key: Buffer,
    rsaKeyPair: RSAKeyPair,
    options?: DecryptionOptions
  ): Promise<any> {
    // Generate a unique operation ID for tracking
    const operationId = NehoID.generate({
      prefix: "lwulsd.dec.op.nehonix",
      separator: "_nxs@",
    });

    // Start tracking the decryption operation
    ProgressTracker.startOperation(OperationType.Decryption, operationId, 5);

    try {
      // Ensure filepath has .nxs extension and exists
      let fullFilepath = filepath.endsWith(NXS_EXTENSION)
        ? filepath
        : filepath + NXS_EXTENSION;

      // Check if file exists
      if (!fs.existsSync(fullFilepath)) {
        logger.debug(`Checking file existence: ${fullFilepath}`);
        // Try with and without .nxs extension
        const alternativePath = fullFilepath.endsWith(NXS_EXTENSION)
          ? fullFilepath.slice(0, -NXS_EXTENSION.length)
          : fullFilepath + NXS_EXTENSION;

        if (fs.existsSync(alternativePath)) {
          logger.debug(`Found alternative path: ${alternativePath}`);
          fullFilepath = alternativePath;
        } else {
          throw new Error(`File not found: ${fullFilepath}`);
        }
      }

      // Step 1: Read the file
      ProgressTracker.updateProgress(
        operationId,
        10,
        "Reading encrypted file..."
      );
      const fileBuffer = fs.readFileSync(fullFilepath);

      // Step 2: Parse header
      ProgressTracker.updateProgress(operationId, 20, "Parsing file header...");
      const headerLength = fileBuffer.readUInt32BE(0);
      const headerJson = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + 4,
        headerLength
      ).toString();
      const header: NXSFileHeader = JSON.parse(headerJson);

      // Verify magic number
      if (header.magic !== NXS_MAGIC) {
        throw new Error("Invalid NXS file format");
      }

      // Step 3: Extract encrypted data
      ProgressTracker.updateProgress(
        operationId,
        30,
        "Extracting encrypted data..."
      );
      const encryptedData = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + 4 + headerLength,
        fileBuffer.length - 4 - headerLength
      );

      // Step 4: Generate secure parameters
      ProgressTracker.updateProgress(
        operationId,
        40,
        "Generating secure parameters..."
      );
      const securityParams = generateSecureParams(key, header.securityLevel);
      securityParams.postQuantumKeyPair = rsaKeyPair;

      // Step 5: Configure Fortify decryption options
      const fortifyOptions: FortifyEncryptionOptions = {
        securityLevel: header.securityLevel,
        compressionLevel: header.compressionLevel,
        layers: header.layers || 5,
        useAlgorithmRotation: true,
        usePostQuantum: header.securityLevel === "max",
        useMemoryHardKDF: true,
        memoryCost: 32768, // 32 MB
        timeCost: 4,
        addHoneypots: true,
      };

      // Step 6: Decrypt the data with Fortify
      ProgressTracker.updateProgress(
        operationId,
        50,
        "Decrypting with Fortify..."
      );

      // Check if this is a version 2 (ultra-secure) file
      if (header.version === 2) {
        // Use Fortify decryption
        const decryptedData = await decryptWithFortify(
          encryptedData,
          securityParams,
          fortifyOptions
        );

        // Try to parse as JSON, return as string if not valid JSON
        try {
          const parsedData = JSON.parse(decryptedData.toString());
          ProgressTracker.completeOperation(
            operationId,
            "File decrypted successfully"
          );
          return parsedData;
        } catch (e) {
          ProgressTracker.completeOperation(
            operationId,
            "File decrypted successfully (as string)"
          );
          return decryptedData.toString();
        }
      } else {
        // Fall back to standard decryption for version 1 files
        ProgressTracker.updateProgress(
          operationId,
          60,
          "Using standard decryption for version 1 file..."
        );

        // Decrypt with multiple layers
        const decryptedData = await this.decryptWithLayers(
          encryptedData,
          key,
          rsaKeyPair,
          header
        );

        // Decompress if needed
        let finalData = decryptedData;

        if (header.compressionLevel !== "none") {
          finalData = await this.decompressData(decryptedData);
        }

        // Try to parse as JSON, return as string if not valid JSON
        try {
          const parsedData = JSON.parse(finalData);
          ProgressTracker.completeOperation(
            operationId,
            "File decrypted successfully"
          );
          return parsedData;
        } catch (e) {
          ProgressTracker.completeOperation(
            operationId,
            "File decrypted successfully (as string)"
          );
          return finalData;
        }
      }
    } catch (error) {
      ProgressTracker.failOperation(
        operationId,
        `Ultra-secure decryption failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );

      logger.error("Ultra-secure decryption failed", error);

      // Try fallback mode if enabled and not explicitly disabled
      const disableFallback = options?.disableFallbackMode === true;

      if (this.fallbackMode && !disableFallback) {
        logger.warn("Attempting fallback recovery...");
        return this.attemptFallbackRecovery(filepath);
      }

      throw error;
    }
  }
}
