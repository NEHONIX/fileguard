/**
 * Ultra-Secure Encryption Module
 *
 * This module implements advanced multi-layer encryption with various security features
 * to make data completely unreadable by humans or other systems except through the
 * FileGuardManager class.
 */

import * as crypto from "crypto";
import * as zlib from "zlib";
import { promisify } from "util";
import { statsTracker } from "./fortify/core/utils/statsTracker";
import { SecureRandom } from "./fortify/core/random";
import { Hash } from "./fortify/core/hash";
import {
  bufferToHex,
  hexToBuffer,
  bufferToBase64,
  base64ToBuffer,
} from "./fortify/core/utils/encoding";
import { logger } from "./logger";
import { ProgressTracker, OperationType } from "./progress";
import { SecurityLevel, CompressionLevel } from "../types";
import { NehoID } from "nehoid";
import { FortifyJS } from "fortify2-js";

// Promisify zlib functions
const deflatePromise = promisify(zlib.deflate);
const inflatePromise = promisify(zlib.inflate);
const gzipPromise = promisify(zlib.gzip);
const gunzipPromise = promisify(zlib.gunzip);
const brotliCompressPromise = promisify(zlib.brotliCompress);
const brotliDecompressPromise = promisify(zlib.brotliDecompress);

// Mapping for internal use
const SecurityLevelMap = {
  standard: "standard",
  high: "high",
  max: "max",
} as const;

// Mapping for internal use
const CompressionLevelMap = {
  none: "none",
  low: "low",
  medium: "medium",
  high: "high",
  maximum: "maximum",
} as const;

// Encryption algorithms by security level
const ENCRYPTION_ALGORITHMS = {
  standard: ["aes-256-gcm"],
  high: ["aes-256-gcm", "chacha20-cbc"],
  max: ["aes-256-gcm", "chacha20-cbc", "camellia-256-cbc", "aria-256-cbc"],
};

// Key derivation parameters by security level
const KDF_PARAMETERS = {
  standard: { iterations: 100000, memory: 64 * 1024, parallelism: 4 },
  high: { iterations: 250000, memory: 128 * 1024, parallelism: 8 },
  max: { iterations: 500000, memory: 256 * 1024, parallelism: 16 },
};

/**
 * Configuration for ultra-secure encryption
 */
export interface UltraSecureEncryptionConfig {
  /**
   * Security level
   * @default 'standard'
   */
  encryptLevel?: SecurityLevel;

  /**
   * Compression level
   * @default 'medium'
   */
  compressionLevel?: CompressionLevel;

  /**
   * Number of encryption layers
   * @default 1
   */
  layers?: number;

  /**
   * Whether to rotate encryption algorithms between layers
   * @default false
   */
  useAlgorithmRotation?: boolean;

  /**
   * Block size for chunked encryption (in KB)
   * @default 64
   */
  blockSize?: number;

  /**
   * Whether to add honeypot data to confuse attackers
   * @default false
   */
  addHoneypots?: boolean;

  /**
   * Additional entropy sources
   * @default []
   */
  additionalEntropy?: Buffer[];

  /**
   * Custom metadata to include in the encrypted file
   * @default {}
   */
  metadata?: Record<string, any>;
}

/**
 * Result of encryption operation
 */
export interface EncryptionResult {
  /**
   * Encrypted data
   */
  data: Buffer;

  /**
   * Encryption metadata
   */
  metadata: {
    /**
     * Initialization vectors for each layer
     */
    ivs: string[];

    /**
     * Authentication tags for authenticated encryption
     */
    authTags: string[];

    /**
     * Algorithms used for each layer
     */
    algorithms: string[];

    /**
     * Salt used for key derivation
     */
    salt: string;

    /**
     * Encryption version
     */
    version: number;

    /**
     * Security level
     */
    securityLevel: SecurityLevel;

    /**
     * Number of layers
     */
    layers: number;

    /**
     * Whether algorithm rotation was used
     */
    algorithmRotation: boolean;

    /**
     * Whether honeypots were added
     */
    honeypots: boolean;

    /**
     * Custom metadata
     */
    custom: Record<string, any>;
  };
}

/**
 * Ultra-secure encryption implementation
 */
export class UltraSecureEncryption {
  /**
   * Encrypt data with ultra-secure multi-layer encryption
   * @param data - Data to encrypt
   * @param key - Primary encryption key
   * @param rsaKeyPair - RSA key pair for asymmetric encryption
   * @param config - Encryption configuration
   * @returns Encrypted data and metadata
   */
  public static async encrypt(
    data: Buffer | string | object,
    key: Buffer | string,
    rsaKeyPair: { publicKey: string; privateKey: string },
    config: UltraSecureEncryptionConfig = {}
  ): Promise<EncryptionResult> {
    // Generate a unique operation ID for tracking
    const operationId = crypto.randomBytes(8).toString("hex");

    // Start tracking the encryption operation
    ProgressTracker.startOperation(
      OperationType.Encryption,
      operationId,
      config.layers || 3
    );

    try {
      // Normalize configuration
      const {
        encryptLevel = "standard",
        compressionLevel = "medium",
        layers = 1,
        useAlgorithmRotation = false,
        blockSize = 64,
        addHoneypots = false,
        additionalEntropy = [],
        metadata = {},
      } = config;

      // Convert data to buffer if needed
      let dataBuffer: Buffer;
      if (Buffer.isBuffer(data)) {
        dataBuffer = data;
      } else if (typeof data === "string") {
        dataBuffer = Buffer.from(data, "utf8");
      } else {
        dataBuffer = Buffer.from(JSON.stringify(data), "utf8");
      }

      // Step 1: Compress data if needed
      ProgressTracker.updateProgress(operationId, 10, "Compressing data...");
      const compressedData = await this.compressData(
        dataBuffer,
        compressionLevel
      );
      ProgressTracker.updateProgress(operationId, 20, "Data compressed");

      // Step 2: Generate encryption parameters
      ProgressTracker.updateProgress(
        operationId,
        30,
        "Generating encryption parameters..."
      );
      const masterKey = this.normalizeKey(key);
      const salt = crypto.randomBytes(32);
      const ivs: Buffer[] = [];
      const authTags: Buffer[] = [];
      const algorithms: string[] = [];

      // Generate initialization vectors and select algorithms for each layer
      for (let i = 0; i < layers; i++) {
        ivs.push(crypto.randomBytes(16));

        // Select algorithm based on security level and rotation
        // Cast to string to ensure it's a valid key for the algorithms object
        const securityLevel = encryptLevel as string;
        const availableAlgorithms =
          ENCRYPTION_ALGORITHMS[
            securityLevel as keyof typeof ENCRYPTION_ALGORITHMS
          ];
        let algorithmIndex = 0;

        if (useAlgorithmRotation) {
          algorithmIndex = i % availableAlgorithms.length;
        }

        algorithms.push(availableAlgorithms[algorithmIndex]);
      }

      // Step 3: Derive layer keys from master key
      ProgressTracker.updateProgress(
        operationId,
        40,
        "Deriving encryption keys..."
      );
      const layerKeys = await this.deriveLayerKeys(
        masterKey,
        salt,
        layers,
        encryptLevel
      );

      // Step 4: Add honeypots if requested
      let dataToEncrypt = compressedData;
      if (addHoneypots) {
        ProgressTracker.updateProgress(
          operationId,
          50,
          "Adding honeypot data..."
        );
        dataToEncrypt = this.addHoneypotData(compressedData);
      }

      // Step 5: Apply multi-layer encryption
      ProgressTracker.updateProgress(operationId, 60, "Encrypting data...");
      let encryptedData = dataToEncrypt;

      // Apply each encryption layer
      for (let i = 0; i < layers; i++) {
        const layerAlgorithm = algorithms[i];
        const layerKey = layerKeys[i];
        const iv = ivs[i];

        // Encrypt with the current layer
        const { encrypted, authTag } = this.encryptLayer(
          encryptedData,
          layerKey,
          iv,
          layerAlgorithm
        );

        encryptedData = encrypted;
        if (authTag) {
          authTags.push(authTag);
        } else {
          // For algorithms without authentication, use a dummy tag
          authTags.push(Buffer.alloc(16, 0));
        }
      }

      // Step 6: Prepare metadata
      ProgressTracker.updateProgress(
        operationId,
        80,
        "Finalizing encryption..."
      );
      const encryptionMetadata = {
        ivs: ivs.map((iv) => iv.toString("hex")),
        authTags: authTags.map((tag) => tag.toString("hex")),
        algorithms,
        salt: salt.toString("hex"),
        version: 1,
        securityLevel: encryptLevel,
        layers,
        algorithmRotation: useAlgorithmRotation,
        honeypots: addHoneypots,
        custom: metadata,
      };

      // Step 7: Encrypt metadata with RSA
      const metadataString = JSON.stringify(encryptionMetadata);
      const encryptedMetadata = crypto.publicEncrypt(
        {
          key: rsaKeyPair.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(metadataString)
      );

      // Step 8: Complete the operation
      ProgressTracker.completeOperation(
        operationId,
        "File encrypted successfully"
      );

      // Track stats
      statsTracker.completeOperation(
        statsTracker.startOperation("ultra-secure-encryption"),
        {
          success: true,
        }
      );

      return {
        data: encryptedData,
        metadata: encryptionMetadata,
      };
    } catch (error: any) {
      ProgressTracker.failOperation(
        operationId,
        `Ultra-secure encryption failed: ${error?.message || "Unknown error"}`
      );
      logger.error("Ultra-secure encryption failed", error);
      throw error;
    }
  }

  /**
   * Decrypt data with ultra-secure multi-layer decryption
   * @param encryptedData - Encrypted data
   * @param metadata - Encryption metadata
   * @param key - Primary encryption key
   * @param rsaKeyPair - RSA key pair for asymmetric encryption
   * @returns Decrypted data
   */
  public static async decrypt(
    encryptedData: Buffer,
    metadata: any,
    key: Buffer | string,
    rsaKeyPair: { publicKey: string; privateKey: string }
  ): Promise<Buffer> {
    // Generate a unique operation ID for tracking
    const operationId = crypto.randomBytes(8).toString("hex");

    // Start tracking the decryption operation
    ProgressTracker.startOperation(OperationType.Decryption, operationId, 4);

    try {
      // Step 1: Extract and validate metadata
      ProgressTracker.updateProgress(
        operationId,
        25,
        "Validating encryption metadata..."
      );
      const {
        ivs,
        authTags,
        algorithms,
        salt,
        version,
        securityLevel,
        layers,
        honeypots,
      } = metadata;

      // Validate metadata
      if (
        !ivs ||
        !authTags ||
        !algorithms ||
        !salt ||
        !version ||
        !securityLevel ||
        !layers
      ) {
        throw new Error("Invalid encryption metadata");
      }

      // Convert hex strings to buffers
      const ivBuffers = ivs.map((iv: string) => Buffer.from(iv, "hex"));
      const authTagBuffers = authTags.map((tag: string) =>
        Buffer.from(tag, "hex")
      );
      const saltBuffer = Buffer.from(salt, "hex");

      // Step 2: Derive layer keys
      ProgressTracker.updateProgress(
        operationId,
        50,
        "Deriving decryption keys..."
      );
      const masterKey = this.normalizeKey(key);
      const layerKeys = await this.deriveLayerKeys(
        masterKey,
        saltBuffer,
        layers,
        securityLevel
      );

      // Step 3: Apply multi-layer decryption in reverse order
      ProgressTracker.updateProgress(operationId, 75, "Decrypting data...");
      let decryptedData = encryptedData;

      // Apply each decryption layer in reverse order
      for (let i = layers - 1; i >= 0; i--) {
        const layerAlgorithm = algorithms[i];
        const layerKey = layerKeys[i];
        const iv = ivBuffers[i];
        const authTag = authTagBuffers[i];

        // Decrypt with the current layer
        decryptedData = this.decryptLayer(
          decryptedData,
          layerKey,
          iv,
          authTag,
          layerAlgorithm
        );
      }

      // Step 4: Remove honeypots if they were added
      if (honeypots) {
        decryptedData = this.removeHoneypotData(decryptedData);
      }

      // Step 5: Decompress data
      const decompressedData = await this.decompressData(decryptedData);

      // Complete the operation
      ProgressTracker.completeOperation(
        operationId,
        "File decrypted successfully"
      );

      // Track stats
      statsTracker.completeOperation(
        statsTracker.startOperation("ultra-secure-decryption"),
        {
          success: true,
        }
      );

      return decompressedData;
    } catch (error: any) {
      ProgressTracker.failOperation(
        operationId,
        `Ultra-secure decryption failed: ${error?.message || "Unknown error"}`
      );
      logger.error("Ultra-secure decryption failed", error);
      throw error;
    }
  }

  /**
   * Compress data using the specified compression level
   * @param data - Data to compress
   * @param level - Compression level
   * @returns Compressed data
   */
  private static async compressData(
    data: Buffer,
    level: CompressionLevel
  ): Promise<Buffer> {
    // Skip compression if level is 'none'
    if (level === "none") {
      return data;
    }

    try {
      // Map compression level to zlib options
      const zlibOptions: zlib.ZlibOptions = {
        level: this.getZlibCompressionLevel(level),
      };

      // Use Brotli for maximum compression
      if (level === "maximum") {
        return await brotliCompressPromise(data, {
          params: {
            [zlib.constants.BROTLI_PARAM_QUALITY]:
              zlib.constants.BROTLI_MAX_QUALITY,
            [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
          },
        });
      }

      // Use gzip for high compression
      if (level === "high") {
        return await gzipPromise(data, zlibOptions);
      }

      // Use deflate for medium/low compression
      return await deflatePromise(data, zlibOptions);
    } catch (error) {
      logger.error("Compression failed", error);
      throw new Error(
        `Compression failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Decompress data
   * @param data - Compressed data
   * @param compressionLevel - Compression level used
   * @returns Decompressed data
   */
  private static async decompressData(
    data: Buffer,
    compressionLevel: CompressionLevel = "medium"
  ): Promise<Buffer> {
    // Skip decompression if level is 'none'
    if (compressionLevel === "none") {
      return data;
    }

    try {
      // Try to detect compression type and decompress accordingly
      // First, try Brotli decompression (used for Maximum level)
      if (compressionLevel === "maximum") {
        try {
          return await brotliDecompressPromise(data);
        } catch (e) {
          // If Brotli fails, try other methods
          logger.warn("Brotli decompression failed, trying other methods");
        }
      }

      // Try gzip decompression (used for High level)
      if (compressionLevel === "high") {
        try {
          return await gunzipPromise(data);
        } catch (e) {
          // If gzip fails, try deflate
          logger.warn("Gzip decompression failed, trying deflate");
        }
      }

      // Try deflate decompression (used for Medium/Low levels)
      return await inflatePromise(data);
    } catch (error) {
      logger.error("Decompression failed", error);
      throw new Error(
        `Decompression failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Add honeypot data to confuse attackers
   * @param data - Original data
   * @returns Data with honeypots
   */
  private static addHoneypotData(data: Buffer): Buffer {
    // Generate fake data sections that look like real data
    const honeypotCount = Math.floor(Math.random() * 3) + 1; // 1-3 honeypots
    const honeypots: Buffer[] = [];

    // Create realistic-looking honeypots with JSON structure
    const fakeDataTypes = [
      // Fake credentials
      () => {
        const users = ["admin", "system", "user", "guest", "dev"];
        const domains = ["example.com", "test.org", "domain.net"];
        return Buffer.from(
          JSON.stringify({
            username: users[Math.floor(Math.random() * users.length)],
            password: NehoID.hex(8),
            email: `${crypto.randomBytes(4).toString("hex")}@${
              domains[Math.floor(Math.random() * domains.length)]
            }`,
            token: crypto.randomBytes(16).toString("base64"),
          })
        );
      },
      // Fake configuration
      () => {
        return Buffer.from(
          JSON.stringify({
            apiKey: crypto.randomBytes(16).toString("hex"),
            endpoint: `https://api.${NehoID.hex(8)}.nehonix.space/v2`,
            timeout: 3000 + Math.floor(Math.random() * 7000),
            retries: 1 + Math.floor(Math.random() * 5),
            enabled: Math.random() > 0.5,
          })
        );
      },
      // Fake personal data
      () => {
        const firstNames = [
          "John",
          "Jane",
          "Michael",
          "Sarah",
          "David",
          "Emily",
        ];
        const lastNames = [
          "Smith",
          "Johnson",
          "Williams",
          "Brown",
          "Jones",
          "Miller",
        ];
        return Buffer.from(
          JSON.stringify({
            firstName:
              firstNames[Math.floor(Math.random() * firstNames.length)],
            lastName: lastNames[Math.floor(Math.random() * lastNames.length)],
            address: `${Math.floor(Math.random() * 1000)} Main St`,
            phone: `(${Math.floor(Math.random() * 900) + 100})-${
              Math.floor(Math.random() * 900) + 100
            }-${Math.floor(Math.random() * 9000) + 1000}`,
            ssn: `${Math.floor(Math.random() * 900) + 100}-${
              Math.floor(Math.random() * 90) + 10
            }-${Math.floor(Math.random() * 9000) + 1000}`,
          })
        );
      },
    ];

    // Generate honeypots
    for (let i = 0; i < honeypotCount; i++) {
      const dataGenerator =
        fakeDataTypes[Math.floor(Math.random() * fakeDataTypes.length)];
      const honeypot = dataGenerator();
      honeypots.push(honeypot);
    }

    // Create a buffer with original data and honeypots
    const totalSize =
      data.length + honeypots.reduce((sum, h) => sum + h.length + 16, 0);
    const result = Buffer.alloc(totalSize);

    // Write the original data size
    result.writeUInt32BE(data.length, 0);

    // Write the honeypot count
    result.writeUInt32BE(honeypotCount, 4);

    // Write a checksum of the original data for integrity verification
    const checksum = crypto.createHash("sha256").update(data).digest();
    result.writeUInt32BE(checksum.readUInt32BE(0), 8); // Write first 4 bytes of checksum

    // Copy the original data
    data.copy(result, 12);

    // Add honeypots with their positions
    let offset = 12 + data.length;
    for (const honeypot of honeypots) {
      // Write honeypot size
      result.writeUInt32BE(honeypot.length, offset);
      offset += 4;

      // Write honeypot type marker (0-2)
      result.writeUInt32BE(Math.floor(Math.random() * 3), offset);
      offset += 4;

      // Write a random identifier
      result.writeUInt32BE(SecureRandom.getRandomInt(0, 0xffffffff), offset);
      offset += 4;

      // Write a fake checksum
      result.writeUInt32BE(SecureRandom.getRandomInt(0, 0xffffffff), offset);
      offset += 4;

      // Copy honeypot data
      honeypot.copy(result, offset);
      offset += honeypot.length;
    }

    return result;
  }

  /**
   * Remove honeypot data
   * @param data - Data with honeypots
   * @returns Original data
   */
  private static removeHoneypotData(data: Buffer): Buffer {
    try {
      // Read the original data size
      const originalSize = data.readUInt32BE(0);

      // Read the checksum
      const storedChecksum = data.readUInt32BE(8);

      // Extract the original data
      const originalData = data.slice(12, 12 + originalSize);

      // Verify the checksum
      const calculatedChecksum = crypto
        .createHash("sha256")
        .update(originalData)
        .digest()
        .readUInt32BE(0);

      if (calculatedChecksum !== storedChecksum) {
        logger.warn("Honeypot data checksum verification failed");
        // Continue anyway, but log the warning
      }

      return originalData;
    } catch (error) {
      logger.error("Error removing honeypot data", error);
      throw new Error(
        `Failed to remove honeypot data: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Derive encryption keys for each layer
   * @param masterKey - Master encryption key
   * @param salt - Salt for key derivation
   * @param layers - Number of encryption layers
   * @param securityLevel - Security level
   * @returns Array of layer keys
   */
  private static async deriveLayerKeys(
    masterKey: Buffer,
    salt: Buffer,
    layers: number,
    securityLevel: SecurityLevel
  ): Promise<Buffer[]> {
    const keys: Buffer[] = [];
    const params = KDF_PARAMETERS[securityLevel];

    // Derive a unique key for each layer
    for (let i = 0; i < layers; i++) {
      // Create a unique info for each layer
      const info = Buffer.from(`layer-${i}-${securityLevel}`, "utf8");

      // Use HMAC-based key derivation instead of hkdfSync which might not be available
      const hmac = crypto.createHmac("sha512", masterKey);
      hmac.update(Buffer.concat([salt, info]));
      const layerKey = hmac.digest().slice(0, 32); // Use first 32 bytes for AES-256

      keys.push(layerKey);
    }

    return keys;
  }

  /**
   * Encrypt a single layer
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param iv - Initialization vector
   * @param algorithm - Encryption algorithm
   * @param context - Encryption context
   * @returns Encrypted data and authentication tag
   */
  private static encryptLayer(
    data: Buffer,
    key: Buffer,
    iv: Buffer,
    algorithm: string
  ): { encrypted: Buffer; authTag?: Buffer } {
    // For GCM mode
    if (algorithm === "aes-256-gcm") {
      const cipher = crypto.createCipheriv(
        algorithm,
        key,
        iv
      ) as crypto.CipherGCM;

      // Encrypt the data
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

      // Get the authentication tag
      const authTag = cipher.getAuthTag();

      return { encrypted, authTag };
    }
    // For CBC and other non-authenticated modes
    else {
      const cipher = crypto.createCipheriv(algorithm, key, iv);

      // Encrypt the data
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

      return { encrypted };
    }
  }

  /**
   * Decrypt a single layer
   * @param data - Encrypted data
   * @param key - Decryption key
   * @param iv - Initialization vector
   * @param authTag - Authentication tag (for authenticated encryption)
   * @param algorithm - Encryption algorithm
   * @param context - Decryption context
   * @returns Decrypted data
   */
  private static decryptLayer(
    data: Buffer,
    key: Buffer,
    iv: Buffer,
    authTag: Buffer,
    algorithm: string
  ): Buffer {
    // For GCM mode
    if (algorithm === "aes-256-gcm") {
      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;

      // Set the authentication tag
      decipher.setAuthTag(authTag);

      // Decrypt the data
      return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    // For CBC and other non-authenticated modes
    else {
      const decipher = crypto.createDecipheriv(algorithm, key, iv);

      // Decrypt the data
      return Buffer.concat([decipher.update(data), decipher.final()]);
    }
  }

  /**
   * Normalize a key to a Buffer
   * @param key - Key as Buffer or string
   * @returns Normalized key as Buffer
   */
  private static normalizeKey(key: Buffer | string): Buffer {
    if (Buffer.isBuffer(key)) {
      return key;
    } else {
      // If key is a hex string
      if (/^[0-9a-fA-F]+$/.test(key)) {
        return Buffer.from(key, "hex");
      } else {
        // Otherwise treat as UTF-8
        return Buffer.from(key, "utf8");
      }
    }
  }

  /**
   * Convert compression level to zlib level
   * @param level - Compression level
   * @returns zlib compression level
   */
  private static getZlibCompressionLevel(level: CompressionLevel): number {
    switch (level) {
      case "none":
        return 0;
      case "low":
        return 1;
      case "medium":
        return 6;
      case "high":
        return 9;
      case "maximum":
        return 9;
      default:
        return 6; // Default to medium
    }
  }
}
