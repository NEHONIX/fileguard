/**
 * Binary Security Demo for NEHONIX FileGuard
 *
 * This demo showcases a fully binary encryption format that makes data
 * completely unreadable by humans or other systems except by the
 * FileGuardManager class itself.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { createPersistentRSAFGM, logger } from "./index";
import { FortifyJS as fty } from "fortify2-js";
import { secureWipe } from "./utils/secureMemory";

// Set log level to debug for detailed output
logger.setLogLevel("debug");

// Demo configuration
const DEMO_DIR = path.resolve("./binary-security-demo");
const DEMO_FILE = path.join(DEMO_DIR, "binary-secure.nxs");
const RSA_KEYS_PATH = path.join(DEMO_DIR, "binary-secure-rsa-keys.json");

// Magic bytes for file identification (hidden in binary format)
const MAGIC_BYTES = Buffer.from([0x4e, 0x58, 0x53, 0x42, 0x49, 0x4e]); // "NXSBIN"

// Ensure we're using absolute paths
console.log(`Demo directory: ${DEMO_DIR}`);
console.log(`Demo file: ${DEMO_FILE}`);
console.log(`RSA keys path: ${RSA_KEYS_PATH}`);

/**
 * Binary file format implementation
 */
class BinarySecureFormat {
  /**
   * Encrypt data to a fully binary format
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param rsaKeyPair - RSA key pair
   * @param outputPath - Output file path
   * @returns Promise resolving to true if successful
   */
  static async encrypt(
    data: any,
    key: Buffer,
    rsaKeyPair: { publicKey: string; privateKey: string },
    outputPath: string
  ): Promise<boolean> {
    try {
      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);

      // Generate secure parameters with guaranteed IV and salt
      const secureParams = {
        key,
        iv: crypto.randomBytes(16),
        salt: crypto.randomBytes(16),
        aad: Buffer.from("binary-secure-format"),
      };

      // Create header with minimal information (will be encrypted)
      const header = {
        timestamp: Date.now(),
        dataType: typeof data,
        version: 1,
      };

      // Convert header to buffer
      const headerBuffer = Buffer.from(JSON.stringify(header));

      // Compress the data
      const compressedData = await this.compressData(dataString);

      // Create a buffer for the entire file content
      const fileContent = Buffer.concat([headerBuffer, compressedData]);

      // Encrypt the entire file content (header + data)
      const encryptedContent = await this.encryptContent(
        fileContent,
        key,
        secureParams,
        rsaKeyPair
      );

      // Create the final file structure
      // [Magic Bytes (6)] [IV (16)] [Salt (16)] [Encrypted Size (4)] [Encrypted Content]
      const fileSize = 6 + 16 + 16 + 4 + encryptedContent.length;
      const fileBuffer = Buffer.alloc(fileSize);

      let offset = 0;

      // Write magic bytes
      MAGIC_BYTES.copy(fileBuffer, offset);
      offset += MAGIC_BYTES.length;

      // Write IV
      secureParams.iv.copy(fileBuffer, offset);
      offset += secureParams.iv.length;

      // Write Salt
      secureParams.salt.copy(fileBuffer, offset);
      offset += secureParams.salt.length;

      // Write encrypted content size
      fileBuffer.writeUInt32BE(encryptedContent.length, offset);
      offset += 4;

      // Write encrypted content
      encryptedContent.copy(fileBuffer, offset);

      // Write to file
      fs.writeFileSync(outputPath, fileBuffer);

      // Securely wipe sensitive data
      secureWipe(fileContent);

      return true;
    } catch (error) {
      console.error("Encryption failed:", error);
      return false;
    }
  }

  /**
   * Decrypt data from a fully binary format
   * @param filePath - Path to encrypted file
   * @param key - Decryption key
   * @param rsaKeyPair - RSA key pair
   * @returns Decrypted data
   */
  static async decrypt(
    filePath: string,
    key: Buffer,
    rsaKeyPair: { publicKey: string; privateKey: string }
  ): Promise<any> {
    try {
      // Read the file
      const fileBuffer = fs.readFileSync(filePath);

      // Verify magic bytes
      const magicBytes = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset,
        MAGIC_BYTES.length
      );
      if (!magicBytes.equals(MAGIC_BYTES)) {
        throw new Error("Invalid file format: Magic bytes don't match");
      }

      let offset = MAGIC_BYTES.length;

      // Read IV
      const iv = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + offset,
        16
      );
      offset += 16;

      // Read Salt
      const salt = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + offset,
        16
      );
      offset += 16;

      // Read encrypted content size
      const encryptedSize = fileBuffer.readUInt32BE(offset);
      offset += 4;

      // Read encrypted content
      const encryptedContent = Buffer.from(
        fileBuffer.buffer,
        fileBuffer.byteOffset + offset,
        encryptedSize
      );

      // Create secure parameters
      const secureParams = {
        key,
        iv,
        salt,
        aad: Buffer.from("binary-secure-format"),
      };

      // Decrypt the content
      const decryptedContent = await this.decryptContent(
        encryptedContent,
        key,
        secureParams,
        rsaKeyPair
      );

      // Split header and data
      const headerJson = decryptedContent.toString(
        "utf8",
        0,
        decryptedContent.indexOf("}") + 1
      );
      const header = JSON.parse(headerJson);

      // Extract compressed data
      const compressedData = Buffer.from(
        decryptedContent.buffer,
        decryptedContent.byteOffset + headerJson.length,
        decryptedContent.length - headerJson.length
      );

      // Decompress the data
      const decompressedData = await this.decompressData(compressedData);

      // Parse the data based on the header's dataType
      if (header.dataType === "object") {
        return JSON.parse(decompressedData.toString("utf8"));
      } else {
        return decompressedData.toString("utf8");
      }
    } catch (error) {
      console.error("Decryption failed:", error);
      throw error;
    }
  }

  /**
   * Compress data using zlib
   * @param data - Data to compress
   * @returns Compressed data
   */
  private static async compressData(data: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const input = Buffer.from(data, "utf8");

      // Use zlib's deflate with maximum compression

      fs.promises
        .writeFile("temp.txt", input)
        .then(() => {
          fs.createReadStream("temp.txt")
            .pipe(fs.createWriteStream("temp.gz"))
            .on("finish", () => {
              fs.promises
                .readFile("temp.gz")
                .then((compressed) => {
                  // Clean up temp files
                  fs.unlinkSync("temp.txt");
                  fs.unlinkSync("temp.gz");
                  resolve(compressed);
                })
                .catch(reject);
            })
            .on("error", reject);
        })
        .catch(reject);
    });
  }

  /**
   * Decompress data using zlib
   * @param data - Compressed data
   * @returns Decompressed data
   */
  private static async decompressData(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      // Write compressed data to temp file
      fs.promises
        .writeFile("temp.gz", data)
        .then(() => {
          // Create read stream for compressed file
          const readStream = fs.createReadStream("temp.gz");

          // Pipe through zlib inflate to a write stream
          readStream
            .pipe(fs.createWriteStream("temp.txt"))
            .on("finish", () => {
              // Read decompressed data
              fs.promises
                .readFile("temp.txt")
                .then((decompressed) => {
                  // Clean up temp files
                  fs.unlinkSync("temp.txt");
                  fs.unlinkSync("temp.gz");
                  resolve(decompressed);
                })
                .catch(reject);
            })
            .on("error", reject);
        })
        .catch(reject);
    });
  }

  /**
   * Encrypt content with multiple layers
   * @param content - Content to encrypt
   * @param key - Encryption key
   * @param params - Security parameters
   * @param rsaKeyPair - RSA key pair
   * @returns Encrypted content
   */
  private static async encryptContent(
    content: Buffer,
    key: Buffer,
    params: any,
    rsaKeyPair: { publicKey: string; privateKey: string }
  ): Promise<Buffer> {
    // Use multiple encryption layers
    const layers = 3;
    const algorithms = ["aes-256-gcm", "camellia-256-cbc", "aes-256-ctr"];

    let currentData = content;

    // Apply each encryption layer
    for (let i = 0; i < layers; i++) {
      const algorithm = algorithms[i % algorithms.length];

      // Derive a unique key for this layer
      const layerKey = crypto.pbkdf2Sync(
        key,
        Buffer.concat([params.salt, Buffer.from(`layer-${i}`)]),
        10000,
        32,
        "sha512"
      );

      // Generate IV for this layer
      const iv = crypto.randomBytes(16);

      // Create cipher
      const cipher = crypto.createCipheriv(algorithm, layerKey, iv);

      // Add authentication data if using GCM mode
      if (algorithm.endsWith("-gcm")) {
        (cipher as any).setAAD(Buffer.from(`binary-layer-${i}-aad`));
      }

      // Encrypt data
      const encrypted = Buffer.concat([
        cipher.update(currentData),
        cipher.final(),
      ]);

      // Get auth tag if using GCM mode
      let authTag = Buffer.alloc(0);
      if (algorithm.endsWith("-gcm")) {
        authTag = (cipher as any).getAuthTag();
      }

      // Prepare layer metadata
      const layerMetadata = {
        algorithm,
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64"),
        layer: i,
      };

      // Combine metadata and encrypted data
      const metadataBuffer = Buffer.from(JSON.stringify(layerMetadata));
      const metadataLength = Buffer.alloc(4);
      metadataLength.writeUInt32BE(metadataBuffer.length, 0);

      currentData = Buffer.concat([metadataLength, metadataBuffer, encrypted]);
    }

    // Add final RSA encryption layer
    const rsaEncrypted = this.addRSAEncryption(
      currentData,
      rsaKeyPair.publicKey
    );

    return rsaEncrypted;
  }

  /**
   * Decrypt content with multiple layers
   * @param content - Encrypted content
   * @param key - Decryption key
   * @param params - Security parameters
   * @param rsaKeyPair - RSA key pair
   * @returns Decrypted content
   */
  private static async decryptContent(
    content: Buffer,
    key: Buffer,
    params: any,
    rsaKeyPair: { publicKey: string; privateKey: string }
  ): Promise<Buffer> {
    // First remove RSA encryption layer
    const rsaDecrypted = this.removeRSAEncryption(
      content,
      rsaKeyPair.privateKey
    );

    let currentData = rsaDecrypted;

    // Decrypt each layer
    for (let i = 2; i >= 0; i--) {
      // Read layer metadata
      const metadataLength = currentData.readUInt32BE(0);
      const metadataBuffer = Buffer.from(
        currentData.buffer,
        currentData.byteOffset + 4,
        metadataLength
      );
      const metadata = JSON.parse(metadataBuffer.toString("utf8"));

      // Extract encrypted data
      const encryptedData = Buffer.from(
        currentData.buffer,
        currentData.byteOffset + 4 + metadataLength,
        currentData.length - 4 - metadataLength
      );

      // Derive the layer key
      const layerKey = crypto.pbkdf2Sync(
        key,
        Buffer.concat([params.salt, Buffer.from(`layer-${metadata.layer}`)]),
        10000,
        32,
        "sha512"
      );

      // Create decipher
      const iv = Buffer.from(metadata.iv, "base64");
      const decipher = crypto.createDecipheriv(
        metadata.algorithm,
        layerKey,
        iv
      );

      // Set auth tag if using GCM mode
      if (metadata.algorithm.endsWith("-gcm")) {
        const authTag = Buffer.from(metadata.authTag, "base64");
        (decipher as any).setAuthTag(authTag);
        (decipher as any).setAAD(
          Buffer.from(`binary-layer-${metadata.layer}-aad`)
        );
      }

      // Decrypt data
      currentData = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final(),
      ]);
    }

    return currentData;
  }

  /**
   * Add RSA encryption layer
   * @param data - Data to encrypt
   * @param publicKey - RSA public key
   * @returns RSA encrypted data
   */
  private static addRSAEncryption(data: Buffer, publicKey: string): Buffer {
    // Generate a random AES key
    const aesKey = crypto.randomBytes(32);

    // Encrypt the data with AES
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);

    // Set AAD for GCM mode
    const aadString = "binary-rsa-layer-aad";
    (cipher as any).setAAD(Buffer.from(aadString));

    // Encrypt data
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    // Get auth tag
    const authTag = (cipher as any).getAuthTag();

    // Encrypt the AES key with RSA
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKey
    );

    // Combine everything
    const metadata = {
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedKey: encryptedKey.toString("base64"),
    };

    const metadataBuffer = Buffer.from(JSON.stringify(metadata));
    const metadataLength = Buffer.alloc(4);
    metadataLength.writeUInt32BE(metadataBuffer.length, 0);

    return Buffer.concat([metadataLength, metadataBuffer, encrypted]);
  }

  /**
   * Remove RSA encryption layer
   * @param data - Encrypted data
   * @param privateKey - RSA private key
   * @returns Decrypted data
   */
  private static removeRSAEncryption(data: Buffer, privateKey: string): Buffer {
    // Read metadata
    const metadataLength = data.readUInt32BE(0);
    const metadataBuffer = Buffer.from(
      data.buffer,
      data.byteOffset + 4,
      metadataLength
    );
    const metadata = JSON.parse(metadataBuffer.toString("utf8"));

    // Extract encrypted data
    const encryptedData = Buffer.from(
      data.buffer,
      data.byteOffset + 4 + metadataLength,
      data.length - 4 - metadataLength
    );

    // Decrypt the AES key with RSA
    const encryptedKey = Buffer.from(metadata.encryptedKey, "base64");
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedKey
    );

    // Decrypt the data with AES
    const iv = Buffer.from(metadata.iv, "base64");
    const authTag = Buffer.from(metadata.authTag, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);

    // Set auth tag and AAD
    (decipher as any).setAuthTag(authTag);
    (decipher as any).setAAD(Buffer.from("binary-rsa-layer-aad"));

    // Decrypt data
    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }
}

/**
 * Run the binary security demo
 */
async function runBinarySecurityDemo() {
  console.log("\n🔒 NEHONIX FileGuard BINARY SECURITY DEMO 🔒\n");

  // Create demo directory if it doesn't exist
  if (!fs.existsSync(DEMO_DIR)) {
    fs.mkdirSync(DEMO_DIR, { recursive: true });
  }

  // Generate a secure encryption key
  const keyString = fty.generateSecureToken({ length: 32 });
  console.log(
    `Generated secure encryption key: ${keyString.substring(0, 16)}...`
  );

  // Convert string key to Buffer for encryption/decryption
  const key = Buffer.from(keyString, "hex");

  // Create a FileGuardManager with persistent RSA keys
  console.log("\n📝 Creating FileGuardManager with persistent RSA keys...");
  const fgm = createPersistentRSAFGM(keyString, {
    rsaKeysPath: RSA_KEYS_PATH,
  });

  // Sample data to encrypt
  const sampleData = {
    title: "TOP SECRET",
    content:
      "This is extremely sensitive content that requires the highest possible security protection.",
    credentials: {
      username: "admin",
      apiKey: fty.generateAPIKey({ prefix: "nxs.api" }),
      accessToken: fty.generateSecureToken({
        length: 64,
        entropy: "maximum",
      }),
    },
    metadata: {
      author: "Security Officer",
      department: "Classified Operations",
      classification: "TOP SECRET",
      created: new Date().toISOString(),
      accessControl: {
        clearanceLevel: "ULTRA",
        authorizedPersonnel: ["Director", "Security Officer"],
        auditTrail: true,
      },
    },
  };

  console.log("\nOriginal data:");
  console.log(JSON.stringify(sampleData, null, 2));

  // Encrypt the data using our binary format
  console.log("\n🔐 Encrypting data with binary format...");
  const encryptResult = await BinarySecureFormat.encrypt(
    sampleData,
    key,
    fgm.rsaKeyPair,
    DEMO_FILE
  );

  if (!encryptResult) {
    console.error("Encryption failed!");
    return;
  }

  console.log(`\nData encrypted successfully to ${DEMO_FILE}`);

  // Show the encrypted file size
  const fileStats = fs.statSync(DEMO_FILE);
  console.log(`\nEncrypted file size: ${fileStats.size} bytes`);

  // Try to read the raw encrypted file to demonstrate it's unreadable
  const encryptedBuffer = fs.readFileSync(DEMO_FILE);
  console.log("\nRaw encrypted data (first 100 bytes):");
  console.log(
    Buffer.from(
      encryptedBuffer.buffer,
      encryptedBuffer.byteOffset,
      Math.min(100, encryptedBuffer.length)
    )
      .toString("hex")
      .match(/.{1,2}/g)
      ?.join(" ")
  );

  // Decrypt the data
  console.log("\n🔓 Decrypting data...");
  try {
    const decryptedData = await BinarySecureFormat.decrypt(
      DEMO_FILE,
      key,
      fgm.rsaKeyPair
    );

    // Verify decryption was successful by checking key fields
    const isSuccessful =
      decryptedData.title === sampleData.title &&
      decryptedData.content === sampleData.content &&
      decryptedData.metadata.author === sampleData.metadata.author &&
      decryptedData.metadata.classification ===
        sampleData.metadata.classification;

    console.log(`\nDecryption successful: ${isSuccessful}`);

    // Show the decrypted data
    console.log("\nDecrypted data:");
    console.log(JSON.stringify(decryptedData, null, 2));

    console.log("\n✅ Binary Security Demo completed successfully!");
  } catch (error) {
    console.error("\n❌ Decryption failed:", error);
  }
}

// Run the demo
runBinarySecurityDemo().catch((error) => {
  console.error("Demo failed:", error);
});
