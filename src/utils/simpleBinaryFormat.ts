/**
 * Simple Binary Format
 * A simplified version of the binary format that doesn't use RSA
 * This is more compatible with different platforms
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { logger } from "./logger";

// Magic bytes to identify the file format
const MAGIC_BYTES = Buffer.from("NHXSBIN", "utf8");

/**
 * Simple Binary Format class
 * Provides a simplified binary format for encryption/decryption
 */
export class SimpleBinaryFormat {
  /**
   * Encrypt data and save to file
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param outputPath - Output file path
   * @param options - Encryption options
   * @returns Promise resolving to encryption result
   */
  public static async encrypt(
    data: any,
    key: Buffer | string,
    outputPath: string,
    options: {
      compressionLevel?: number;
      addRandomPadding?: boolean;
    } = {}
  ): Promise<{
    filepath: string;
    size: { original: number; encrypted: number };
  }> {
    // Convert key to Buffer if it's a string
    const keyBuffer = typeof key === "string" ? Buffer.from(key, "hex") : key;

    // Convert data to JSON string and then to Buffer
    const jsonData = JSON.stringify(data);
    const dataBuffer = Buffer.from(jsonData, "utf8");

    // Generate IV
    const iv = crypto.randomBytes(16);

    // Encrypt data
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuffer, iv);
    const encrypted = Buffer.concat([
      cipher.update(dataBuffer),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Create metadata
    const metadata = {
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: "aes-256-gcm",
      timestamp: Date.now(),
      format: "simple-binary",
    };

    // Convert metadata to Buffer
    const metadataBuffer = Buffer.from(JSON.stringify(metadata), "utf8");

    // Create header with magic bytes and metadata length
    const metadataLength = Buffer.alloc(4);
    metadataLength.writeUInt32BE(metadataBuffer.length, 0);

    // Combine all parts
    const fileBuffer = Buffer.concat([
      MAGIC_BYTES,
      metadataLength,
      metadataBuffer,
      encrypted,
    ]);

    // Create output directory if it doesn't exist
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Write to file
    fs.writeFileSync(outputPath, fileBuffer);

    return {
      filepath: outputPath,
      size: {
        original: dataBuffer.length,
        encrypted: fileBuffer.length,
      },
    };
  }

  /**
   * Decrypt data from file
   * @param filePath - Path to encrypted file
   * @param key - Decryption key
   * @returns Promise resolving to decrypted data
   */
  public static async decrypt(
    filePath: string,
    key: Buffer | string
  ): Promise<any> {
    // Convert key to Buffer if it's a string
    const keyBuffer = typeof key === "string" ? Buffer.from(key, "hex") : key;

    // Read file
    const fileBuffer = fs.readFileSync(filePath);

    // Verify magic bytes
    const magicBytes = fileBuffer.subarray(0, MAGIC_BYTES.length);
    if (!magicBytes.equals(MAGIC_BYTES)) {
      throw new Error("Invalid file format or corrupted file");
    }

    // Extract metadata
    const metadataLengthBuffer = fileBuffer.subarray(
      MAGIC_BYTES.length,
      MAGIC_BYTES.length + 4
    );
    const metadataLength = metadataLengthBuffer.readUInt32BE(0);

    const metadataBuffer = fileBuffer.subarray(
      MAGIC_BYTES.length + 4,
      MAGIC_BYTES.length + 4 + metadataLength
    );

    const metadata = JSON.parse(metadataBuffer.toString("utf8"));

    // Extract encrypted data
    const encryptedData = fileBuffer.subarray(
      MAGIC_BYTES.length + 4 + metadataLength
    );

    // Decrypt data
    const iv = Buffer.from(metadata.iv, "base64");
    const authTag = Buffer.from(metadata.authTag, "base64");

    const decipher = crypto.createDecipheriv(metadata.algorithm, keyBuffer, iv);

    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);

    // Parse JSON data
    return JSON.parse(decrypted.toString("utf8"));
  }
}
