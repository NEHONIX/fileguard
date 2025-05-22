/**
 * Simple Binary Format for NEHONIX FileGuard
 * 
 * Implements a binary encryption format that makes data
 * completely unreadable by humans or other systems.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { logger } from "../utils/logger";

// Magic bytes for file identification (hidden in binary format)
const MAGIC_BYTES = Buffer.from([0x4E, 0x58, 0x53, 0x42, 0x49, 0x4E]); // "NXSBIN"

/**
 * Simple binary format implementation
 */
export class SimpleBinaryFormat {
  /**
   * Encrypt data to a binary format
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param outputPath - Output file path
   * @returns Promise resolving to true if successful
   */
  static async encrypt(
    data: any,
    key: Buffer,
    outputPath: string
  ): Promise<boolean> {
    try {
      // Convert data to string if it's not already
      const dataString = typeof data === "string" ? data : JSON.stringify(data);
      
      // Generate secure parameters
      const iv = crypto.randomBytes(16);
      const salt = crypto.randomBytes(16);
      
      // Create header with minimal information (will be encrypted)
      const header = {
        timestamp: Date.now(),
        dataType: typeof data,
        version: 1
      };
      
      // Convert header to buffer
      const headerBuffer = Buffer.from(JSON.stringify(header));
      
      // Create a buffer for the entire file content
      const fileContent = Buffer.concat([
        headerBuffer,
        Buffer.from(dataString)
      ]);
      
      // Encrypt the entire file content (header + data)
      const encryptedContent = this.encryptContent(fileContent, key, iv, salt);
      
      // Create the final file structure
      // [Magic Bytes (6)] [IV (16)] [Salt (16)] [Encrypted Size (4)] [Encrypted Content]
      const fileSize = 6 + 16 + 16 + 4 + encryptedContent.length;
      const fileBuffer = Buffer.alloc(fileSize);
      
      let offset = 0;
      
      // Write magic bytes
      MAGIC_BYTES.copy(fileBuffer, offset);
      offset += MAGIC_BYTES.length;
      
      // Write IV
      iv.copy(fileBuffer, offset);
      offset += iv.length;
      
      // Write Salt
      salt.copy(fileBuffer, offset);
      offset += salt.length;
      
      // Write encrypted content size
      fileBuffer.writeUInt32BE(encryptedContent.length, offset);
      offset += 4;
      
      // Write encrypted content
      encryptedContent.copy(fileBuffer, offset);
      
      // Create directory if it doesn't exist
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      // Write to file
      fs.writeFileSync(outputPath, fileBuffer);
      
      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Encryption failed: ${errorMessage}`, error);
      return false;
    }
  }
  
  /**
   * Decrypt data from a binary format
   * @param filePath - Path to encrypted file
   * @param key - Decryption key
   * @returns Decrypted data
   */
  static async decrypt(
    filePath: string,
    key: Buffer
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
      
      // Decrypt the content
      const decryptedContent = this.decryptContent(encryptedContent, key, iv, salt);
      
      // Split header and data
      const headerEndIndex = decryptedContent.indexOf("}") + 1;
      const headerJson = decryptedContent.toString("utf8", 0, headerEndIndex);
      const header = JSON.parse(headerJson);
      
      // Extract data
      const dataBuffer = Buffer.from(
        decryptedContent.buffer,
        decryptedContent.byteOffset + headerJson.length,
        decryptedContent.length - headerJson.length
      );
      
      // Parse the data based on the header's dataType
      if (header.dataType === "object") {
        return JSON.parse(dataBuffer.toString("utf8"));
      } else {
        return dataBuffer.toString("utf8");
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Decryption failed: ${errorMessage}`, error);
      throw error;
    }
  }
  
  /**
   * Encrypt content with AES-256-GCM
   * @param content - Content to encrypt
   * @param key - Encryption key
   * @param iv - Initialization vector
   * @param salt - Salt for key derivation
   * @returns Encrypted content
   */
  private static encryptContent(
    content: Buffer,
    key: Buffer,
    iv: Buffer,
    salt: Buffer
  ): Buffer {
    // Derive encryption key from master key and salt
    const derivedKey = crypto.pbkdf2Sync(
      key,
      salt,
      10000,
      32,
      "sha512"
    );
    
    // Create cipher
    const cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv);
    
    // Add authentication data
    const aad = Buffer.from("simple-binary-format");
    (cipher as any).setAAD(aad);
    
    // Encrypt data
    const encrypted = Buffer.concat([
      cipher.update(content),
      cipher.final()
    ]);
    
    // Get auth tag
    const authTag = (cipher as any).getAuthTag();
    
    // Combine auth tag and encrypted data
    return Buffer.concat([authTag, encrypted]);
  }
  
  /**
   * Decrypt content with AES-256-GCM
   * @param content - Encrypted content
   * @param key - Decryption key
   * @param iv - Initialization vector
   * @param salt - Salt for key derivation
   * @returns Decrypted content
   */
  private static decryptContent(
    content: Buffer,
    key: Buffer,
    iv: Buffer,
    salt: Buffer
  ): Buffer {
    // Derive decryption key from master key and salt
    const derivedKey = crypto.pbkdf2Sync(
      key,
      salt,
      10000,
      32,
      "sha512"
    );
    
    // Extract auth tag (first 16 bytes)
    const authTag = content.subarray(0, 16);
    const encryptedData = content.subarray(16);
    
    // Create decipher
    const decipher = crypto.createDecipheriv("aes-256-gcm", derivedKey, iv);
    
    // Set auth tag and AAD
    (decipher as any).setAuthTag(authTag);
    (decipher as any).setAAD(Buffer.from("simple-binary-format"));
    
    // Decrypt data
    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
  }
}
