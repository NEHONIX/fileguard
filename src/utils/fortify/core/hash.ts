/**
 * Hash utilities for Fortify security library
 */

import * as crypto from "crypto";
import { SecurityLevel } from "../../fortify/types";
import { DEFAULT_HASH_ALGORITHMS } from "./utils/constants";
import { statsTracker } from "./utils/statsTracker";
import { bufferToHex } from "./utils/encoding";

/**
 * Hash class for cryptographic hash functions
 */
export class Hash {
  /**
   * Compute a secure hash with additional security features
   * @param data - Data to hash
   * @param options - Hash options
   * @returns Secure hash as a hex string
   */
  public static secureHash(
    data: string | Buffer | Uint8Array,
    options: {
      algorithm?: string;
      iterations?: number;
      salt?: string | Buffer | Uint8Array;
      pepper?: string;
      outputFormat?: 'hex' | 'base64' | 'buffer';
    } = {}
  ): string | Buffer {
    const {
      algorithm = 'sha256',
      iterations = 1,
      salt,
      pepper,
      outputFormat = 'hex'
    } = options;
    
    const operationId = statsTracker.startOperation('hash_computation');
    
    try {
      // Convert data to buffer
      let dataBuffer: Buffer;
      if (typeof data === 'string') {
        dataBuffer = Buffer.from(data, 'utf8');
      } else if (data instanceof Buffer) {
        dataBuffer = data;
      } else {
        dataBuffer = Buffer.from(data);
      }
      
      // Apply pepper if provided
      if (pepper) {
        dataBuffer = Buffer.concat([
          dataBuffer,
          Buffer.from(pepper, 'utf8')
        ]);
      }
      
      // Apply salt if provided
      let saltBuffer: Buffer | undefined;
      if (salt) {
        if (typeof salt === 'string') {
          saltBuffer = Buffer.from(salt, 'utf8');
        } else if (salt instanceof Buffer) {
          saltBuffer = salt;
        } else {
          // Convert Uint8Array to Buffer
          saltBuffer = Buffer.from(salt.buffer, salt.byteOffset, salt.byteLength);
        }
      }
      
      // Perform iterative hashing
      let hash = dataBuffer;
      for (let i = 0; i < iterations; i++) {
        const hmac = saltBuffer 
          ? crypto.createHmac(algorithm, saltBuffer)
          : crypto.createHash(algorithm);
          
        hmac.update(hash);
        hash = hmac.digest();
      }
      
      // Format output
      let result: string | Buffer;
      if (outputFormat === 'buffer') {
        result = hash;
      } else if (outputFormat === 'base64') {
        result = hash.toString('base64');
      } else {
        result = bufferToHex(hash);
      }
      
      statsTracker.completeOperation(operationId, {
        algorithm,
        iterations,
        hasSalt: !!salt,
        hasPepper: !!pepper
      });
      
      return result;
    } catch (error: any) {
      statsTracker.failOperation(operationId, error?.message || 'Unknown error');
      throw error;
    }
  }
  /**
   * Get the default hash algorithm for a security level
   * @param securityLevel - Security level
   * @returns Hash algorithm
   */
  public static getDefaultAlgorithm(securityLevel: SecurityLevel): string {
    return DEFAULT_HASH_ALGORITHMS[securityLevel] || "sha256";
  }

  /**
   * Compute a hash
   * @param data - Data to hash
   * @param algorithm - Hash algorithm
   * @returns Hash as a hex string
   */
  public static compute(
    data: string | Buffer | Uint8Array,
    algorithm: string = "sha256"
  ): string {
    const operationId = statsTracker.startOperation("hash");

    try {
      // Convert data to buffer if needed
      const buffer =
        Buffer.isBuffer(data) || data instanceof Uint8Array
          ? Buffer.from(data)
          : Buffer.from(data, "utf8");

      // Compute hash
      const hash = crypto.createHash(algorithm).update(buffer).digest();

      // Complete operation
      statsTracker.completeOperation(operationId, {
        success: true
      });

      return bufferToHex(hash);
    } catch (error) {
      // Handle error
      statsTracker.failOperation(operationId,
        error instanceof Error ? error.message : String(error)
      );

      throw error;
    }
  }

  /**
   * Compute an HMAC
   * @param data - Data to hash
   * @param key - HMAC key
   * @param algorithm - Hash algorithm
   * @returns HMAC as a hex string
   */
  public static hmac(
    data: string | Buffer | Uint8Array,
    key: string | Buffer | Uint8Array,
    algorithm: string = "sha256"
  ): string {
    const operationId = statsTracker.startOperation("hmac");

    try {
      // Convert data to buffer if needed
      const dataBuffer =
        Buffer.isBuffer(data) || data instanceof Uint8Array
          ? Buffer.from(data)
          : Buffer.from(data, "utf8");

      // Convert key to buffer if needed
      const keyBuffer =
        Buffer.isBuffer(key) || key instanceof Uint8Array
          ? Buffer.from(key)
          : Buffer.from(key, "utf8");

      // Compute HMAC
      const hmac = crypto
        .createHmac(algorithm, keyBuffer)
        .update(dataBuffer)
        .digest();

      // Complete operation
      statsTracker.completeOperation(operationId, {
        success: true
      });

      return bufferToHex(hmac);
    } catch (error) {
      // Handle error
      statsTracker.failOperation(operationId,
        error instanceof Error ? error.message : String(error)
      );

      throw error;
    }
  }

  /**
   * Compute a keyed hash (HKDF)
   * @param ikm - Input key material
   * @param salt - Salt
   * @param info - Context and application specific information
   * @param length - Output key length
   * @param algorithm - Hash algorithm
   * @returns Derived key as a hex string
   */
  public static hkdf(
    ikm: string | Buffer | Uint8Array,
    salt: string | Buffer | Uint8Array,
    info: string | Buffer | Uint8Array,
    length: number,
    algorithm: string = "sha256"
  ): string {
    const operationId = statsTracker.startOperation("hkdf");

    try {
      // Convert inputs to buffers if needed
      const ikmBuffer =
        Buffer.isBuffer(ikm) || ikm instanceof Uint8Array
          ? Buffer.from(ikm)
          : Buffer.from(ikm, "utf8");

      const saltBuffer =
        Buffer.isBuffer(salt) || salt instanceof Uint8Array
          ? Buffer.from(salt)
          : Buffer.from(salt, "utf8");

      const infoBuffer =
        Buffer.isBuffer(info) || info instanceof Uint8Array
          ? Buffer.from(info)
          : Buffer.from(info, "utf8");

      // Extract phase
      const prk = crypto
        .createHmac(algorithm, saltBuffer)
        .update(ikmBuffer)
        .digest();

      // Expand phase
      let result = Buffer.alloc(0);
      let t = Buffer.alloc(0);
      let i = 0;

      while (result.length < length) {
        i++;
        t = crypto
          .createHmac(algorithm, prk)
          .update(Buffer.concat([t, infoBuffer, Buffer.from([i])]))
          .digest();

        result = Buffer.concat([result, t]);
      }

      // Complete operation
      statsTracker.completeOperation(operationId, {
        success: true
      });

      return bufferToHex(result.slice(0, length));
    } catch (error) {
      // Handle error
      statsTracker.failOperation(operationId,
        error instanceof Error ? error.message : String(error)
      );

      throw error;
    }
  }
}
