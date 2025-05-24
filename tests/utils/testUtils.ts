/**
 * Test utilities for NEHONIX FileGuard tests
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { RSAKeyPair } from "../../src/types";

// Test directory for temporary files
export const TEST_DIR = path.join(__dirname, "..", "output");

/**
 * Ensure test directory exists
 */
export function ensureTestDirectory(): void {
  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }
}

/**
 * Clean up test files
 */
export function cleanupTestFiles(): void {
  if (fs.existsSync(TEST_DIR)) {
    const files = fs.readdirSync(TEST_DIR);
    for (const file of files) {
      try {
        fs.unlinkSync(path.join(TEST_DIR, file));
      } catch (error) {
        console.error(`Error deleting file ${file}:`, error);
      }
    }
  }
}

/**
 * Generate a random encryption key
 * @returns Buffer containing the encryption key
 */
export function generateTestEncryptionKey(): Buffer {
  return Random.getRandomBytes(32);
}

/**
 * Generate an RSA key pair for testing
 * @returns RSA key pair with public and private keys
 */
export function generateTestRSAKeyPair(): RSAKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey };
}

/**
 * Generate test data with various data types and structures
 * @returns Test data object
 */
export function generateTestData(): any {
  return {
    title: "Test Document",
    timestamp: new Date().toISOString(),
    content:
      "This is a test document with some content for encryption testing.",
    numbers: [1, 2, 3, 4, 5],
    nested: {
      field1: "value1",
      field2: 123,
      field3: true,
      deepNested: {
        array: ["a", "b", "c"],
        date: new Date().toISOString(),
      },
    },
    boolean: true,
    nullValue: null,
    metadata: {
      author: "Test Author",
      tags: ["test", "encryption", "security"],
      version: "1.0.0",
    },
  };
}

/**
 * Generate a large test data object for performance testing
 * @param sizeInKB - Approximate size in KB
 * @returns Large test data object
 */
export function generateLargeTestData(sizeInKB: number = 100): any {
  // Generate a large string (approximately 1KB per 1000 chars)
  const generateLargeString = (size: number) => {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < size; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  return {
    title: "Large Test Document",
    timestamp: new Date().toISOString(),
    content: generateLargeString(sizeInKB * 1000), // Approx. sizeInKB in size
    metadata: {
      author: "Test Author",
      tags: ["test", "large", "performance"],
      version: "1.0.0",
    },
  };
}

/**
 * Verify that two objects are deeply equal
 * This is useful for comparing original and decrypted data
 * @param original - Original object
 * @param decrypted - Decrypted object
 * @returns True if objects are deeply equal
 */
export function verifyDataIntegrity(original: any, decrypted: any): boolean {
  // Convert to JSON and back to handle Date objects and other special types
  const normalizedOriginal = JSON.parse(JSON.stringify(original));
  const normalizedDecrypted = JSON.parse(JSON.stringify(decrypted));

  return (
    JSON.stringify(normalizedOriginal) === JSON.stringify(normalizedDecrypted)
  );
}

/**
 * Generate a unique test file path
 * @param prefix - Prefix for the filename
 * @param extension - File extension (default: .nxs)
 * @returns Path to the test file
 */
export function getTestFilePath(
  prefix: string = "test",
  extension: string = ".nxs"
): string {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  return path.join(TEST_DIR, `${prefix}-${timestamp}-${random}${extension}`);
}

/**
 * Measure execution time of a function
 * @param fn - Function to measure
 * @returns Result of the function and execution time in milliseconds
 */
export async function measureExecutionTime<T>(
  fn: () => Promise<T>
): Promise<{ result: T; executionTimeMs: number }> {
  const startTime = Date.now();
  const result = await fn();
  const endTime = Date.now();
  return {
    result,
    executionTimeMs: endTime - startTime,
  };
}
