/**
 * Test script for Fortify utilities
 */

import { HashAlgorithm, FortifyJS as fty } from "fortify2-js";
import { NehoID } from "nehoid";

// Test hash functions
console.log("\nTesting hash functions...");
const data = "Hello, world!";
const hash = fty.secureHash(
  data,
//   "1177e8b33a1ff2e51f65a5827280e1a3229efac2a48d06e196f54c0c3d7f453f",
  {algorithm: "sha256"}
);
console.log(`SHA-256 hash of "${data}": ${hash}`);
