/**
 * NEHONIX FileGuard (NXS)
 * An ultra-secure file management library with advanced encryption capabilities and integrated compression.
 */

export { ProgressTracker, OperationType } from "./utils/progress";

// Export main components
export { FileGuardManager } from "./core/FileGuardManager";
export { BinarySecureFormat } from "./core/BinarySecureFormat";
export { SimpleBinaryFormat } from "./utils/simpleBinaryFormat";
export { createPersistentRSAFGM } from "./utils/rsaSolution";
export { encryptOrDecryptNXS } from "./utils/encryptionUtils";
export { logger } from "./utils/logger";
export { UltraSecureEncryption } from "./utils/ultraSecureEncryption";

// Export simplified encryption utilities
export {
  encryptData,
  decryptData,
  generateEncryptionKey,
  generateRSAKeyPair,
  ensureDirectoryExists,
  // Also export the types
  EncryptionOptions,
  SimplifiedEncryptionResult,
} from "./utils/cryptUtils";

export * from "./types/index";
