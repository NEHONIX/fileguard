/**
 * NEHONIX FileGuard (NXS)
 * An ultra-secure file management library with advanced encryption capabilities and integrated compression.
 */

export { ProgressTracker, OperationType } from "./utils/progress";

// Export main components
export { FileGuardManager } from "./core/FileGuardManager";
export { BinarySecureFormat } from "./core/BinarySecureFormat";
export { SimpleBinaryFormat } from "./core/SimpleBinaryFormat";
export { createPersistentRSAFGM } from "./utils/rsaSolution";
export { encryptOrDecryptNXS } from "./utils/encryptionUtils";
export { logger } from "./utils/logger";
export { UltraSecureEncryption } from "./utils/ultraSecureEncryption";

// Export Fortify core utilities
export { SecureRandom } from "./utils/fortify/core/random";
export { Hash } from "./utils/fortify/core/hash";
export { StatsTracker } from "./utils/fortify/core/utils/stats";
export {
  bufferToHex,
  hexToBuffer,
  bufferToBase64,
  base64ToBuffer,
} from "./utils/fortify/core/utils/encoding";

// Export types
export {
  EntropySource,
  SecurityLevelType,
  CryptoStats,
  LamportKeygenOptions,
  LamportKeyPair,
  LamportSignOptions,
  LamportSignature,
  KyberKeygenOptions,
  KyberKeyPair,
  KyberEncapsulateOptions,
  KyberEncapsulation,
  KyberDecapsulateOptions,
  KyberDecapsulation,
  Argon2Options,
  KDFResult,
} from "./utils/fortify/types";
export { SecurityLevel } from "./utils/fortify/types";
export * from "./types/index";
