/**
 * Demo script for NEHONIX FileGuard
 */

import * as crypto from "crypto";
import {
  FileGuardManager,
  SecurityLevel,
  CompressionLevel,
  logger,
  ProgressTracker,
  OperationType,
  createPersistentRSAFGM,
  encryptOrDecryptNXS,
} from "./index";

// Set log level to debug for detailed output
logger.setLogLevel("debug");

/**
 * Run the demo
 */
async function runDemo() {
  console.log("\n🔒 NEHONIX FileGuard Demo 🔒\n");

  
}

// Run the demo
runDemo().catch((error) => {
  console.error("Demo failed:", error);
});
