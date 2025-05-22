/**
 * Secure memory utilities for NEHONIX FileGuard
 * Provides functions for secure memory handling
 */

import { logger } from './logger';

/**
 * Securely wipe a buffer by overwriting it multiple times
 * @param buffer - Buffer to wipe
 * @param passes - Number of passes (default: 3)
 */
export function secureWipe(buffer: Buffer, passes: number = 3): void {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError('Input must be a Buffer');
  }
  
  // Multiple pass secure wiping
  for (let pass = 0; pass < passes; pass++) {
    // Different patterns for each pass
    const pattern = pass === 0 
      ? 0x00 // First pass: all zeros
      : pass === 1 
        ? 0xFF // Second pass: all ones
        : Math.floor(Math.random() * 256); // Third+ pass: random
    
    // Fill the buffer with the pattern
    buffer.fill(pattern);
  }
  
  logger.debug(`Securely wiped buffer (${buffer.length} bytes, ${passes} passes)`);
}

/**
 * Create a secure buffer that auto-zeros when destroyed
 */
export class SecureBuffer {
  private buffer: Buffer;
  private isDestroyed: boolean = false;
  
  /**
   * Create a new secure buffer
   * @param size - Size of the buffer in bytes
   */
  constructor(size: number) {
    this.buffer = Buffer.alloc(size, 0);
    
    // Register cleanup on garbage collection (if supported)
    if (typeof globalThis !== 'undefined' && 
        'FinalizationRegistry' in globalThis && 
        typeof (globalThis as any).FinalizationRegistry === 'function') {
      const FinalizationRegistry = (globalThis as any).FinalizationRegistry;
      const registry = new FinalizationRegistry((heldValue: Buffer) => {
        secureWipe(heldValue);
      });
      
      registry.register(this, this.buffer, this);
    }
  }
  
  /**
   * Get the underlying buffer
   * @returns The buffer
   * @throws Error if the buffer has been destroyed
   */
  public getBuffer(): Buffer {
    if (this.isDestroyed) {
      throw new Error('Buffer has been destroyed');
    }
    
    return this.buffer;
  }
  
  /**
   * Destroy the buffer by securely wiping it
   */
  public destroy(): void {
    if (!this.isDestroyed) {
      secureWipe(this.buffer);
      this.isDestroyed = true;
      logger.debug('Secure buffer destroyed');
    }
  }
}

/**
 * Create a secure string that can be explicitly cleared
 */
export class SecureString {
  private value: string | null;
  
  /**
   * Create a new secure string
   * @param value - String value
   */
  constructor(value: string) {
    this.value = value;
  }
  
  /**
   * Get the string value
   * @returns The string value
   * @throws Error if the string has been cleared
   */
  public getValue(): string {
    if (this.value === null) {
      throw new Error('Secure string has been cleared');
    }
    
    return this.value;
  }
  
  /**
   * Clear the string by setting it to null
   */
  public clear(): void {
    this.value = null;
    
    // Force garbage collection if possible
    if (typeof global.gc === 'function') {
      global.gc();
    }
    
    logger.debug('Secure string cleared');
  }
}

/**
 * Constant-time comparison to prevent timing attacks
 * @param a - First buffer
 * @param b - Second buffer
 * @returns Whether the buffers are equal
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Inputs must be Buffers');
  }
  
  // If lengths differ, return false but still do the comparison
  // to prevent timing attacks based on length
  const result = a.length === b.length ? 1 : 0;
  
  // XOR each byte, if any byte differs, the result will be non-zero
  let diff = 0;
  
  // Use the minimum length to avoid out-of-bounds access
  const len = Math.min(a.length, b.length);
  
  for (let i = 0; i < len; i++) {
    // Use bitwise XOR to compare bytes
    diff |= a[i] ^ b[i];
  }
  
  // If any byte differs, diff will be non-zero
  // Use bitwise operations to convert to 0 or 1
  return (result & (diff === 0 ? 1 : 0)) === 1;
}
