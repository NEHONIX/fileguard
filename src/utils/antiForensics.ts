/**
 * Anti-forensics utilities for NEHONIX FileGuard
 * Provides functions to prevent forensic analysis
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import { logger } from './logger';
import { secureWipe } from './secureMemory';

/**
 * Anti-forensics techniques
 */
export class AntiForensics {
  /**
   * Securely delete a file by overwriting it multiple times
   * @param filepath - Path to the file
   * @param passes - Number of passes (default: 7)
   * @returns Promise resolving when the file is securely deleted
   */
  public static async secureDelete(
    filepath: string,
    passes: number = 7
  ): Promise<void> {
    try {
      // Check if file exists
      if (!fs.existsSync(filepath)) {
        throw new Error(`File not found: ${filepath}`);
      }
      
      // Get file size
      const stats = fs.statSync(filepath);
      const fileSize = stats.size;
      
      logger.debug(`Securely deleting file: ${filepath} (${fileSize} bytes, ${passes} passes)`);
      
      // Open file for writing
      const fd = fs.openSync(filepath, 'r+');
      
      // Create a buffer for overwriting
      const bufferSize = Math.min(fileSize, 1024 * 1024); // Max 1MB buffer
      const buffer = Buffer.alloc(bufferSize);
      
      // Perform multiple overwrite passes
      for (let pass = 0; pass < passes; pass++) {
        logger.debug(`Secure delete pass ${pass + 1}/${passes}`);
        
        // Different patterns for each pass
        let pattern: number;
        
        switch (pass % 7) {
          case 0: pattern = 0x00; break; // All zeros
          case 1: pattern = 0xFF; break; // All ones
          case 2: pattern = 0xAA; break; // 10101010
          case 3: pattern = 0x55; break; // 01010101
          case 4: pattern = 0xF0; break; // 11110000
          case 5: pattern = 0x0F; break; // 00001111
          case 6: pattern = Math.floor(Math.random() * 256); break; // Random
          default: pattern = 0x00;
        }
        
        // Fill buffer with pattern
        buffer.fill(pattern);
        
        // Write buffer to file repeatedly until the entire file is overwritten
        let bytesWritten = 0;
        
        while (bytesWritten < fileSize) {
          const toWrite = Math.min(buffer.length, fileSize - bytesWritten);
          fs.writeSync(fd, buffer, 0, toWrite, bytesWritten);
          bytesWritten += toWrite;
        }
        
        // Flush to disk
        fs.fsyncSync(fd);
      }
      
      // Close file
      fs.closeSync(fd);
      
      // Delete the file
      fs.unlinkSync(filepath);
      
      logger.debug(`File securely deleted: ${filepath}`);
    } catch (error) {
      logger.error(`Error securely deleting file: ${filepath}`, error);
      throw error;
    }
  }
  
  /**
   * Add decoy data to a file to confuse forensic analysis
   * @param buffer - Buffer to add decoys to
   * @param decoyCount - Number of decoys to add
   * @returns Buffer with decoys
   */
  public static addDecoys(buffer: Buffer, decoyCount: number = 5): Buffer {
    // Create a new buffer with space for decoys
    const decoySize = 1024; // 1KB per decoy
    const newBuffer = Buffer.alloc(buffer.length + decoyCount * decoySize);
    
    // Copy original data to a random position
    const originalPosition = crypto.randomInt(0, decoyCount) * decoySize;
    buffer.copy(newBuffer, originalPosition);
    
    // Add a marker to find the real data (encrypted)
    const marker = crypto.randomBytes(16);
    marker.copy(newBuffer, originalPosition - 16);
    
    // Fill the rest with random decoy data
    for (let i = 0; i < decoyCount; i++) {
      const position = i * decoySize;
      
      // Skip the position with real data
      if (position === originalPosition) continue;
      
      // Generate convincing decoy data
      const decoy = this.generateConvincingDecoy(decoySize);
      decoy.copy(newBuffer, position);
    }
    
    logger.debug(`Added ${decoyCount} decoys to data`);
    
    return newBuffer;
  }
  
  /**
   * Remove decoys from a buffer
   * @param buffer - Buffer with decoys
   * @param marker - Marker to find the real data
   * @returns Buffer without decoys
   */
  public static removeDecoys(buffer: Buffer, marker: Buffer): Buffer {
    // Find the marker position
    let markerPos = -1;
    
    for (let i = 0; i <= buffer.length - marker.length; i++) {
      let found = true;
      
      for (let j = 0; j < marker.length; j++) {
        if (buffer[i + j] !== marker[j]) {
          found = false;
          break;
        }
      }
      
      if (found) {
        markerPos = i;
        break;
      }
    }
    
    if (markerPos === -1) {
      throw new Error('Marker not found, cannot remove decoys');
    }
    
    // Extract the real data
    const dataPosition = markerPos + marker.length;
    const dataSize = buffer.length - dataPosition;
    const realData = Buffer.alloc(dataSize);
    
    buffer.copy(realData, 0, dataPosition);
    
    logger.debug('Removed decoys from data');
    
    return realData;
  }
  
  /**
   * Add misleading metadata to confuse forensic analysis
   * @param filepath - Path to the file
   */
  public static addMisleadingMetadata(filepath: string): void {
    try {
      // Set random timestamps
      const pastDate = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000);
      
      fs.utimesSync(filepath, pastDate, pastDate);
      
      logger.debug(`Added misleading metadata to file: ${filepath}`);
    } catch (error) {
      logger.error(`Error adding misleading metadata: ${filepath}`, error);
    }
  }
  
  /**
   * Generate convincing decoy data
   * @param size - Size of the decoy data
   * @returns Buffer with decoy data
   */
  private static generateConvincingDecoy(size: number): Buffer {
    const buffer = Buffer.alloc(size);
    
    // Fill with random data
    crypto.randomFillSync(buffer);
    
    // Add some structure to make it look like real data
    // Add a fake header
    const header = Buffer.from('FILE', 'ascii');
    header.copy(buffer, 0);
    
    // Add some fake metadata
    const metadata = Buffer.from(JSON.stringify({
      timestamp: new Date().toISOString(),
      type: 'document',
      version: '1.0',
      encrypted: true
    }));
    
    metadata.copy(buffer, 4);
    
    return buffer;
  }
}
