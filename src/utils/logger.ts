/**
 * Logger utility for NEHONIX FileGuard
 * Provides colored logging with different log levels
 */

import { LogLevel } from '../types';

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  brightGreen: '\x1b[92m'
};

// Emoji indicators for different log types
const emoji = {
  info: '🟢',
  warn: '🟡',
  error: '🔴',
  debug: '🟣',
  success: '✅',
  fileOp: '📄'
};

/**
 * Logger class for NEHONIX FileGuard
 */
class Logger {
  private logLevel: LogLevel = 'info';

  /**
   * Set the log level
   * @param level - Log level to set
   */
  public setLogLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  /**
   * Get the current log level
   * @returns Current log level
   */
  public getLogLevel(): LogLevel {
    return this.logLevel;
  }

  /**
   * Log an informational message
   * @param message - Message to log
   * @param data - Optional data to include
   */
  public info(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      this.log(emoji.info, colors.green, 'INFO', message, data);
    }
  }

  /**
   * Log a warning message
   * @param message - Message to log
   * @param data - Optional data to include
   */
  public warn(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      this.log(emoji.warn, colors.yellow, 'WARN', message, data);
    }
  }

  /**
   * Log an error message
   * @param message - Message to log
   * @param error - Optional error to include
   */
  public error(message: string, error?: any): void {
    if (this.shouldLog('error')) {
      this.log(emoji.error, colors.red, 'ERROR', message, error);
    }
  }

  /**
   * Log a debug message
   * @param message - Message to log
   * @param data - Optional data to include
   */
  public debug(message: string, data?: any): void {
    if (this.shouldLog('debug')) {
      this.log(emoji.debug, colors.magenta, 'DEBUG', message, data);
    }
  }

  /**
   * Log a success message
   * @param message - Message to log
   * @param data - Optional data to include
   */
  public success(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      this.log(emoji.success, colors.brightGreen, 'SUCCESS', message, data);
    }
  }

  /**
   * Log a file operation
   * @param operation - Operation type
   * @param filepath - File path
   * @param success - Whether the operation was successful
   * @param details - Optional details
   */
  public fileOperation(
    operation: string,
    filepath: string,
    success: boolean,
    details?: string
  ): void {
    if (this.shouldLog('info')) {
      const color = success ? colors.brightGreen : colors.red;
      const status = success ? 'SUCCESS' : 'FAILED';
      const message = `${operation.toUpperCase()} ${filepath} - ${status}`;
      
      this.log(emoji.fileOp, color, 'FILE', message, details ? { details } : undefined);
    }
  }

  /**
   * Check if a message should be logged based on the current log level
   * @param messageLevel - Level of the message
   * @returns Whether the message should be logged
   */
  private shouldLog(messageLevel: string): boolean {
    if (this.logLevel === 'none') return false;
    if (this.logLevel === 'error') return messageLevel === 'error';
    if (this.logLevel === 'info') return messageLevel !== 'debug';
    return true; // 'debug' level logs everything
  }

  /**
   * Format and log a message
   * @param icon - Emoji icon
   * @param color - ANSI color code
   * @param level - Log level
   * @param message - Message to log
   * @param data - Optional data to include
   */
  private log(
    icon: string,
    color: string,
    level: string,
    message: string,
    data?: any
  ): void {
    const timestamp = new Date().toISOString();
    const formattedLevel = level.padEnd(7);
    
    console.log(
      `${color}${icon} [${timestamp}] ${formattedLevel} ${message}${colors.reset}`
    );
    
    if (data !== undefined) {
      if (data instanceof Error) {
        console.log(`${color}  ↳ ${data.message}${colors.reset}`);
        if (data.stack) {
          console.log(`${colors.magenta}  ↳ ${data.stack}${colors.reset}`);
        }
      } else if (typeof data === 'object') {
        console.log(`${colors.cyan}  ↳ ${JSON.stringify(data, null, 2)}${colors.reset}`);
      } else {
        console.log(`${colors.cyan}  ↳ ${data}${colors.reset}`);
      }
    }
  }
}

// Export a singleton instance
export const logger = new Logger();
