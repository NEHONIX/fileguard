/**
 * Progress tracking utility for NEHONIX FileGuard
 * Provides progress bars and operation tracking
 */

import { logger } from './logger';

/**
 * Operation types
 */
export enum OperationType {
  Encryption = 'encryption',
  Decryption = 'decryption',
  Compression = 'compression',
  Decompression = 'decompression',
  FileOperation = 'file-operation'
}

/**
 * Operation status
 */
enum OperationStatus {
  InProgress = 'in-progress',
  Completed = 'completed',
  Failed = 'failed'
}

/**
 * Operation information
 */
interface Operation {
  id: string;
  type: OperationType;
  status: OperationStatus;
  progress: number;
  currentStep: number;
  totalSteps: number;
  startTime: number;
  endTime?: number;
  message?: string;
  error?: string;
}

/**
 * Progress tracker for operations
 */
class ProgressTrackerClass {
  private operations: Map<string, Operation> = new Map();

  /**
   * Start tracking a new operation
   * @param type - Operation type
   * @param id - Operation ID
   * @param totalSteps - Total number of steps
   * @returns The operation ID
   */
  public startOperation(
    type: OperationType,
    id: string,
    totalSteps: number = 1
  ): string {
    const operation: Operation = {
      id,
      type,
      status: OperationStatus.InProgress,
      progress: 0,
      currentStep: 1,
      totalSteps,
      startTime: Date.now()
    };
    
    this.operations.set(id, operation);
    
    logger.info(`Started ${type} operation`, { id, totalSteps });
    this.renderProgress(operation);
    
    return id;
  }

  /**
   * Update the progress of an operation
   * @param id - Operation ID
   * @param progress - Progress percentage (0-100)
   * @param message - Optional message
   */
  public updateProgress(
    id: string,
    progress: number,
    message?: string
  ): void {
    const operation = this.getOperation(id);
    if (!operation) return;
    
    operation.progress = Math.min(Math.max(progress, 0), 100);
    if (message) operation.message = message;
    
    this.operations.set(id, operation);
    this.renderProgress(operation);
  }

  /**
   * Move to the next step in an operation
   * @param id - Operation ID
   * @param message - Optional message
   */
  public nextStep(id: string, message?: string): void {
    const operation = this.getOperation(id);
    if (!operation) return;
    
    operation.currentStep = Math.min(operation.currentStep + 1, operation.totalSteps);
    operation.progress = (operation.currentStep - 1) / operation.totalSteps * 100;
    if (message) operation.message = message;
    
    this.operations.set(id, operation);
    this.renderProgress(operation);
  }

  /**
   * Mark an operation as completed
   * @param id - Operation ID
   * @param message - Optional completion message
   */
  public completeOperation(id: string, message?: string): void {
    const operation = this.getOperation(id);
    if (!operation) return;
    
    operation.status = OperationStatus.Completed;
    operation.progress = 100;
    operation.currentStep = operation.totalSteps;
    operation.endTime = Date.now();
    if (message) operation.message = message;
    
    this.operations.set(id, operation);
    this.renderProgress(operation);
    
    const duration = (operation.endTime - operation.startTime) / 1000;
    logger.success(
      `Completed ${operation.type} operation in ${duration.toFixed(2)}s`,
      { id, message }
    );
  }

  /**
   * Mark an operation as failed
   * @param id - Operation ID
   * @param error - Error message
   */
  public failOperation(id: string, error: string): void {
    const operation = this.getOperation(id);
    if (!operation) return;
    
    operation.status = OperationStatus.Failed;
    operation.endTime = Date.now();
    operation.error = error;
    
    this.operations.set(id, operation);
    this.renderProgress(operation);
    
    const duration = (operation.endTime - operation.startTime) / 1000;
    logger.error(
      `Failed ${operation.type} operation after ${duration.toFixed(2)}s`,
      { id, error }
    );
  }

  /**
   * Get an operation by ID
   * @param id - Operation ID
   * @returns The operation or undefined if not found
   */
  private getOperation(id: string): Operation | undefined {
    const operation = this.operations.get(id);
    
    if (!operation) {
      logger.warn(`Operation not found: ${id}`);
      return undefined;
    }
    
    return operation;
  }

  /**
   * Render the progress of an operation
   * @param operation - Operation to render
   */
  private renderProgress(operation: Operation): void {
    // Only render in non-production environments
    if (process.env.NODE_ENV === 'production') return;
    
    const { id, type, status, progress, currentStep, totalSteps, message } = operation;
    
    // Create progress bar
    const barLength = 30;
    const filledLength = Math.round(barLength * progress / 100);
    const emptyLength = barLength - filledLength;
    
    const bar = '[' + 
      '='.repeat(filledLength) + 
      (filledLength < barLength ? '>' : '') + 
      ' '.repeat(Math.max(0, emptyLength - (filledLength < barLength ? 1 : 0))) + 
      ']';
    
    // Status indicator
    let statusIndicator = '';
    switch (status) {
      case OperationStatus.InProgress:
        statusIndicator = '🔄';
        break;
      case OperationStatus.Completed:
        statusIndicator = '✅';
        break;
      case OperationStatus.Failed:
        statusIndicator = '❌';
        break;
    }
    
    // Format message
    const progressInfo = `${statusIndicator} ${type.toUpperCase()} (${id.slice(0, 8)}) ${bar} ${progress.toFixed(1)}%`;
    const stepInfo = `Step ${currentStep}/${totalSteps}`;
    const messageInfo = message ? `: ${message}` : '';
    
    // Log progress
    console.log(`${progressInfo} ${stepInfo}${messageInfo}`);
    
    // Log error if failed
    if (status === OperationStatus.Failed && operation.error) {
      console.log(`  ↳ Error: ${operation.error}`);
    }
  }

  /**
   * Get all operations
   * @returns Map of all operations
   */
  public getAllOperations(): Map<string, Operation> {
    return new Map(this.operations);
  }

  /**
   * Get operation statistics
   * @returns Operation statistics
   */
  public getStats(): {
    total: number;
    completed: number;
    failed: number;
    inProgress: number;
    averageDuration: number;
  } {
    let completed = 0;
    let failed = 0;
    let inProgress = 0;
    let totalDuration = 0;
    let completedCount = 0;
    
    this.operations.forEach(op => {
      if (op.status === OperationStatus.Completed) {
        completed++;
        if (op.endTime && op.startTime) {
          totalDuration += op.endTime - op.startTime;
          completedCount++;
        }
      } else if (op.status === OperationStatus.Failed) {
        failed++;
      } else {
        inProgress++;
      }
    });
    
    const averageDuration = completedCount > 0 
      ? totalDuration / completedCount / 1000 
      : 0;
    
    return {
      total: this.operations.size,
      completed,
      failed,
      inProgress,
      averageDuration
    };
  }
}

// Export a singleton instance
export const ProgressTracker = new ProgressTrackerClass();
