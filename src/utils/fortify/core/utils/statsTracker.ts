/**
 * Class for tracking cryptographic operation statistics
 */
export class StatsTracker {
    private static instance: StatsTracker;

    private stats = {
        tokensGenerated: 0,
        hashesComputed: 0,
        keysDerivated: 0,
        averageEntropyBits: 0,
        lastOperationTime: new Date().toISOString(),
        performance: {
            tokenGenerationAvgMs: 0,
            hashComputationAvgMs: 0,
            keyDerivationAvgMs: 0,
        },
        memory: {
            peakUsageBytes: 0,
            averageUsageBytes: 0,
            currentUsageBytes: 0,
        },
    };

    private tokenGenerationTimes: number[] = [];
    private hashComputationTimes: number[] = [];
    private keyDerivationTimes: number[] = [];
    private entropyMeasurements: number[] = [];
    private memoryMeasurements: number[] = [];

    // Map to store active operations
    private _activeOperations = new Map<string, any>();

    /**
     * Get the singleton instance of StatsTracker
     * @returns The StatsTracker instance
     */
    public static getInstance(): StatsTracker {
        if (!StatsTracker.instance) {
            StatsTracker.instance = new StatsTracker();
        }
        return StatsTracker.instance;
    }

    /**
     * Private constructor to enforce singleton pattern
     */
    private constructor() {
        // Initialize memory tracking if in Node.js environment
        if (
            typeof process !== "undefined" &&
            typeof process.memoryUsage === "function"
        ) {
            this.trackMemoryUsage();
        }
    }

    /**
     * Start tracking an operation
     * @param operationType - Type of operation
     * @param operationId - Unique identifier for the operation
     * @returns Operation ID
     */
    public startOperation(operationType: string, operationId?: string): string {
        const id = operationId || this.generateOperationId();
        const startTime = Date.now();
        
        // Store operation data
        const operationData = {
            operationId: id,
            operationType,
            startTime,
            success: false
        };
        
        this._activeOperations.set(id, operationData);
        
        return id;
    }
    
    /**
     * Complete an operation successfully
     * @param operationId - ID of the operation to complete
     * @param metrics - Additional metrics for the operation
     */
    public completeOperation(operationId: string, metrics?: any): void {
        if (!this._activeOperations.has(operationId)) {
            return;
        }
        
        const operation = this._activeOperations.get(operationId);
        if (!operation) {
            return;
        }
        
        const endTime = Date.now();
        const timeTakenMs = endTime - (operation.startTime || endTime);
        
        // Update operation data
        operation.endTime = endTime;
        operation.timeTakenMs = timeTakenMs;
        operation.success = true;
        
        if (metrics) {
            Object.assign(operation, metrics);
        }
        
        // Remove from active operations
        this._activeOperations.delete(operationId);
        
        // Update stats based on operation type
        this.updateOperationStats(operation);
    }
    
    /**
     * Mark an operation as failed
     * @param operationId - ID of the operation that failed
     * @param error - Error information
     */
    public failOperation(operationId: string, error: string): void {
        if (!this._activeOperations.has(operationId)) {
            return;
        }
        
        const operation = this._activeOperations.get(operationId);
        if (!operation) {
            return;
        }
        
        const endTime = Date.now();
        
        // Update operation data
        operation.endTime = endTime;
        operation.timeTakenMs = endTime - (operation.startTime || endTime);
        operation.success = false;
        operation.error = error;
        
        // Remove from active operations
        this._activeOperations.delete(operationId);
    }
    
    /**
     * Generate a unique operation ID
     * @returns Unique ID
     */
    private generateOperationId(): string {
        return `op-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    }
    
    /**
     * Update stats based on completed operation
     * @param operation - Completed operation data
     */
    private updateOperationStats(operation: any): void {
        // Update specific stats based on operation type
        switch (operation.operationType) {
            case 'token_generation':
                this.trackTokenGeneration(
                    operation.timeTakenMs || 0, 
                    operation.entropyBits || 128
                );
                break;
            case 'hash_computation':
                this.trackHashComputation(operation.timeTakenMs || 0);
                break;
            case 'key_derivation':
                this.trackKeyDerivation(
                    operation.timeTakenMs || 0, 
                    operation.memoryUsedBytes || 0
                );
                break;
        }
    }

    /**
     * Track token generation
     * @param timeMs - Time taken to generate the token in milliseconds
     * @param entropyBits - Estimated entropy bits of the token
     */
    public trackTokenGeneration(timeMs: number, entropyBits: number): void {
        this.stats.tokensGenerated++;
        this.tokenGenerationTimes.push(timeMs);
        this.entropyMeasurements.push(entropyBits);
        this.updateAverages();
        this.updateLastOperationTime();
    }

    /**
     * Track hash computation
     * @param timeMs - Time taken to compute the hash in milliseconds
     */
    public trackHashComputation(timeMs: number): void {
        this.stats.hashesComputed++;
        this.hashComputationTimes.push(timeMs);
        this.updateAverages();
        this.updateLastOperationTime();
    }

    /**
     * Track key derivation
     * @param timeMs - Time taken to derive the key in milliseconds
     * @param memoryUsedBytes - Memory used for key derivation in bytes
     */
    public trackKeyDerivation(timeMs: number, memoryUsedBytes: number): void {
        this.stats.keysDerivated++;
        this.keyDerivationTimes.push(timeMs);
        if (memoryUsedBytes > 0) {
            this.memoryMeasurements.push(memoryUsedBytes);
        }
        this.updateAverages();
        this.updateLastOperationTime();
    }

    /**
     * Update average values
     */
    private updateAverages(): void {
        // Update token generation average time
        if (this.tokenGenerationTimes.length > 0) {
            const sum = this.tokenGenerationTimes.reduce((a, b) => a + b, 0);
            this.stats.performance.tokenGenerationAvgMs = sum / this.tokenGenerationTimes.length;
        }

        // Update hash computation average time
        if (this.hashComputationTimes.length > 0) {
            const sum = this.hashComputationTimes.reduce((a, b) => a + b, 0);
            this.stats.performance.hashComputationAvgMs = sum / this.hashComputationTimes.length;
        }

        // Update key derivation average time
        if (this.keyDerivationTimes.length > 0) {
            const sum = this.keyDerivationTimes.reduce((a, b) => a + b, 0);
            this.stats.performance.keyDerivationAvgMs = sum / this.keyDerivationTimes.length;
        }

        // Update average entropy bits
        if (this.entropyMeasurements.length > 0) {
            const sum = this.entropyMeasurements.reduce((a, b) => a + b, 0);
            this.stats.averageEntropyBits = sum / this.entropyMeasurements.length;
        }

        // Update average memory usage
        if (this.memoryMeasurements.length > 0) {
            const sum = this.memoryMeasurements.reduce((a, b) => a + b, 0);
            this.stats.memory.averageUsageBytes = sum / this.memoryMeasurements.length;
        }
    }

    /**
     * Update the last operation timestamp
     */
    private updateLastOperationTime(): void {
        this.stats.lastOperationTime = new Date().toISOString();
    }

    /**
     * Track memory usage in Node.js environment
     */
    private trackMemoryUsage(): void {
        try {
            const memoryUsage = process.memoryUsage();
            const heapUsed = memoryUsage.heapUsed;
            
            // Update peak memory usage
            if (heapUsed > this.stats.memory.peakUsageBytes) {
                this.stats.memory.peakUsageBytes = heapUsed;
            }
            
            // Update current memory usage
            this.stats.memory.currentUsageBytes = heapUsed;
            
            // Schedule next check
            setTimeout(() => this.trackMemoryUsage(), 5000); // Check every 5 seconds
        } catch (error) {
            // Ignore errors in memory tracking
        }
    }

    /**
     * Get the current statistics
     * @returns Current statistics
     */
    public getStats(): any {
        return { ...this.stats };
    }

    /**
     * Reset all statistics
     */
    public resetStats(): void {
        this.stats = {
            tokensGenerated: 0,
            hashesComputed: 0,
            keysDerivated: 0,
            averageEntropyBits: 0,
            lastOperationTime: new Date().toISOString(),
            performance: {
                tokenGenerationAvgMs: 0,
                hashComputationAvgMs: 0,
                keyDerivationAvgMs: 0,
            },
            memory: {
                peakUsageBytes: 0,
                averageUsageBytes: 0,
                currentUsageBytes: 0,
            },
        };
        
        this.tokenGenerationTimes = [];
        this.hashComputationTimes = [];
        this.keyDerivationTimes = [];
        this.entropyMeasurements = [];
        this.memoryMeasurements = [];
    }
}

// Export the singleton instance
export const statsTracker = StatsTracker.getInstance();
