/**
 * Worker pool for parallel note scanning.
 *
 * Manages a pool of Web Workers to perform trial decryption in parallel,
 * significantly speeding up wallet scanning.
 */

// Use Vite's worker import syntax
import ScanWorker from './scan-worker?worker';

interface ScanOutput {
  ciphertext: string;
  ephemeral_pk: string;
  note_commitment: string;
  note_commitment_pq?: string;
  position: number;
  block_height: number;
}

interface DecryptedNote {
  value: string;
  recipientPkHash: string;
  randomness: string;
  commitment: string;
  position: string;
  blockHeight: number;
  nullifier: string;
}

interface WorkerState {
  worker: Worker;
  busy: boolean;
  ready: boolean;
}

/**
 * Pool of Web Workers for parallel scanning.
 */
export class ScanWorkerPool {
  private workers: WorkerState[] = [];
  private poolSize: number;
  private initialized: boolean = false;

  constructor(poolSize?: number) {
    // Default to navigator.hardwareConcurrency or 4
    this.poolSize = poolSize ?? Math.min(navigator.hardwareConcurrency || 4, 8);
  }

  /**
   * Initialize the worker pool.
   * Must be called before using scan().
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    const initPromises: Promise<void>[] = [];

    for (let i = 0; i < this.poolSize; i++) {
      const worker = new ScanWorker();
      const state: WorkerState = { worker, busy: false, ready: false };
      this.workers.push(state);

      initPromises.push(
        new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error(`Worker ${i} initialization timeout`));
          }, 30000);

          worker.onmessage = (event) => {
            if (event.data.type === 'ready') {
              clearTimeout(timeout);
              state.ready = true;
              resolve();
            } else if (event.data.type === 'error') {
              clearTimeout(timeout);
              reject(new Error(event.data.error));
            }
          };

          worker.postMessage({ type: 'init' });
        })
      );
    }

    await Promise.all(initPromises);
    this.initialized = true;
  }

  /**
   * Get the pool size.
   */
  get size(): number {
    return this.poolSize;
  }

  /**
   * Scan outputs in parallel using the worker pool.
   *
   * @param outputs - Array of encrypted outputs to scan
   * @param pkHash - Recipient's public key hash (hex)
   * @param nullifierKey - Nullifier key (hex)
   * @param onProgress - Progress callback
   * @returns Array of decrypted notes found
   */
  async scan(
    outputs: ScanOutput[],
    pkHash: string,
    nullifierKey: string,
    onProgress?: (processed: number, total: number) => void
  ): Promise<DecryptedNote[]> {
    if (!this.initialized) {
      throw new Error('Worker pool not initialized');
    }

    if (outputs.length === 0) {
      return [];
    }

    // Split outputs into chunks for parallel processing
    const chunkSize = Math.ceil(outputs.length / this.poolSize);
    const chunks: ScanOutput[][] = [];
    for (let i = 0; i < outputs.length; i += chunkSize) {
      chunks.push(outputs.slice(i, i + chunkSize));
    }

    // Process chunks in parallel
    let processedCount = 0;
    const allNotes: DecryptedNote[] = [];

    const chunkPromises = chunks.map((chunk, index) => {
      return new Promise<DecryptedNote[]>((resolve, reject) => {
        const workerState = this.workers[index % this.workers.length];

        const handleMessage = (event: MessageEvent) => {
          if (event.data.type === 'result') {
            workerState.worker.removeEventListener('message', handleMessage);
            workerState.busy = false;
            processedCount += chunk.length;
            onProgress?.(processedCount, outputs.length);
            resolve(event.data.notes);
          } else if (event.data.type === 'error') {
            workerState.worker.removeEventListener('message', handleMessage);
            workerState.busy = false;
            reject(new Error(event.data.error));
          }
        };

        workerState.worker.addEventListener('message', handleMessage);
        workerState.busy = true;
        workerState.worker.postMessage({
          type: 'scan',
          outputs: chunk,
          pkHash,
          nullifierKey,
        });
      });
    });

    const results = await Promise.all(chunkPromises);
    for (const notes of results) {
      allNotes.push(...notes);
    }

    return allNotes;
  }

  /**
   * Terminate all workers and clean up.
   */
  terminate(): void {
    for (const state of this.workers) {
      state.worker.terminate();
    }
    this.workers = [];
    this.initialized = false;
  }
}

// Singleton pool instance
let poolInstance: ScanWorkerPool | null = null;

/**
 * Get the shared worker pool instance.
 * Creates and initializes the pool on first call.
 */
export async function getWorkerPool(): Promise<ScanWorkerPool> {
  if (!poolInstance) {
    poolInstance = new ScanWorkerPool();
    await poolInstance.initialize();
  }
  return poolInstance;
}

/**
 * Check if Web Workers are supported.
 */
export function isWorkerSupported(): boolean {
  return typeof Worker !== 'undefined';
}
