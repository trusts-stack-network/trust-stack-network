/**
 * Test component for Plonky2 WASM prover.
 *
 * This component tests browser-based quantum-resistant proof generation.
 */

import { useState, useCallback } from 'react';

// Types for WASM prover
interface WasmProver {
  prebuild_circuit(num_spends: number, num_outputs: number): void;
  prove(witness_json: string): string;
  verify(proof_json: string, num_spends: number, num_outputs: number): boolean;
  free(): void;
}

interface InitOutput {
  memory: WebAssembly.Memory;
}

type InitFn = () => Promise<InitOutput>;
type WasmProverConstructor = new () => WasmProver;

interface TestResult {
  status: 'idle' | 'loading' | 'success' | 'error';
  message: string;
  proofSize?: number;
  proofTime?: number;
  verifyTime?: number;
}

// Generate random 32-byte hex string
function randomHex32(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate a mock Merkle path (32 levels deep)
function generateMerklePath(): { siblings: string[], indices: number[] } {
  const siblings: string[] = [];
  const indices: number[] = [];
  for (let i = 0; i < 32; i++) {
    siblings.push(randomHex32());
    indices.push(Math.random() > 0.5 ? 1 : 0);
  }
  return { siblings, indices };
}

export default function PlonkyTest() {
  const [result, setResult] = useState<TestResult>({ status: 'idle', message: 'Click "Run Test" to test the Plonky2 WASM prover' });
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = useCallback((msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${msg}`]);
    console.log(msg);
  }, []);

  const runTest = useCallback(async () => {
    setResult({ status: 'loading', message: 'Initializing WASM module...' });
    setLogs([]);
    addLog('Starting Plonky2 WASM test...');

    try {
      // Dynamic import of WASM module
      addLog('Loading WASM module...');
      const wasmModule = await import('tsn-plonky2-wasm');

      // Initialize WASM
      addLog('Initializing WASM...');
      const init: InitFn = wasmModule.default;
      await init();
      addLog('WASM initialized successfully');

      // Create prover
      addLog('Creating WasmProver instance...');
      const WasmProverClass: WasmProverConstructor = wasmModule.WasmProver;
      const prover = new WasmProverClass();
      addLog('WasmProver created');

      // Pre-build circuit for 1 spend, 1 output
      addLog('Pre-building circuit (1 spend, 1 output)...');
      setResult({ status: 'loading', message: 'Pre-building circuit...' });
      const prebuildStart = Date.now();
      prover.prebuild_circuit(1, 1);
      const prebuildTime = Date.now() - prebuildStart;
      addLog(`Circuit pre-built in ${prebuildTime}ms`);

      // Generate test witness
      addLog('Generating test witness...');
      const merkle = generateMerklePath();
      const witness = {
        spends: [{
          value: '1000',
          recipientPkHash: randomHex32(),
          randomness: randomHex32(),
          nullifierKey: randomHex32(),
          position: '0',
          merkleRoot: randomHex32(),
          merklePath: merkle.siblings,
          pathIndices: merkle.indices,
        }],
        outputs: [{
          value: '900',
          recipientPkHash: randomHex32(),
          randomness: randomHex32(),
        }],
        fee: '100',
      };
      addLog('Witness generated');

      // Generate proof
      addLog('Generating proof (this may take a moment)...');
      setResult({ status: 'loading', message: 'Generating proof...' });
      const proveStart = Date.now();
      const proofJson = prover.prove(JSON.stringify(witness));
      const proofTime = Date.now() - proveStart;
      addLog(`Proof generated in ${proofTime}ms`);

      // Parse proof
      const proof = JSON.parse(proofJson);
      const proofSize = proof.proofBytes.length / 2; // hex string, so divide by 2
      addLog(`Proof size: ${proofSize} bytes (${(proofSize / 1024).toFixed(1)} KB)`);

      // Verify proof
      addLog('Verifying proof...');
      setResult({ status: 'loading', message: 'Verifying proof...' });
      const verifyStart = Date.now();
      const isValid = prover.verify(proofJson, 1, 1);
      const verifyTime = Date.now() - verifyStart;
      addLog(`Proof verified in ${verifyTime}ms: ${isValid ? 'VALID' : 'INVALID'}`);

      // Cleanup
      prover.free();

      if (isValid) {
        setResult({
          status: 'success',
          message: 'Plonky2 WASM prover works in browser!',
          proofSize,
          proofTime,
          verifyTime,
        });
        addLog('Test completed successfully!');
      } else {
        setResult({
          status: 'error',
          message: 'Proof verification failed',
        });
        addLog('ERROR: Proof verification failed');
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      addLog(`ERROR: ${errorMsg}`);
      setResult({
        status: 'error',
        message: `Test failed: ${errorMsg}`,
      });
    }
  }, [addLog]);

  return (
    <div style={{
      padding: '20px',
      maxWidth: '800px',
      margin: '0 auto',
      fontFamily: 'system-ui, -apple-system, sans-serif'
    }}>
      <h1 style={{ marginBottom: '20px' }}>Plonky2 WASM Prover Test</h1>

      <div style={{ marginBottom: '20px' }}>
        <p style={{ color: '#666', marginBottom: '10px' }}>
          This tests the quantum-resistant Plonky2 STARK prover running in your browser via WebAssembly.
        </p>
        <button
          onClick={runTest}
          disabled={result.status === 'loading'}
          style={{
            padding: '12px 24px',
            fontSize: '16px',
            backgroundColor: result.status === 'loading' ? '#ccc' : '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: result.status === 'loading' ? 'not-allowed' : 'pointer',
          }}
        >
          {result.status === 'loading' ? 'Running...' : 'Run Test'}
        </button>
      </div>

      {/* Status */}
      <div style={{
        padding: '16px',
        borderRadius: '8px',
        marginBottom: '20px',
        backgroundColor: result.status === 'success' ? '#d4edda' :
                        result.status === 'error' ? '#f8d7da' :
                        result.status === 'loading' ? '#fff3cd' : '#e9ecef',
        borderLeft: `4px solid ${
          result.status === 'success' ? '#28a745' :
          result.status === 'error' ? '#dc3545' :
          result.status === 'loading' ? '#ffc107' : '#6c757d'
        }`,
      }}>
        <strong>Status:</strong> {result.message}

        {result.status === 'success' && (
          <div style={{ marginTop: '10px' }}>
            <div>Proof generation: <strong>{result.proofTime}ms</strong></div>
            <div>Proof verification: <strong>{result.verifyTime}ms</strong></div>
            <div>Proof size: <strong>{result.proofSize} bytes</strong> ({((result.proofSize || 0) / 1024).toFixed(1)} KB)</div>
          </div>
        )}
      </div>

      {/* Logs */}
      <div>
        <h3 style={{ marginBottom: '10px' }}>Logs</h3>
        <div style={{
          backgroundColor: '#1e1e1e',
          color: '#d4d4d4',
          padding: '16px',
          borderRadius: '8px',
          fontFamily: 'monospace',
          fontSize: '13px',
          maxHeight: '400px',
          overflow: 'auto',
        }}>
          {logs.length === 0 ? (
            <div style={{ color: '#666' }}>No logs yet</div>
          ) : (
            logs.map((log, i) => (
              <div key={i} style={{
                marginBottom: '4px',
                color: log.includes('ERROR') ? '#f48771' :
                       log.includes('successfully') || log.includes('VALID') ? '#89d185' : '#d4d4d4'
              }}>
                {log}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
