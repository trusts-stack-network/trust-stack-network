import { useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import './Landing.css'

// Example ML-DSA-65 signature (3,309 bytes represented as hex, truncated for display)
const EXAMPLE_SIGNATURE = `8a4f2b1c9e7d3f5a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a
4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c
8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e
2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a
... (3,309 bytes total)`

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

interface DemoState {
  status: 'idle' | 'loading' | 'success' | 'error';
  step: string;
  proofSize?: number;
  proofTime?: number;
  verifyTime?: number;
  proofPreview?: string;
  error?: string;
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

export default function Landing() {
  const [demoState, setDemoState] = useState<DemoState>({
    status: 'idle',
    step: 'Click "Generate Proof" to create a quantum-resistant STARK proof in your browser'
  });

  const runPlonkyDemo = useCallback(async () => {
    setDemoState({ status: 'loading', step: 'Initializing WASM module...' });

    try {
      // Dynamic import of WASM module
      const wasmModule = await import('tsn-plonky2-wasm');

      // Initialize WASM
      setDemoState({ status: 'loading', step: 'Loading Plonky2 prover...' });
      const init: InitFn = wasmModule.default;
      await init();

      // Create prover
      setDemoState({ status: 'loading', step: 'Building circuit (1 input, 1 output)...' });
      const WasmProverClass: WasmProverConstructor = wasmModule.WasmProver;
      const prover = new WasmProverClass();

      // Pre-build circuit for 1 spend, 1 output
      const prebuildStart = Date.now();
      prover.prebuild_circuit(1, 1);
      const prebuildTime = Date.now() - prebuildStart;
      console.log(`Circuit built in ${prebuildTime}ms`);

      // Generate test witness
      setDemoState({ status: 'loading', step: 'Generating STARK proof...' });
      const merkle = generateMerklePath();
      const witness = {
        spends: [{
          value: '1000000000', // 1 TSN
          recipientPkHash: randomHex32(),
          randomness: randomHex32(),
          nullifierKey: randomHex32(),
          position: '0',
          merkleRoot: randomHex32(),
          merklePath: merkle.siblings,
          pathIndices: merkle.indices,
        }],
        outputs: [{
          value: '999000000', // 0.999 TSN (0.001 fee)
          recipientPkHash: randomHex32(),
          randomness: randomHex32(),
        }],
        fee: '1000000', // 0.001 TSN
      };

      // Generate proof
      const proveStart = Date.now();
      const proofJson = prover.prove(JSON.stringify(witness));
      const proofTime = Date.now() - proveStart;

      // Parse proof
      const proof = JSON.parse(proofJson);
      const proofSize = proof.proofBytes.length / 2;

      // Verify proof
      setDemoState({ status: 'loading', step: 'Verifying proof...' });
      const verifyStart = Date.now();
      const isValid = prover.verify(proofJson, 1, 1);
      const verifyTime = Date.now() - verifyStart;

      // Cleanup
      prover.free();

      if (isValid) {
        // Create a preview of the proof (first 200 chars)
        const proofPreview = proof.proofBytes.substring(0, 200) + '...';

        setDemoState({
          status: 'success',
          step: 'Proof generated and verified!',
          proofSize,
          proofTime,
          verifyTime,
          proofPreview,
        });
      } else {
        setDemoState({
          status: 'error',
          step: 'Proof verification failed',
          error: 'The generated proof did not pass verification',
        });
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      setDemoState({
        status: 'error',
        step: 'Error generating proof',
        error: errorMsg,
      });
    }
  }, []);

  return (
    <div className="landing">
      <div className="landing-container">
        {/* Hero Section */}
        <header className="hero">
          <img src="/logo.png" alt="TSN" className="logo" />
          <h1 className="title">TSN</h1>
          <p className="tagline">Fully Quantum-Resistant Private Transactions</p>
                    <nav className="nav-links hero-nav">
            <Link to="/wallet" className="nav-link">
              Open Wallet
            </Link>
            <Link to="/explorer" className="nav-link secondary">
              Block Explorer
            </Link>
          </nav>
        </header>

        {/* Description */}
        <section className="section">
          <h2>What is TSN?</h2>
          <p className="description">
            TSN is a privacy-focused cryptocurrency that combines <strong>post-quantum signatures</strong> with
            <strong> post-quantum zero-knowledge proofs</strong> to create truly private, quantum-resistant transactions.
          </p>
          <div className="features">
            <div className="feature">
              <div className="feature-icon">Q</div>
              <h3>Quantum Resistant</h3>
              <p>Built on ML-DSA-65 (FIPS 204), a NIST-standardized lattice-based signature scheme that remains secure against quantum computers.</p>
            </div>
            <div className="feature">
              <div className="feature-icon">S</div>
              <h3>STARK Proofs</h3>
              <p>V2 transactions use Plonky2 STARKs over the Goldilocks field—fully quantum-resistant zero-knowledge proofs with no trusted setup.</p>
            </div>
            <div className="feature">
              <div className="feature-icon">P</div>
              <h3>Private by Default</h3>
              <p>All transaction amounts are hidden using Poseidon hash commitments. Only you can see your balance with your viewing key.</p>
            </div>
          </div>
        </section>

        {/* Comparison with Other Private Blockchains */}
        <section className="section">
          <h2>How TSN Compares</h2>
          <p className="section-intro">
            TSN is the first privacy-focused blockchain to achieve <strong>full quantum resistance</strong> across
            all cryptographic components—signatures, proofs, and commitments.
          </p>
          <div className="comparison-table">
            <table>
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>TSN</th>
                  <th>Zcash</th>
                  <th>Monero</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Signatures</td>
                  <td className="safe">ML-DSA-65 (PQ) ✓</td>
                  <td className="warning">ECDSA ⚠</td>
                  <td className="warning">EdDSA ⚠</td>
                </tr>
                <tr>
                  <td>ZK Proofs</td>
                  <td className="safe">Plonky2 STARKs (PQ) ✓</td>
                  <td className="warning">Groth16 ⚠</td>
                  <td>Bulletproofs</td>
                </tr>
                <tr>
                  <td>Commitments</td>
                  <td className="safe">Poseidon (PQ) ✓</td>
                  <td className="warning">Pedersen ⚠</td>
                  <td className="warning">Pedersen ⚠</td>
                </tr>
                <tr>
                  <td>Quantum Safe</td>
                  <td className="safe">Fully ✓</td>
                  <td className="warning">No ⚠</td>
                  <td className="warning">No ⚠</td>
                </tr>
                <tr>
                  <td>Trusted Setup</td>
                  <td className="safe">None ✓</td>
                  <td className="warning">Required ⚠</td>
                  <td className="safe">None ✓</td>
                </tr>
                <tr>
                  <td>Hidden Amounts</td>
                  <td className="safe">Yes ✓</td>
                  <td className="safe">Yes ✓</td>
                  <td className="safe">Yes ✓</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Quantum Signature Demo */}
        <section className="section">
          <h2>Quantum-Resistant Signatures</h2>
          <p className="section-intro">
            Every transaction is signed with <strong>ML-DSA-65</strong> (FIPS 204), a lattice-based digital signature
            algorithm standardized by NIST. Unlike ECDSA, it cannot be broken by Shor's algorithm.
          </p>
          <div className="demo-card">
            <div className="demo-header">
              <span className="demo-label">ML-DSA-65 Signature</span>
              <span className="demo-size">3,309 bytes</span>
            </div>
            <pre className="demo-content signature">{EXAMPLE_SIGNATURE}</pre>
            <div className="demo-footer">
              <div className="spec-item">
                <span className="spec-label">Public Key</span>
                <span className="spec-value">1,952 bytes</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Security Level</span>
                <span className="spec-value">NIST Level 3</span>
              </div>
            </div>
          </div>
        </section>

        {/* Interactive Plonky2 Demo */}
        <section className="section">
          <h2>Plonky2 STARK Proofs</h2>
          <p className="section-intro">
            V2 transactions generate <strong>Plonky2 STARK proofs</strong> directly in your browser using WebAssembly.
            These proofs are quantum-resistant and require no trusted setup.
          </p>
          <div className="demo-card interactive">
            <div className="demo-header">
              <span className="demo-label">Live Plonky2 Proof Generator</span>
              <span className="demo-size">~50 KB proof</span>
            </div>

            <div className="demo-interactive">
              <button
                className={`demo-button ${demoState.status === 'loading' ? 'loading' : ''}`}
                onClick={runPlonkyDemo}
                disabled={demoState.status === 'loading'}
              >
                {demoState.status === 'loading' ? 'Generating...' : 'Generate Proof'}
              </button>

              <div className={`demo-status ${demoState.status}`}>
                <span className="status-icon">
                  {demoState.status === 'idle' && '○'}
                  {demoState.status === 'loading' && '◐'}
                  {demoState.status === 'success' && '✓'}
                  {demoState.status === 'error' && '✗'}
                </span>
                <span className="status-text">{demoState.step}</span>
              </div>

              {demoState.status === 'success' && (
                <div className="demo-results">
                  <div className="result-item">
                    <span className="result-label">Proof Time</span>
                    <span className="result-value">{demoState.proofTime}ms</span>
                  </div>
                  <div className="result-item">
                    <span className="result-label">Verify Time</span>
                    <span className="result-value">{demoState.verifyTime}ms</span>
                  </div>
                  <div className="result-item">
                    <span className="result-label">Proof Size</span>
                    <span className="result-value">{((demoState.proofSize || 0) / 1024).toFixed(1)} KB</span>
                  </div>
                </div>
              )}

              {demoState.proofPreview && (
                <pre className="demo-content proof-preview">
                  {demoState.proofPreview}
                </pre>
              )}

              {demoState.error && (
                <div className="demo-error">
                  {demoState.error}
                </div>
              )}
            </div>

            <div className="demo-footer">
              <div className="spec-item">
                <span className="spec-label">Field</span>
                <span className="spec-value">Goldilocks</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Hash</span>
                <span className="spec-value">Poseidon</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Security</span>
                <span className="spec-value">100+ bit PQ</span>
              </div>
            </div>
          </div>
        </section>

        {/* Whitepaper */}
        <section className="section whitepaper-section">
          <h2>Technical Details</h2>
          <p className="section-intro">
            For a complete technical specification of the protocol, cryptographic primitives,
            and security analysis, read the whitepaper.
          </p>
          <a href="/whitepaper" className="whitepaper-link" target="_blank" rel="noopener noreferrer">
            Read Whitepaper v2.0 (Web)
          </a>
        </section>

        <footer className="footer">
          <p>MIT License | Fully Open Source</p>
        </footer>
      </div>
    </div>
  )
}
