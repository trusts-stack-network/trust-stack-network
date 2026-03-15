import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  generateKeyPair,
  bytesToHex,
  hexToBytes,
  sign,
  MLDSA65_PK_SIZE,
  MLDSA65_SK_SIZE,
} from './crypto';
import { computePkHash } from './shielded-crypto';
import { ShieldedWallet, ShieldedWalletV2 } from './shielded-wallet';
import {
  createShieldedTransactionV2,
  validateTransactionParams,
} from './transaction-builder';
import { submitShieldedTransactionV2, getChainInfo, getFaucetStatus, getFaucetStats } from './api';
import type { Wallet as WalletType } from './types';
import Faucet from './components/Faucet';
import './App.css';

const STORAGE_KEY = 'tsn_wallet';

export default function Wallet() {
  const [wallet, setWallet] = useState<WalletType | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'wallet' | 'send' | 'receive' | 'faucet' | 'sign'>('wallet');

  // Shielded wallet state
  const [shieldedWallet, setShieldedWallet] = useState<ShieldedWalletV2 | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>('');
  const [balance, setBalance] = useState<string>('0');
  const [unspentCount, setUnspentCount] = useState(0);

  // Sign message state
  const [messageToSign, setMessageToSign] = useState('');
  const [signedResult, setSignedResult] = useState<{ message: string; signature: string } | null>(null);

  // Send form state
  const [sendTo, setSendTo] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendFee, setSendFee] = useState('0.001');
  const [sending, setSending] = useState(false);
  const [sendResult, setSendResult] = useState<{ success: boolean; message: string } | null>(null);

  // Import form state
  const [showImport, setShowImport] = useState(false);
  const [importPk, setImportPk] = useState('');
  const [importSk, setImportSk] = useState('');

  // Faucet status for tab sparkle
  const [faucetReady, setFaucetReady] = useState(false);

  // Show keys state
  const [showKeys, setShowKeys] = useState(false);

  // Load wallet from storage
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        setWallet(JSON.parse(stored));
      } catch (e) {
        console.error('Failed to load wallet:', e);
      }
    }
    setLoading(false);
  }, []);

  // Initialize shielded wallet when wallet is loaded
  useEffect(() => {
    if (wallet) {
      const initializeWallet = async () => {
        // Initialize Poseidon hash before creating wallet (required for nullifier derivation)
        await ShieldedWallet.initialize(false, (msg) => setScanStatus(msg));

        const sw = ShieldedWalletV2.fromHexV2(wallet.secret_key, wallet.public_key);
        // Set wallet birthday for faster scanning (skip outputs before wallet creation)
        if (wallet.birthday) {
          sw.birthday = wallet.birthday;
        }
        setShieldedWallet(sw);
        updateBalanceDisplay(sw);

        // Expose for debugging (remove in production)
        (window as any).wallet = sw;
        (window as any).debugWallet = () => {
          console.log('=== WALLET DEBUG ===');
          console.log('V2 Balance:', sw.v2Balance.toString());
          console.log('V2 Unspent Count:', sw.unspentV2Count);
          console.log('V2 Notes:');
          sw.v2Notes.forEach((n, i) => {
            console.log(`  [${i}] value=${n.value}, spent=${n.spent}, nullifier=${n.nullifier?.slice(0, 20)}...`);
          });
          console.log('V1 Balance:', sw.v1Balance.toString());
          console.log('V1 Unspent Count:', sw.unspentCount);
          return { v2Notes: sw.v2Notes, v1Notes: sw.notes };
        };
        console.log('Wallet exposed on window. Run debugWallet() to see state.');
      };
      initializeWallet().catch(console.error);
    }
  }, [wallet]);

  // Update balance display from shielded wallet (V2 enabled)
  const updateBalanceDisplay = useCallback((sw: ShieldedWalletV2) => {
    const summary = sw.getExtendedSummary();
    // Show V2 balance since we send V2 transactions
    setBalance(summary.v2Balance);
    setUnspentCount(summary.v2UnspentCount);
  }, []);

  // Scan for notes
  const handleScan = async () => {
    if (!shieldedWallet || scanning) return;

    setScanning(true);
    setScanStatus('Starting scan...');

    try {
      await shieldedWallet.scan((msg) => setScanStatus(msg));
      updateBalanceDisplay(shieldedWallet);
      setScanStatus('Scan complete');
    } catch (e) {
      setScanStatus(`Scan failed: ${(e as Error).message}`);
    } finally {
      setScanning(false);
    }
  };

  // Auto-scan on wallet load
  useEffect(() => {
    if (shieldedWallet && !scanning && shieldedWallet.lastScannedHeight < 0) {
      handleScan();
    }
  }, [shieldedWallet]);

  // Check faucet status for tab sparkle indicator
  useEffect(() => {
    if (!wallet) return;

    const checkFaucetStatus = async () => {
      try {
        const stats = await getFaucetStats();
        if (!stats.enabled) {
          setFaucetReady(false);
          return;
        }
        const status = await getFaucetStatus(wallet.address);
        setFaucetReady(status.can_claim);
      } catch {
        setFaucetReady(false);
      }
    };

    // Check immediately and when switching views (catches post-claim state)
    checkFaucetStatus();

    // Check every 30 seconds
    const interval = setInterval(checkFaucetStatus, 30000);
    return () => clearInterval(interval);
  }, [wallet, view]);

  // Create new wallet
  const createWallet = async () => {
    setLoading(true);
    try {
      const { publicKey, secretKey } = generateKeyPair();
      // Use computePkHash for shielded address (32 bytes -> 64 hex)
      const pkHash = computePkHash(publicKey);
      const address = bytesToHex(pkHash);

      // Get current chain height as wallet birthday (for faster scanning)
      let birthday: number | undefined;
      try {
        const chainInfo = await getChainInfo();
        birthday = chainInfo.height;
      } catch {
        // If chain info unavailable, skip birthday (will scan from genesis)
        console.warn('Could not get chain height for wallet birthday');
      }

      const newWallet: WalletType = {
        address,
        public_key: bytesToHex(publicKey),
        secret_key: bytesToHex(secretKey),
        birthday,
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(newWallet));
      setWallet(newWallet);
    } catch (e) {
      alert('Failed to create wallet: ' + (e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  // Import wallet
  const importWallet = async () => {
    const pk = importPk.trim();
    const sk = importSk.trim();

    if (!pk || !sk) {
      alert('Please enter both public and secret keys');
      return;
    }

    if (pk.length !== MLDSA65_PK_SIZE * 2) {
      alert(`Invalid public key length. Expected ${MLDSA65_PK_SIZE * 2} hex characters`);
      return;
    }

    if (sk.length !== MLDSA65_SK_SIZE * 2) {
      alert(`Invalid secret key length. Expected ${MLDSA65_SK_SIZE * 2} hex characters`);
      return;
    }

    try {
      const publicKeyBytes = hexToBytes(pk);
      const pkHash = computePkHash(publicKeyBytes);
      const address = bytesToHex(pkHash);

      const newWallet: WalletType = {
        address,
        public_key: pk,
        secret_key: sk,
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(newWallet));
      setWallet(newWallet);
      setShowImport(false);
      setImportPk('');
      setImportSk('');
    } catch (e) {
      alert('Failed to import wallet: ' + (e as Error).message);
    }
  };

  // Logout
  const logout = () => {
    if (confirm('Are you sure you want to logout? Make sure you have backed up your keys!')) {
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem('tsn_shielded_state');
      localStorage.removeItem('tsn_shielded_state_v2');
      setWallet(null);
      setShieldedWallet(null);
    }
  };

  // Sign arbitrary message
  const handleSignMessage = () => {
    if (!wallet) return;
    if (!messageToSign.trim()) {
      alert('Please enter a message to sign');
      return;
    }

    try {
      const messageBytes = new TextEncoder().encode(messageToSign);
      const secretKeyBytes = hexToBytes(wallet.secret_key);
      const signatureBytes = sign(messageBytes, secretKeyBytes);
      const signature = bytesToHex(signatureBytes);

      setSignedResult({
        message: messageToSign,
        signature,
      });
    } catch (e) {
      alert('Failed to sign message: ' + (e as Error).message);
    }
  };

  // Send shielded transaction
  const handleSend = async () => {
    if (!wallet || !shieldedWallet || sending) return;

    setSending(true);
    setSendResult(null);

    try {
      // Initialize V2 (Plonky2) prover for quantum-resistant proofs
      setSendResult({ success: false, message: 'Initializing quantum-resistant prover...' });
      const { initProver, prebuildCircuit } = await import('./prover-pq');
      await initProver();
      // Pre-build circuit for 1 spend, 1 output (common case)
      await prebuildCircuit(1, 1);

      // Parse amounts
      const amount = ShieldedWallet.parseAmount(sendAmount);
      const fee = ShieldedWallet.parseAmount(sendFee);

      // Validate recipient
      const recipientPkHash = sendTo.trim();
      if (recipientPkHash.length !== 64) {
        throw new Error('Recipient pk_hash must be 64 hex characters');
      }

      // Select V2 (post-quantum) notes
      const notesToSpend = shieldedWallet.selectV2Notes(amount + fee);

      // Validate
      const validationError = validateTransactionParams({
        spendNotes: notesToSpend,
        recipients: [{ pkHash: recipientPkHash, amount }],
        fee,
        secretKey: hexToBytes(wallet.secret_key),
        publicKey: hexToBytes(wallet.public_key),
        senderPkHash: shieldedWallet.pkHash,
      });

      if (validationError) {
        throw new Error(validationError);
      }

      // Build V2 (post-quantum) transaction with progress updates
      setSendResult({ success: false, message: `Preparing V2 (quantum-resistant) transaction with ${notesToSpend.length} note(s)...` });
      const tx = await createShieldedTransactionV2({
        spendNotes: notesToSpend,
        recipients: [{ pkHash: recipientPkHash, amount }],
        fee,
        secretKey: hexToBytes(wallet.secret_key),
        publicKey: hexToBytes(wallet.public_key),
        senderPkHash: shieldedWallet.pkHash,
        onProgress: (status) => {
          setSendResult({ success: false, message: status });
        },
      });

      // Submit V2 transaction
      setSendResult({ success: false, message: 'Submitting V2 transaction to network...' });
      const result = await submitShieldedTransactionV2(tx);

      if ('error' in result) {
        throw new Error(result.error);
      }

      setSendResult({
        success: true,
        message: `Transaction submitted! Hash: ${result.hash.slice(0, 16)}...`,
      });

      // Clear form
      setSendTo('');
      setSendAmount('');

      // Refresh balance after a delay
      setTimeout(() => {
        handleScan();
      }, 2000);
    } catch (e) {
      setSendResult({
        success: false,
        message: (e as Error).message,
      });
    } finally {
      setSending(false);
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="app">
        <header className="app-header">
          <Link to="/" className="logo">
            <img src="/logo.png" alt="TSN" className="logo-img" />
            <span>TSN</span>
          </Link>
          <nav className="main-nav">
            <Link to="/explorer">Explorer</Link>
            <Link to="/wallet" className="active">Wallet</Link>
          </nav>
        </header>
        <main className="container">
          <nav className="nav-tabs">
            <a className="active">Balance</a>
            <a>Send</a>
            <a>Receive</a>
            <a>Faucet</a>
            <a>Sign</a>
          </nav>
          <div className="loading">Loading...</div>
        </main>
      </div>
    );
  }

  // No wallet - show create/import
  if (!wallet) {
    return (
      <div className="app">
        <header className="app-header">
          <Link to="/" className="logo">
            <img src="/logo.png" alt="TSN" className="logo-img" />
            <span>TSN</span>
          </Link>
          <nav className="main-nav">
            <Link to="/explorer">Explorer</Link>
            <Link to="/wallet" className="active">Wallet</Link>
          </nav>
        </header>
        <main className="container">
          <nav className="nav-tabs">
            <a className="active">Balance</a>
            <a>Send</a>
            <a>Receive</a>
            <a>Faucet</a>
            <a>Sign</a>
          </nav>
          <h1>Create Wallet</h1>
          <p className="subtitle">Get started with private, quantum-resistant money</p>

          <div className="card info">
            <strong>Post-Quantum Security</strong>
            <p>Uses ML-DSA-65 (FIPS 204) for quantum-resistant signatures.</p>
            <p>All keys are generated and stored locally in your browser.</p>
          </div>

          <div className="card">
            <h2>Get Started</h2>
            <button onClick={createWallet}>Create New Wallet</button>
            <button className="secondary" onClick={() => setShowImport(true)}>
              Import Existing Wallet
            </button>
          </div>

          {showImport && (
            <div className="card">
              <h2>Import Wallet</h2>
              <div className="form-group">
                <label>Public Key (hex)</label>
                <textarea
                  value={importPk}
                  onChange={(e) => setImportPk(e.target.value)}
                  placeholder="Enter your public key..."
                />
              </div>
              <div className="form-group">
                <label>Secret Key (hex)</label>
                <textarea
                  value={importSk}
                  onChange={(e) => setImportSk(e.target.value)}
                  placeholder="Enter your secret key..."
                />
              </div>
              <button onClick={importWallet}>Import</button>
              <button className="secondary" onClick={() => setShowImport(false)}>
                Cancel
              </button>
            </div>
          )}
        </main>
      </div>
    );
  }

  // Wallet view
  return (
    <div className="app">
      <header className="app-header">
        <Link to="/" className="logo">
          <img src="/logo.png" alt="TSN" className="logo-img" />
          <span>TSN</span>
        </Link>
        <nav className="main-nav">
          <Link to="/explorer">Explorer</Link>
          <Link to="/wallet" className="active">Wallet</Link>
        </nav>
      </header>

      <main className="container">
        <nav className="nav-tabs">
          <a className={view === 'wallet' ? 'active' : ''} onClick={() => setView('wallet')}>
            Balance
          </a>
          <a className={view === 'send' ? 'active' : ''} onClick={() => setView('send')}>
            Send
          </a>
          <a className={view === 'receive' ? 'active' : ''} onClick={() => setView('receive')}>
            Receive
          </a>
          <a className={`${view === 'faucet' ? 'active' : ''} ${faucetReady ? 'faucet-ready' : ''}`} onClick={() => setView('faucet')}>
            Faucet
            {faucetReady && (
              <span className="tab-sparkles">
                <span className="tab-sparkle"></span>
                <span className="tab-sparkle"></span>
                <span className="tab-sparkle"></span>
              </span>
            )}
          </a>
          <a className={view === 'sign' ? 'active' : ''} onClick={() => setView('sign')}>
            Sign
          </a>
        </nav>

      {view === 'wallet' && (
        <>
          <div className="card balance-card">
            <div className="balance-display">
              <img src="/logo.png" alt="TSN" className="balance-logo" />
              <div className="balance-info">
                <div className="balance shielded">
                  {scanning ? (
                    <span className="scanning">Scanning...</span>
                  ) : (
                    <>
                      {balance} <span className="currency">TSN</span>
                    </>
                  )}
                </div>
                <p className="balance-label">Shielded Balance</p>
              </div>
            </div>
            {!scanning && (
              <p className="note-count">
                {unspentCount} unspent note{unspentCount !== 1 ? 's' : ''}
              </p>
            )}
            {scanStatus && (
              <p className="scan-status">{scanStatus}</p>
            )}
            <div className="button-row">
              <button
                onClick={handleScan}
                disabled={scanning}
                className="secondary"
              >
                {scanning ? 'Scanning...' : 'Refresh Balance'}
              </button>
            </div>
            <p className="address">
              <span className="label">Public Key Hash:</span>
              <code>{wallet.address}</code>
            </p>
          </div>

          <div className="card">
            <h2>Backup Keys</h2>
            <p className="warning">Save these keys securely. If you lose them, you lose access to your funds.</p>
            <button className="secondary" onClick={() => setShowKeys(!showKeys)}>
              {showKeys ? 'Hide Keys' : 'Show Keys'}
            </button>
            <button className="danger" onClick={logout}>
              Logout
            </button>

            {showKeys && (
              <div className="keys-display">
                <div className="form-group">
                  <label>Public Key (1952 bytes)</label>
                  <textarea readOnly value={wallet.public_key} />
                </div>
                <div className="form-group">
                  <label>Secret Key (4032 bytes)</label>
                  <textarea readOnly value={wallet.secret_key} />
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {view === 'send' && (
        <>
          <div className="page-header">
            <img src="/logo.png" alt="TSN" className="page-header-logo" />
            <div className="page-header-text">
              <h1>Send TSN</h1>
              <p>Send shielded funds privately</p>
            </div>
          </div>
          <div className="card">

          <div className="form-group">
            <label>Recipient Public Key Hash</label>
            <input
              type="text"
              value={sendTo}
              onChange={(e) => setSendTo(e.target.value)}
              placeholder="64-character hex pk_hash"
              disabled={sending}
            />
          </div>

          <div className="form-group">
            <label>Amount (TSN)</label>
            <input
              type="text"
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="0.000000000"
              disabled={sending}
            />
            {shieldedWallet && (
              <small className="helper-text">
                Available: {balance} TSN
              </small>
            )}
          </div>

          <div className="form-group">
            <label>Fee (TSN)</label>
            <input
              type="text"
              value={sendFee}
              onChange={(e) => setSendFee(e.target.value)}
              placeholder="0.001"
              disabled={sending}
            />
          </div>

          <button onClick={handleSend} disabled={sending || !sendTo || !sendAmount}>
            {sending ? 'Sending...' : 'Send'}
          </button>

          {sendResult && (
            <div className={`result ${sendResult.success ? 'success' : 'error'}`}>
              {sendResult.message}
            </div>
          )}
        </div>
        </>
      )}

      {view === 'receive' && (
        <>
          <div className="page-header">
            <img src="/logo.png" alt="TSN" className="page-header-logo" />
            <div className="page-header-text">
              <h1>Receive TSN</h1>
              <p>Share your address to receive funds</p>
            </div>
          </div>
          <div className="card">
          <div className="form-group">
            <label>Your Public Key Hash (pk_hash)</label>
            <div className="address-display">
              <code>{wallet.address}</code>
            </div>
          </div>
          <button
            className="secondary"
            onClick={() => navigator.clipboard.writeText(wallet.address)}
          >
            Copy pk_hash
          </button>
          <p className="shielded-note" style={{ marginTop: '16px' }}>
            Senders will encrypt notes to your pk_hash. Only you can decrypt them.
          </p>
        </div>
        </>
      )}

      {view === 'faucet' && (
        <Faucet pkHash={wallet.address} />
      )}

      {view === 'sign' && (
        <>
          <div className="page-header">
            <img src="/logo.png" alt="TSN" className="page-header-logo" />
            <div className="page-header-text">
              <h1>Sign Message</h1>
              <p>Prove ownership with quantum-resistant signatures</p>
            </div>
          </div>
          <div className="card">
          <div className="form-group">
            <label>Message to Sign</label>
            <textarea
              value={messageToSign}
              onChange={(e) => setMessageToSign(e.target.value)}
              placeholder="Enter any text to sign..."
              rows={4}
            />
          </div>
          <button onClick={handleSignMessage}>
            Sign Message
          </button>

          {signedResult && (
            <div className="sign-result">
              <div className="form-group">
                <label>Original Message</label>
                <textarea readOnly value={signedResult.message} rows={2} />
              </div>
              <div className="form-group">
                <label>Signature (ML-DSA-65, {signedResult.signature.length / 2} bytes)</label>
                <textarea readOnly value={signedResult.signature} rows={6} />
              </div>
              <div className="form-group">
                <label>Your Public Key (for verification)</label>
                <textarea readOnly value={wallet.public_key} rows={4} />
              </div>
              <button
                className="secondary"
                onClick={() => navigator.clipboard.writeText(JSON.stringify({
                  message: signedResult.message,
                  signature: signedResult.signature,
                  public_key: wallet.public_key,
                  address: wallet.address,
                }, null, 2))}
              >
                Copy All (JSON)
              </button>
            </div>
          )}
        </div>
        </>
      )}
      </main>
    </div>
  );
}
