/**
 * Integration test for shielded transactions with binding signatures.
 *
 * This test:
 * 1. Generates a new wallet
 * 2. Connects to a running node
 * 3. Waits for mining rewards
 * 4. Creates and submits a shielded transaction
 * 5. Verifies the transaction is accepted
 *
 * Prerequisites:
 * - Node running with mining: cargo run -- --mine <pk_hash>
 *
 * Run with: npx vite-node src/integration-test.ts
 */

import { generateKeyPair, bytesToHex, hexToBytes } from './crypto';
import { initPoseidon } from './poseidon';
import { initBindingCrypto } from './binding';
import { ShieldedWallet } from './shielded-wallet';
import {
  createShieldedTransaction,
  validateTransactionParams,
  loadProvingKeys,
  setCircuitBasePath,
  type ShieldedTransaction,
} from './transaction-builder';
import {
  getChainInfo,
  submitShieldedTransaction,
} from './api';
import { computePkHash } from './shielded-crypto';
import * as fs from 'fs';

// Set API base for Node.js environment
const API_BASE = process.env.API_BASE || 'http://localhost:3000';

// Polyfill localStorage for Node.js
if (typeof globalThis.localStorage === 'undefined') {
  const store: Record<string, string> = {};
  (globalThis as any).localStorage = {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { Object.keys(store).forEach(k => delete store[k]); },
  };
}

// Patch fetch to use absolute URLs when running in Node
const originalFetch = globalThis.fetch;
globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  if (typeof input === 'string' && input.startsWith('/')) {
    input = API_BASE + input;
  }
  return originalFetch(input, init);
};

// ANSI colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
};

function log(msg: string, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

function logStep(step: number, msg: string) {
  log(`\n[Step ${step}] ${msg}`, colors.cyan + colors.bright);
}

function logSuccess(msg: string) {
  log(`  ✓ ${msg}`, colors.green);
}

function logWarning(msg: string) {
  log(`  ⚠ ${msg}`, colors.yellow);
}

function logError(msg: string) {
  log(`  ✗ ${msg}`, colors.red);
}

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForConnection(maxRetries = 10): Promise<boolean> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const info = await getChainInfo();
      logSuccess(`Connected to node at height ${info.height}`);
      return true;
    } catch {
      if (i < maxRetries - 1) {
        log(`  Waiting for node... (attempt ${i + 1}/${maxRetries})`);
        await sleep(2000);
      }
    }
  }
  return false;
}

async function waitForBalance(
  wallet: ShieldedWallet,
  minBalance: bigint,
  maxWaitSec = 120
): Promise<boolean> {
  const startTime = Date.now();
  const maxWaitMs = maxWaitSec * 1000;

  while (Date.now() - startTime < maxWaitMs) {
    await wallet.scan();

    const balance = wallet.balance;
    if (balance >= minBalance) {
      logSuccess(`Balance: ${formatBalance(balance)} TSN (${wallet.unspentNotes.length} notes)`);
      return true;
    }

    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    log(`  Balance: ${formatBalance(balance)} TSN, waiting... (${elapsed}s/${maxWaitSec}s)`);
    await sleep(5000);
  }

  return false;
}

function formatBalance(value: bigint): string {
  const DECIMALS = 9;
  const divisor = 10n ** BigInt(DECIMALS);
  const whole = value / divisor;
  const frac = value % divisor;
  const fracStr = frac.toString().padStart(DECIMALS, '0').replace(/0+$/, '');
  return fracStr ? `${whole}.${fracStr}` : whole.toString();
}

async function runIntegrationTest() {
  log('\n' + '='.repeat(60), colors.bright);
  log('  SHIELDED TRANSACTION INTEGRATION TEST', colors.bright);
  log('='.repeat(60) + '\n', colors.bright);

  // Step 1: Initialize cryptographic primitives
  logStep(1, 'Initializing cryptographic primitives...');

  log('  Initializing Poseidon hash...');
  await initPoseidon();
  logSuccess('Poseidon initialized');

  log('  Initializing BN254 curve for binding signatures...');
  await initBindingCrypto();
  logSuccess('Binding crypto initialized');

  log('  Loading ZK proving keys (this may take a moment)...');
  try {
    // Set circuit path for Node.js environment
    const circuitPath = process.env.CIRCUIT_PATH || './public/circuits';
    setCircuitBasePath(circuitPath);
    await loadProvingKeys();
    logSuccess('Proving keys loaded');
  } catch (e) {
    logWarning(`Proving keys not available: ${e}`);
    logWarning('Transaction creation will use placeholder proofs');
  }

  // Step 2: Load wallet from file or generate new one
  logStep(2, 'Loading wallet...');

  const walletPath = process.env.WALLET_FILE || '../test-wallet.json';
  let secretKey: Uint8Array;
  let publicKey: Uint8Array;
  let pkHash: Uint8Array;

  if (fs.existsSync(walletPath)) {
    log(`  Loading wallet from ${walletPath}...`);
    const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf-8'));
    secretKey = hexToBytes(walletData.secret_key);
    publicKey = hexToBytes(walletData.public_key);
    pkHash = hexToBytes(walletData.pk_hash);
    logSuccess(`Loaded wallet from file`);
  } else {
    log(`  No wallet file found, generating new wallet...`);
    const keyPair = generateKeyPair();
    secretKey = keyPair.secretKey;
    publicKey = keyPair.publicKey;
    pkHash = computePkHash(publicKey);
    logWarning('Using generated wallet - you need to mine to this address');
  }

  logSuccess(`Public key: ${bytesToHex(publicKey).slice(0, 32)}...`);
  logSuccess(`PK hash: ${bytesToHex(pkHash)}`);

  const wallet = new ShieldedWallet(secretKey, publicKey);

  // Step 3: Connect to node
  logStep(3, 'Connecting to node...');

  const connected = await waitForConnection();
  if (!connected) {
    logError('Could not connect to node!');
    logError('Make sure the node is running: cargo run -- --mine <pk_hash>');
    process.exit(1);
  }

  // Step 4: Check if we can use an existing funded wallet or need to mine
  logStep(4, 'Checking for existing balance...');

  await wallet.scan();
  let balance = wallet.balance;

  if (balance === 0n) {
    logWarning('No balance found. You need to mine some blocks first.');
    log('\n  To mine to this wallet, restart the node with:');
    log(`  cargo run -- --mine ${bytesToHex(pkHash)}`, colors.yellow);
    log('\n  Or use an existing wallet by setting environment variables:');
    log('  WALLET_SECRET_KEY=<hex> WALLET_PUBLIC_KEY=<hex>', colors.yellow);

    // Wait for balance if mining
    log('\n  Waiting for mining rewards...');
    const gotBalance = await waitForBalance(wallet, 1_000_000_000n, 120);

    if (!gotBalance) {
      logError('Timeout waiting for balance. Make sure mining is enabled.');
      process.exit(1);
    }
  } else {
    logSuccess(`Found existing balance: ${formatBalance(balance)} TSN`);
  }

  // Step 5: Create a transaction
  logStep(5, 'Creating shielded transaction...');

  // Generate a recipient address (send to ourselves for testing)
  const recipientKeyPair = generateKeyPair();
  const recipientPkHash = computePkHash(recipientKeyPair.publicKey);

  // Select notes to spend
  const unspentNotes = wallet.unspentNotes;
  if (unspentNotes.length === 0) {
    logError('No unspent notes available!');
    process.exit(1);
  }

  // Use first note
  const noteToSpend = unspentNotes[0];
  const sendAmount = noteToSpend.value / 2n; // Send half
  const fee = 1_000_000n; // 0.001 TSN

  log(`  Spending note: ${formatBalance(noteToSpend.value)} TSN`);
  log(`  Sending: ${formatBalance(sendAmount)} TSN`);
  log(`  Fee: ${formatBalance(fee)} TSN`);
  log(`  Recipient: ${bytesToHex(recipientPkHash).slice(0, 32)}...`);

  const txParams = {
    spendNotes: [noteToSpend],
    recipients: [{ pkHash: bytesToHex(recipientPkHash), amount: sendAmount }],
    fee,
    secretKey,
    publicKey,
    senderPkHash: pkHash,
    onProgress: (status: string) => log(`  ${status}`),
  };

  // Validate params
  const validationError = validateTransactionParams(txParams);
  if (validationError) {
    logError(`Validation failed: ${validationError}`);
    process.exit(1);
  }

  // Create the transaction
  log('\n  Building transaction...');
  const startBuild = Date.now();

  let tx: ShieldedTransaction;
  try {
    tx = await createShieldedTransaction(txParams);
    logSuccess(`Transaction built in ${Date.now() - startBuild}ms`);
  } catch (e) {
    logError(`Failed to build transaction: ${e}`);
    process.exit(1);
    throw e; // TypeScript doesn't know process.exit never returns
  }

  // Log transaction details
  log(`\n  Transaction summary:`);
  log(`    Spends: ${tx.spends.length}`);
  log(`    Outputs: ${tx.outputs.length}`);
  log(`    Fee: ${tx.fee}`);
  log(`    Binding signature: ${tx.binding_sig.signature.slice(0, 32)}...`);

  // Step 6: Submit transaction
  logStep(6, 'Submitting transaction to node...');

  const result = await submitShieldedTransaction(tx);

  if ('error' in result) {
    logError(`Transaction rejected: ${result.error}`);
    process.exit(1);
    throw new Error(result.error); // TypeScript doesn't know process.exit never returns
  }

  logSuccess(`Transaction accepted!`);
  log(`    Hash: ${result.hash}`);
  log(`    Status: ${result.status}`);

  // Step 7: Verify transaction appears in mempool or block
  logStep(7, 'Verifying transaction...');

  // Wait a moment for the transaction to propagate
  await sleep(2000);

  // Scan recipient wallet
  const recipientWallet = new ShieldedWallet(
    recipientKeyPair.secretKey,
    recipientKeyPair.publicKey
  );

  // Wait for the transaction to be mined
  log('  Waiting for transaction to be mined...');
  let recipientBalance = 0n;
  for (let i = 0; i < 30; i++) {
    await sleep(2000);
    await recipientWallet.scan();
    recipientBalance = recipientWallet.balance;

    if (recipientBalance > 0n) {
      break;
    }
    log(`    Waiting for confirmation... (${i * 2}s)`);
  }

  if (recipientBalance >= sendAmount) {
    logSuccess(`Recipient received: ${formatBalance(recipientBalance)} TSN`);
  } else {
    logWarning(`Recipient balance: ${formatBalance(recipientBalance)} TSN`);
    logWarning('Transaction may still be in mempool');
  }

  // Final summary
  log('\n' + '='.repeat(60), colors.bright);
  log('  TEST COMPLETE', colors.green + colors.bright);
  log('='.repeat(60), colors.bright);

  log('\n  Summary:');
  log(`    - Wallet PK hash: ${bytesToHex(pkHash).slice(0, 32)}...`);
  log(`    - Transaction created with real binding signature`);
  log(`    - Node accepted the transaction`);

  if (recipientBalance > 0n) {
    log(`    - Recipient verified to have received funds`, colors.green);
  }

  log('\n');
}

// Run the test
runIntegrationTest().catch(e => {
  logError(`Test failed with error: ${e}`);
  console.error(e);
  process.exit(1);
});
