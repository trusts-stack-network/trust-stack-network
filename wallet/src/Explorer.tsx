import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import './Explorer.css';

interface ChainInfo {
  height: number;
  difficulty: number;
  commitment_count: number;
  nullifier_count: number;
}

interface Block {
  height: number;
  hash: string;
  tx_count: number;
  timestamp: number;
}

interface BlockDetail {
  hash: string;
  height: number;
  prev_hash: string;
  timestamp: number;
  difficulty: number;
  nonce: number;
  tx_count: number;
  commitment_root: string;
  nullifier_root: string;
  transactions: string[];
  coinbase_reward: number;
  total_fees: number;
}

interface Transaction {
  hash: string;
  fee: number;
  spend_count: number;
  output_count: number;
  status: 'pending' | 'confirmed';
  block_height: number | null;
}

type DetailView =
  | { type: 'none' }
  | { type: 'block'; data: BlockDetail }
  | { type: 'transaction'; data: Transaction }

const COIN = 1_000_000_000;

function formatAmount(amount: number): string {
  return (amount / COIN).toFixed(2);
}

export default function Explorer() {
  const [chainInfo, setChainInfo] = useState<ChainInfo | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [mempoolCount, setMempoolCount] = useState(0);
  const [search, setSearch] = useState('');
  const [detailView, setDetailView] = useState<DetailView>({ type: 'none' });
  const [loading, setLoading] = useState(false);

  const fetchBlockDetail = async (hash: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/block/${hash}`);
      if (res.ok) {
        const data: BlockDetail = await res.json();
        setDetailView({ type: 'block', data });
      }
    } catch (e) {
      console.error('Failed to fetch block:', e);
    }
    setLoading(false);
  };

  const fetchBlockByHeight = async (height: number) => {
    setLoading(true);
    try {
      const res = await fetch(`/block/height/${height}`);
      if (res.ok) {
        const data: BlockDetail = await res.json();
        setDetailView({ type: 'block', data });
      }
    } catch (e) {
      console.error('Failed to fetch block:', e);
    }
    setLoading(false);
  };

  const handleBlockClick = (block: Block) => {
    fetchBlockDetail(block.hash);
  };

  const handleTransactionClick = (tx: Transaction) => {
    setDetailView({ type: 'transaction', data: tx });
  };

  const closeDetail = () => {
    setDetailView({ type: 'none' });
  };

  const fetchData = useCallback(async () => {
    try {
      // Fetch chain info
      const infoRes = await fetch('/chain/info');
      const info: ChainInfo = await infoRes.json();
      setChainInfo(info);

      // Fetch mempool
      const mempoolRes = await fetch('/mempool');
      const mempool = await mempoolRes.json();
      setMempoolCount(mempool.count);

      // Fetch recent blocks
      const fetchedBlocks: Block[] = [];
      for (let h = info.height; h >= Math.max(0, info.height - 9); h--) {
        const blockRes = await fetch(`/block/height/${h}`);
        if (blockRes.ok) {
          fetchedBlocks.push(await blockRes.json());
        }
      }
      setBlocks(fetchedBlocks);

      // Fetch recent transactions (privacy-preserving: only shows fees, not amounts)
      const txRes = await fetch('/transactions/recent');
      const txs: Transaction[] = await txRes.json();
      setTransactions(txs);
    } catch (e) {
      console.error('Failed to fetch data:', e);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const query = search.trim();
      if (query.length === 64) {
        window.location.href = `/block/${query}`;
      } else if (query.length === 40) {
        window.location.href = `/account/${query}`;
      }
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <Link to="/" className="logo">
          <img src="/logo.png" alt="TSN" className="logo-img" />
          <span>TSN</span>
        </Link>
        <nav className="main-nav">
          <Link to="/explorer" className="active">Explorer</Link>
          <Link to="/wallet">Wallet</Link>
        </nav>
      </header>

      <main className="container">
        <input
        type="text"
        className="search"
        placeholder="Search by block hash or address..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        onKeyPress={handleSearch}
      />

      <div className="card">
        <div className="stats-grid">
          <div className="stat">
            <div className="stat-value">{chainInfo?.height ?? '-'}</div>
            <div className="stat-label">Block Height</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.difficulty ?? '-'}</div>
            <div className="stat-label">Difficulty</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.commitment_count ?? '-'}</div>
            <div className="stat-label">Commitments</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.nullifier_count ?? '-'}</div>
            <div className="stat-label">Nullifiers</div>
          </div>
          <div className="stat">
            <div className="stat-value">{mempoolCount}</div>
            <div className="stat-label">Pending Txs</div>
          </div>
        </div>
      </div>

      <h2>Recent Blocks</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Height</th>
              <th>Hash</th>
              <th>Transactions</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {blocks.length === 0 ? (
              <tr><td colSpan={4} className="loading">Loading...</td></tr>
            ) : (
              blocks.map((b) => (
                <tr key={b.hash} className="clickable" onClick={() => handleBlockClick(b)}>
                  <td>{b.height}</td>
                  <td className="hash">{b.hash.substring(0, 16)}...</td>
                  <td>{b.tx_count}</td>
                  <td>{new Date(b.timestamp * 1000).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h2>Recent Transactions</h2>
      <p className="privacy-note">Transaction amounts and addresses are private. Only fees are visible.</p>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Hash</th>
              <th>Spends</th>
              <th>Outputs</th>
              <th>Fee</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {transactions.length === 0 ? (
              <tr><td colSpan={5} className="loading">No transactions yet</td></tr>
            ) : (
              transactions.map((tx) => (
                <tr key={tx.hash} className="clickable" onClick={() => handleTransactionClick(tx)}>
                  <td className="hash">{tx.hash.substring(0, 16)}...</td>
                  <td>{tx.spend_count}</td>
                  <td>{tx.output_count}</td>
                  <td>{formatAmount(tx.fee)} TSN</td>
                  <td>
                    <span className={`badge ${tx.status}`}>
                      {tx.status}{tx.block_height !== null ? ` #${tx.block_height}` : ''}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="card info-card">
        <h3>Privacy Notice</h3>
        <p>
          This is a shielded blockchain. Account balances, transaction amounts, and
          sender/receiver addresses are encrypted and not visible on-chain.
        </p>
        <p>
          Only you can see your balance by decrypting your notes with your private key.
        </p>
      </div>

      {/* Detail Modal */}
      {detailView.type !== 'none' && (
        <div className="modal-overlay" onClick={closeDetail}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={closeDetail}>&times;</button>

            {loading ? (
              <div className="modal-loading">Loading...</div>
            ) : detailView.type === 'block' ? (
              <div className="block-detail">
                <h2>Block #{detailView.data.height}</h2>

                <div className="detail-section">
                  <h3>Overview</h3>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">Height</span>
                      <span className="detail-value">{detailView.data.height}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Timestamp</span>
                      <span className="detail-value">{new Date(detailView.data.timestamp * 1000).toLocaleString()}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Transactions</span>
                      <span className="detail-value">{detailView.data.tx_count}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Difficulty</span>
                      <span className="detail-value">{detailView.data.difficulty}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Nonce</span>
                      <span className="detail-value">{detailView.data.nonce}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Coinbase Reward</span>
                      <span className="detail-value">{formatAmount(detailView.data.coinbase_reward)} TSN</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Total Fees</span>
                      <span className="detail-value">{formatAmount(detailView.data.total_fees)} TSN</span>
                    </div>
                  </div>
                </div>

                <div className="detail-section">
                  <h3>Hashes</h3>
                  <div className="hash-item">
                    <span className="hash-label">Block Hash</span>
                    <code className="hash-value">{detailView.data.hash}</code>
                  </div>
                  <div className="hash-item">
                    <span className="hash-label">Previous Block</span>
                    <code className="hash-value clickable-hash" onClick={() => fetchBlockDetail(detailView.data.prev_hash)}>
                      {detailView.data.prev_hash}
                    </code>
                  </div>
                  <div className="hash-item">
                    <span className="hash-label">Commitment Root</span>
                    <code className="hash-value">{detailView.data.commitment_root}</code>
                  </div>
                  <div className="hash-item">
                    <span className="hash-label">Nullifier Root</span>
                    <code className="hash-value">{detailView.data.nullifier_root}</code>
                  </div>
                </div>

                {detailView.data.transactions.length > 0 && (
                  <div className="detail-section">
                    <h3>Transactions ({detailView.data.transactions.length})</h3>
                    <div className="tx-list">
                      {detailView.data.transactions.map((txHash, i) => (
                        <div key={txHash} className="tx-list-item">
                          <span className="tx-index">{i + 1}</span>
                          <code className="hash-value">{txHash}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : detailView.type === 'transaction' ? (
              <div className="tx-detail">
                <h2>Transaction Details</h2>

                <div className="detail-section">
                  <h3>Overview</h3>
                  <div className="hash-item">
                    <span className="hash-label">Transaction Hash</span>
                    <code className="hash-value">{detailView.data.hash}</code>
                  </div>
                </div>

                <div className="detail-section">
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">Status</span>
                      <span className={`badge ${detailView.data.status}`}>
                        {detailView.data.status}
                      </span>
                    </div>
                    {detailView.data.block_height !== null && (
                      <div className="detail-item">
                        <span className="detail-label">Block Height</span>
                        <span className="detail-value clickable-link" onClick={() => fetchBlockByHeight(detailView.data.block_height!)}>
                          #{detailView.data.block_height}
                        </span>
                      </div>
                    )}
                    <div className="detail-item">
                      <span className="detail-label">Fee</span>
                      <span className="detail-value">{formatAmount(detailView.data.fee)} TSN</span>
                    </div>
                  </div>
                </div>

                <div className="detail-section">
                  <h3>Inputs & Outputs</h3>
                  <div className="io-visual">
                    <div className="io-box inputs">
                      <div className="io-header">Spends (Inputs)</div>
                      <div className="io-count">{detailView.data.spend_count}</div>
                      <div className="io-desc">shielded inputs</div>
                    </div>
                    <div className="io-arrow">→</div>
                    <div className="io-box outputs">
                      <div className="io-header">Outputs</div>
                      <div className="io-count">{detailView.data.output_count}</div>
                      <div className="io-desc">shielded outputs</div>
                    </div>
                  </div>
                </div>

                <div className="detail-section privacy-info">
                  <p>
                    Transaction amounts and addresses are encrypted. Only the fee is publicly visible.
                  </p>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
      </main>
    </div>
  );
}
