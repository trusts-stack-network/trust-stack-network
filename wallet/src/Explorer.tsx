import { useState, useEffect, useCallback, useRef } from 'react';
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
  difficulty: number;
  coinbase_reward: number;
}

interface BlockListResponse {
  blocks: Block[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
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

interface PeerData {
  url: string;
  version: string;
  height: number | null;
  latency: number | null;
  status: 'online' | 'offline';
}

interface P2pPeerData {
  peer_id: string;
  height: number | null;
  protocol: string;
}

type ExplorerTab = 'explorer' | 'network';

type DetailView =
  | { type: 'none' }
  | { type: 'block'; data: BlockDetail }
  | { type: 'transaction'; data: Transaction }

const COIN = 1_000_000_000;
const BLOCKS_PER_PAGE = 50;

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
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalBlocks, setTotalBlocks] = useState(0);
  const [goToHeight, setGoToHeight] = useState('');
  const autoRefreshRef = useRef(true);
  const [activeTab, setActiveTab] = useState<ExplorerTab>('explorer');
  const [peers, setPeers] = useState<PeerData[]>([]);
  const [p2pPeers, setP2pPeers] = useState<P2pPeerData[]>([]);
  const [nodeInfo, setNodeInfo] = useState<{ version: string; peer_id: string; role: string } | null>(null);
  const [networkLoading, setNetworkLoading] = useState(false);

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

  const fetchBlocks = useCallback(async (page: number) => {
    try {
      const res = await fetch(`/blocks/list?page=${page}&limit=${BLOCKS_PER_PAGE}`);
      if (res.ok) {
        const data: BlockListResponse = await res.json();
        setBlocks(data.blocks);
        setTotalPages(data.total_pages);
        setTotalBlocks(data.total);
      }
    } catch (e) {
      console.error('Failed to fetch blocks:', e);
    }
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [infoRes, mempoolRes, txRes] = await Promise.all([
        fetch('/chain/info'),
        fetch('/mempool'),
        fetch('/transactions/recent'),
      ]);
      const info: ChainInfo = await infoRes.json();
      setChainInfo(info);
      const mempool = await mempoolRes.json();
      setMempoolCount(mempool.count);
      const txs: Transaction[] = await txRes.json();
      setTransactions(txs);
    } catch (e) {
      console.error('Failed to fetch data:', e);
    }
  }, []);

  const fetchNetworkData = useCallback(async () => {
    setNetworkLoading(true);
    try {
      // Fetch node info
      const infoRes = await fetch('/node/info');
      if (infoRes.ok) {
        const info = await infoRes.json();
        setNodeInfo({ version: info.version, peer_id: info.peer_id, role: info.role });
      }

      // Fetch HTTP peers list
      const peersRes = await fetch('/peers');
      if (peersRes.ok) {
        const data = await peersRes.json();
        const peerUrls: string[] = data.peers || [];
        // For each peer, fetch their node/info to get version
        const peerResults = await Promise.all(
          peerUrls.map(async (url) => {
            const start = Date.now();
            try {
              const res = await fetch(`${url}/node/info`, { signal: AbortSignal.timeout(5000) });
              const latency = Date.now() - start;
              if (res.ok) {
                const info = await res.json();
                return {
                  url,
                  version: info.version || 'unknown',
                  height: info.height ?? null,
                  latency,
                  status: 'online' as const,
                };
              }
            } catch { /* offline */ }
            return { url, version: 'unknown', height: null, latency: null, status: 'offline' as const };
          })
        );
        setPeers(peerResults);
      }

      // Fetch P2P peers
      const p2pRes = await fetch('/peers/p2p');
      if (p2pRes.ok) {
        const data = await p2pRes.json();
        setP2pPeers(data.peers || []);
      }
    } catch (e) {
      console.error('Failed to fetch network data:', e);
    }
    setNetworkLoading(false);
  }, []);

  // Initial load + auto-refresh
  useEffect(() => {
    fetchData();
    fetchBlocks(currentPage);
    const interval = setInterval(() => {
      fetchData();
      // Only auto-refresh blocks on page 1
      if (autoRefreshRef.current) {
        fetchBlocks(currentPage);
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchData, fetchBlocks, currentPage]);

  // Load network data when tab switches to network
  useEffect(() => {
    if (activeTab === 'network') {
      fetchNetworkData();
      const interval = setInterval(fetchNetworkData, 30000);
      return () => clearInterval(interval);
    }
  }, [activeTab, fetchNetworkData]);

  // Track if on page 1 for auto-refresh
  useEffect(() => {
    autoRefreshRef.current = currentPage === 1;
  }, [currentPage]);

  const goToPage = (page: number) => {
    const p = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(p);
    fetchBlocks(p);
  };

  const handleGoToHeight = () => {
    const height = parseInt(goToHeight, 10);
    if (!isNaN(height) && height >= 0 && totalBlocks > 0) {
      // Calculate which page contains this height
      const maxHeight = totalBlocks - 1;
      const clampedHeight = Math.max(0, Math.min(height, maxHeight));
      const offset = maxHeight - clampedHeight;
      const page = Math.floor(offset / BLOCKS_PER_PAGE) + 1;
      goToPage(page);
      setGoToHeight('');
    }
  };

  const handleSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const query = search.trim();
      if (/^\d+$/.test(query)) {
        // Numeric = go to block height
        fetchBlockByHeight(parseInt(query, 10));
      } else if (query.length === 64) {
        fetchBlockDetail(query);
      } else if (query.length === 40) {
        window.location.href = `/account/${query}`;
      }
    }
  };

  // Generate page numbers to display
  const getPageNumbers = (): (number | '...')[] => {
    const pages: (number | '...')[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) pages.push('...');
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) pages.push(i);
      if (currentPage < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

  return (
    <div className="app">
      <header className="app-header">
        <Link to="/" className="logo">
          <img src="/logo.png" alt="TSN" className="logo-img" />
          <span>TSN</span>
        </Link>
        <nav className="main-nav">
          <a
            href="#"
            className={activeTab === 'explorer' ? 'active' : ''}
            onClick={(e) => { e.preventDefault(); setActiveTab('explorer'); }}
          >Explorer</a>
          <a
            href="#"
            className={activeTab === 'network' ? 'active' : ''}
            onClick={(e) => { e.preventDefault(); setActiveTab('network'); }}
          >Network</a>
          <Link to="/wallet">Wallet</Link>
        </nav>
      </header>

      <main className="container">
      {activeTab === 'network' ? (
        <div className="network-tab">
          <div className="card" style={{ marginBottom: 24 }}>
            <h2 style={{ marginBottom: 16 }}>Node Info</h2>
            {nodeInfo ? (
              <div className="stats-grid">
                <div className="stat">
                  <div className="stat-value" style={{ fontSize: '1.5rem' }}>v{nodeInfo.version}</div>
                  <div className="stat-label">Version</div>
                </div>
                <div className="stat">
                  <div className="stat-value" style={{ fontSize: '1.5rem' }}>{nodeInfo.role}</div>
                  <div className="stat-label">Role</div>
                </div>
                <div className="stat">
                  <div className="stat-value" style={{ fontSize: '1.5rem' }}>{peers.filter(p => p.status === 'online').length}</div>
                  <div className="stat-label">HTTP Peers</div>
                </div>
                <div className="stat">
                  <div className="stat-value" style={{ fontSize: '1.5rem' }}>{p2pPeers.length}</div>
                  <div className="stat-label">P2P Peers</div>
                </div>
                <div className="stat">
                  <div className="stat-value" style={{ fontSize: '1.5rem' }}>{chainInfo?.height ?? '-'}</div>
                  <div className="stat-label">Height</div>
                </div>
              </div>
            ) : (
              <div className="loading">Loading...</div>
            )}
          </div>

          <h2>HTTP Peers</h2>
          <div className="card" style={{ marginBottom: 24 }}>
            {networkLoading && peers.length === 0 ? (
              <div className="loading" style={{ padding: 20 }}>Loading peers...</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Version</th>
                    <th>Height</th>
                    <th>Latency</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {peers.map((peer) => (
                    <tr key={peer.url}>
                      <td className="hash" style={{ fontSize: '0.8rem' }}>{peer.url}</td>
                      <td>
                        <span className={`badge ${peer.version === nodeInfo?.version ? 'confirmed' : peer.version === 'unknown' ? 'pending' : 'pending'}`}>
                          v{peer.version}
                        </span>
                      </td>
                      <td>{peer.height ?? '-'}</td>
                      <td>{peer.latency !== null ? `${peer.latency}ms` : '-'}</td>
                      <td>
                        <span className={`badge ${peer.status === 'online' ? 'confirmed' : 'pending'}`}>
                          {peer.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {peers.length === 0 && (
                    <tr><td colSpan={5} className="loading">No peers connected</td></tr>
                  )}
                </tbody>
              </table>
            )}
          </div>

          {p2pPeers.length > 0 && (
            <>
              <h2>P2P Peers (libp2p)</h2>
              <div className="card">
                <table>
                  <thead>
                    <tr>
                      <th>Peer ID</th>
                      <th>Protocol</th>
                      <th>Height</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p2pPeers.map((peer) => (
                      <tr key={peer.peer_id}>
                        <td className="hash" style={{ fontSize: '0.8rem' }}>{peer.peer_id.substring(0, 24)}...</td>
                        <td>
                          <span className={`badge confirmed`}>
                            {peer.protocol}
                          </span>
                        </td>
                        <td>{peer.height ?? '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      ) : (
        <>
        <input
        type="text"
        className="search"
        placeholder="Search by block height, hash, or address..."
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

      <div className="blocks-header">
        <h2>Blocks</h2>
        <div className="blocks-jump">
          <input
            type="text"
            className="jump-input"
            placeholder="Go to height..."
            value={goToHeight}
            onChange={(e) => setGoToHeight(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleGoToHeight()}
          />
          <button className="jump-btn" onClick={handleGoToHeight}>Go</button>
        </div>
      </div>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Height</th>
              <th>Hash</th>
              <th>Txs</th>
              <th>Reward</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {blocks.length === 0 ? (
              <tr><td colSpan={5} className="loading">Loading...</td></tr>
            ) : (
              blocks.map((b) => (
                <tr key={b.hash} className="clickable" onClick={() => handleBlockClick(b)}>
                  <td className="height-cell">{b.height}</td>
                  <td className="hash">{b.hash.substring(0, 16)}...</td>
                  <td>{b.tx_count}</td>
                  <td>{formatAmount(b.coinbase_reward)} TSN</td>
                  <td>{new Date(b.timestamp * 1000).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="pagination">
          <button
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => goToPage(1)}
            title="First page (latest blocks)"
          >&#171; First</button>
          <button
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => goToPage(currentPage - 1)}
          >&#8249; Prev</button>

          <div className="page-numbers">
            {getPageNumbers().map((p, i) =>
              p === '...' ? (
                <span key={`ellipsis-${i}`} className="page-ellipsis">...</span>
              ) : (
                <button
                  key={p}
                  className={`page-num ${p === currentPage ? 'active' : ''}`}
                  onClick={() => goToPage(p)}
                >{p}</button>
              )
            )}
          </div>

          <button
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => goToPage(currentPage + 1)}
          >Next &#8250;</button>
          <button
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => goToPage(totalPages)}
            title="Last page (genesis)"
          >Last &#187;</button>

          <span className="page-info">
            Page {currentPage} / {totalPages} ({totalBlocks} blocks)
          </span>
        </div>
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

      {/* Detail Modal — rendered outside tab content so it overlays everything */}
      </>
      )}
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
