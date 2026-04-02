/**
 * Warmup progress card component.
 *
 * Displays the status of Plonky2 circuit warmup with a friendly explanation
 * of what's happening and why it's important.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  startBackgroundWarmup,
  getWarmupProgress,
  isWarmupInProgress,
  wasWarmupCompleted,
  getWarmupCompletedAt,
  type WarmupProgress,
} from '../prover-pq';

interface WarmupCardProps {
  /** Maximum spends to warm up (default: 5) */
  maxSpends?: number;
  /** Maximum outputs to warm up (default: 2) */
  maxOutputs?: number;
  /** Auto-start warmup on mount (default: true) */
  autoStart?: boolean;
  /** Callback when warmup completes */
  onComplete?: (circuitsBuilt: number) => void;
  /** Whether to show the card even after completion (default: false) */
  showWhenComplete?: boolean;
  /** Hide card entirely for returning users (default: true) */
  hideForReturningUsers?: boolean;
  /** Custom className for styling */
  className?: string;
}

export default function WarmupCard({
  maxSpends = 5,
  maxOutputs = 2,
  autoStart = true,
  onComplete,
  showWhenComplete = false,
  hideForReturningUsers = true,
  className = '',
}: WarmupCardProps) {
  const [progress, setProgress] = useState<WarmupProgress | null>(null);
  const [started, setStarted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReturningUser, setIsReturningUser] = useState(false);
  const [lastWarmupDate, setLastWarmupDate] = useState<Date | null>(null);

  // Check if this is a returning user on mount
  useEffect(() => {
    const wasCached = wasWarmupCompleted(maxSpends, maxOutputs);
    setIsReturningUser(wasCached);
    if (wasCached) {
      setLastWarmupDate(getWarmupCompletedAt());
    }
  }, [maxSpends, maxOutputs]);

  const startWarmup = useCallback(async () => {
    if (started || isWarmupInProgress()) {
      // Already started, just sync state
      setProgress(getWarmupProgress());
      return;
    }

    setStarted(true);
    setError(null);

    try {
      const circuitsBuilt = await startBackgroundWarmup({
        maxSpends,
        maxOutputs,
        onProgress: setProgress,
        skipIfCached: false, // We handle caching at the UI level
      });
      onComplete?.(circuitsBuilt);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Warmup failed');
    }
  }, [maxSpends, maxOutputs, started, onComplete]);

  useEffect(() => {
    if (autoStart) {
      // For returning users, warmup silently in background
      if (isReturningUser) {
        startBackgroundWarmup({
          maxSpends,
          maxOutputs,
          skipIfCached: true, // Will run silently since cached
        }).then(onComplete);
      } else {
        startWarmup();
      }
    }
  }, [autoStart, isReturningUser, maxSpends, maxOutputs, startWarmup, onComplete]);

  // Don't render for returning users if hideForReturningUsers is true
  if (isReturningUser && hideForReturningUsers) {
    return null;
  }

  // Don't render if complete and showWhenComplete is false
  if (progress?.done && !showWhenComplete && !isReturningUser) {
    return null;
  }

  // Don't render if not started and not auto-starting
  if (!started && !autoStart && !isReturningUser) {
    return (
      <div className={`warmup-card warmup-card--idle ${className}`} style={styles.card}>
        <button onClick={startWarmup} style={styles.startButton}>
          Start Circuit Warmup
        </button>
      </div>
    );
  }

  // Show "already warmed" state for returning users if showWhenComplete is true
  if (isReturningUser && showWhenComplete) {
    return (
      <div className={`warmup-card warmup-card--cached ${className}`} style={styles.card}>
        <div style={styles.header}>
          <div style={styles.iconContainer}>
            <CheckIcon />
          </div>
          <div style={styles.headerText}>
            <h3 style={styles.title}>Circuits Ready</h3>
            <p style={styles.subtitle}>
              {lastWarmupDate
                ? `Last warmed ${formatRelativeTime(lastWarmupDate)}`
                : 'Previously warmed'}
            </p>
          </div>
        </div>
        <div style={styles.explanation}>
          <InfoIcon />
          <p style={styles.explanationText}>
            Your wallet remembered the circuit warmup from your last visit.
            Transactions will be fast and quantum-resistant.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={`warmup-card ${progress?.done ? 'warmup-card--complete' : 'warmup-card--loading'} ${className}`} style={styles.card}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.iconContainer}>
          {progress?.done ? (
            <CheckIcon />
          ) : (
            <SpinnerIcon />
          )}
        </div>
        <div style={styles.headerText}>
          <h3 style={styles.title}>
            {progress?.done ? 'Ready to Send' : 'Preparing Quantum-Safe Proofs'}
          </h3>
          <p style={styles.subtitle}>
            {progress?.done
              ? 'All circuits are ready for fast transactions'
              : `Building circuit ${progress?.currentShape || '...'}`}
          </p>
        </div>
      </div>

      {/* Progress bar */}
      {!progress?.done && (
        <div style={styles.progressContainer}>
          <div style={styles.progressBar}>
            <div
              style={{
                ...styles.progressFill,
                width: `${progress?.percent || 0}%`,
              }}
            />
          </div>
          <div style={styles.progressText}>
            <span>{progress?.completed || 0} / {progress?.total || '?'} circuits</span>
            <span>
              {progress?.estimatedSecondsRemaining
                ? `~${formatTime(progress.estimatedSecondsRemaining)} remaining`
                : 'Calculating...'}
            </span>
          </div>
        </div>
      )}

      {/* Explanation */}
      <div style={styles.explanation}>
        <InfoIcon />
        <p style={styles.explanationText}>
          {progress?.done ? (
            <>
              Your wallet is now optimized for fast, quantum-resistant transactions.
              Sending funds will be quick and secure.
            </>
          ) : (
            <>
              We're pre-building cryptographic circuits so your transactions are instant.
              This only happens once and runs in the background.
              <strong> You can still use the wallet while this completes.</strong>
            </>
          )}
        </p>
      </div>

      {/* Error state */}
      {error && (
        <div style={styles.error}>
          <span>Error: {error}</span>
          <button onClick={startWarmup} style={styles.retryButton}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}

// Helper to format seconds as "Xm Ys"
function formatTime(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
}

// Helper to format relative time (e.g., "2 hours ago")
function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffDays > 0) {
    return diffDays === 1 ? 'yesterday' : `${diffDays} days ago`;
  }
  if (diffHours > 0) {
    return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
  }
  if (diffMins > 0) {
    return diffMins === 1 ? '1 minute ago' : `${diffMins} minutes ago`;
  }
  return 'just now';
}

// Simple SVG icons
function SpinnerIcon() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      style={{ animation: 'spin 1s linear infinite' }}
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="31.4 31.4"
        opacity="0.3"
      />
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="31.4 31.4"
        strokeDashoffset="23.55"
      />
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" fill="#22c55e" />
      <path
        d="M8 12l2.5 2.5L16 9"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" opacity="0.6">
      <path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 3a1 1 0 110 2 1 1 0 010-2zm2 8H6v-1h1V8H6V7h3v4h1v1z" />
    </svg>
  );
}

// Inline styles (can be replaced with CSS/Tailwind)
const styles: Record<string, React.CSSProperties> = {
  card: {
    backgroundColor: '#1a1a2e',
    borderRadius: '12px',
    padding: '16px',
    border: '1px solid #2a2a4a',
    maxWidth: '400px',
    fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  header: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '12px',
    marginBottom: '12px',
  },
  iconContainer: {
    color: '#8b5cf6',
    flexShrink: 0,
  },
  headerText: {
    flex: 1,
    minWidth: 0,
  },
  title: {
    margin: 0,
    fontSize: '16px',
    fontWeight: 600,
    color: '#f0f0f0',
  },
  subtitle: {
    margin: '4px 0 0 0',
    fontSize: '13px',
    color: '#a0a0b0',
  },
  progressContainer: {
    marginBottom: '12px',
  },
  progressBar: {
    height: '6px',
    backgroundColor: '#2a2a4a',
    borderRadius: '3px',
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#8b5cf6',
    borderRadius: '3px',
    transition: 'width 0.3s ease',
  },
  progressText: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px',
    color: '#808090',
    marginTop: '6px',
  },
  explanation: {
    display: 'flex',
    gap: '8px',
    padding: '10px',
    backgroundColor: '#12121f',
    borderRadius: '8px',
    alignItems: 'flex-start',
  },
  explanationText: {
    margin: 0,
    fontSize: '12px',
    lineHeight: 1.5,
    color: '#a0a0b0',
  },
  error: {
    marginTop: '12px',
    padding: '10px',
    backgroundColor: '#2d1f1f',
    borderRadius: '8px',
    color: '#f87171',
    fontSize: '13px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  retryButton: {
    padding: '4px 12px',
    backgroundColor: '#7c3aed',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '12px',
  },
  startButton: {
    width: '100%',
    padding: '12px',
    backgroundColor: '#7c3aed',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 500,
  },
};
