/**
 * Compact warmup toast notification.
 *
 * A smaller, less intrusive version of the warmup card that can be
 * displayed as a toast or inline status indicator.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  startBackgroundWarmup,
  getWarmupProgress,
  isWarmupInProgress,
  wasWarmupCompleted,
  type WarmupProgress,
} from '../prover-pq';

interface WarmupToastProps {
  /** Maximum spends to warm up (default: 5) */
  maxSpends?: number;
  /** Maximum outputs to warm up (default: 2) */
  maxOutputs?: number;
  /** Auto-start warmup on mount (default: true) */
  autoStart?: boolean;
  /** Auto-hide after completion (ms, 0 = don't hide) */
  autoHideDelay?: number;
  /** Callback when warmup completes */
  onComplete?: (circuitsBuilt: number) => void;
  /** Callback when toast is dismissed */
  onDismiss?: () => void;
  /** Position on screen */
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left';
  /** Hide entirely for returning users (default: true) */
  hideForReturningUsers?: boolean;
}

export default function WarmupToast({
  maxSpends = 5,
  maxOutputs = 2,
  autoStart = true,
  autoHideDelay = 3000,
  onComplete,
  onDismiss,
  position = 'bottom-right',
  hideForReturningUsers = true,
}: WarmupToastProps) {
  const [progress, setProgress] = useState<WarmupProgress | null>(null);
  const [visible, setVisible] = useState(true);
  const [started, setStarted] = useState(false);
  const [isReturningUser] = useState(() => wasWarmupCompleted(maxSpends, maxOutputs));

  const startWarmup = useCallback(async () => {
    if (started || isWarmupInProgress()) {
      setProgress(getWarmupProgress());
      return;
    }

    setStarted(true);

    try {
      const circuitsBuilt = await startBackgroundWarmup({
        maxSpends,
        maxOutputs,
        onProgress: setProgress,
        skipIfCached: false,
      });
      onComplete?.(circuitsBuilt);

      // Auto-hide after completion
      if (autoHideDelay > 0) {
        setTimeout(() => {
          setVisible(false);
          onDismiss?.();
        }, autoHideDelay);
      }
    } catch (e) {
      console.error('Warmup failed:', e);
    }
  }, [maxSpends, maxOutputs, started, onComplete, onDismiss, autoHideDelay]);

  useEffect(() => {
    if (autoStart) {
      if (isReturningUser) {
        // For returning users, warm up silently and don't show toast
        startBackgroundWarmup({
          maxSpends,
          maxOutputs,
          skipIfCached: true,
        }).then(onComplete);
        if (hideForReturningUsers) {
          setVisible(false);
        }
      } else {
        startWarmup();
      }
    }
  }, [autoStart, isReturningUser, hideForReturningUsers, maxSpends, maxOutputs, startWarmup, onComplete]);

  if (!visible || (!started && !autoStart) || (isReturningUser && hideForReturningUsers)) {
    return null;
  }

  const positionStyles = getPositionStyles(position);

  return (
    <div style={{ ...styles.toast, ...positionStyles }}>
      {/* Progress indicator */}
      <div style={styles.progressRing}>
        {progress?.done ? (
          <CheckIcon />
        ) : (
          <CircularProgress percent={progress?.percent || 0} />
        )}
      </div>

      {/* Text */}
      <div style={styles.content}>
        <span style={styles.label}>
          {progress?.done ? 'Circuits ready' : 'Warming up circuits'}
        </span>
        {!progress?.done && (
          <span style={styles.detail}>
            {progress?.currentShape} ({progress?.percent || 0}%)
          </span>
        )}
      </div>

      {/* Dismiss button */}
      <button
        onClick={() => {
          setVisible(false);
          onDismiss?.();
        }}
        style={styles.dismissButton}
        aria-label="Dismiss"
      >
        <CloseIcon />
      </button>
    </div>
  );
}

function CircularProgress({ percent }: { percent: number }) {
  const radius = 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percent / 100) * circumference;

  return (
    <svg width="24" height="24" viewBox="0 0 24 24">
      <circle
        cx="12"
        cy="12"
        r={radius}
        fill="none"
        stroke="#3a3a5a"
        strokeWidth="2"
      />
      <circle
        cx="12"
        cy="12"
        r={radius}
        fill="none"
        stroke="#8b5cf6"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 12 12)"
        style={{ transition: 'stroke-dashoffset 0.3s ease' }}
      />
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

function CloseIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
      <path d="M13 1L1 13M1 1l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function getPositionStyles(position: string): React.CSSProperties {
  const base = { position: 'fixed' as const, zIndex: 1000 };
  switch (position) {
    case 'top-right':
      return { ...base, top: 16, right: 16 };
    case 'top-left':
      return { ...base, top: 16, left: 16 };
    case 'bottom-left':
      return { ...base, bottom: 16, left: 16 };
    case 'bottom-right':
    default:
      return { ...base, bottom: 16, right: 16 };
  }
}

const styles: Record<string, React.CSSProperties> = {
  toast: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    backgroundColor: '#1a1a2e',
    borderRadius: '10px',
    border: '1px solid #2a2a4a',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    animation: 'slideIn 0.3s ease',
  },
  progressRing: {
    flexShrink: 0,
  },
  content: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  label: {
    fontSize: '13px',
    fontWeight: 500,
    color: '#f0f0f0',
  },
  detail: {
    fontSize: '11px',
    color: '#808090',
  },
  dismissButton: {
    background: 'none',
    border: 'none',
    padding: '4px',
    cursor: 'pointer',
    color: '#606070',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
};

// Add keyframes via style tag
if (typeof document !== 'undefined') {
  const styleId = 'warmup-toast-styles';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      @keyframes slideIn {
        from {
          opacity: 0;
          transform: translateY(10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }
    `;
    document.head.appendChild(style);
  }
}
