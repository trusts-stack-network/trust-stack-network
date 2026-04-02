import { useState, useEffect, useCallback } from 'react';
import { getFaucetStatus, claimFromFaucetGame, getFaucetStats } from '../api';
import type { FaucetStatusResponse, ClaimResponse, FaucetStatsResponse } from '../api';
import { FaucetGame } from './FaucetGame';
import './Faucet.css';

interface FaucetProps {
  pkHash: string;
}

type FaucetMode = 'default' | 'game';

export default function Faucet({ pkHash }: FaucetProps) {
  const [status, setStatus] = useState<FaucetStatusResponse | null>(null);
  const [stats, setStats] = useState<FaucetStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [claiming, setClaiming] = useState(false);
  const [showCelebration, setShowCelebration] = useState(false);
  const [claimResult, setClaimResult] = useState<ClaimResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [countdown, setCountdown] = useState(0);
  const [mode, setMode] = useState<FaucetMode>('default');

  // Fetch faucet status
  const fetchStatus = useCallback(async () => {
    try {
      const statsData = await getFaucetStats();
      setStats(statsData);

      if (!statsData.enabled) {
        setError(null);
        setLoading(false);
        return;
      }

      const statusData = await getFaucetStatus(pkHash);
      setStatus(statusData);
      setCountdown(statusData.seconds_until_eligible);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [pkHash]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Countdown timer
  useEffect(() => {
    if (countdown <= 0) return;

    const interval = setInterval(() => {
      setCountdown((prev) => {
        const next = prev - 1;
        if (next <= 0) {
          fetchStatus();
        }
        return Math.max(0, next);
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [countdown, fetchStatus]);

  const formatCountdown = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getProgress = (): number => {
    if (!status) return 0;
    if (status.can_claim) return 100;
    const total = 86400;
    const elapsed = total - status.seconds_until_eligible;
    return (elapsed / total) * 100;
  };

  const renderFlames = (streak: number): React.ReactElement[] => {
    const maxFlames = 7;
    const flames = Math.min(streak, maxFlames);
    return Array.from({ length: flames }, (_, i) => (
      <span key={i} className="flame" style={{ animationDelay: `${i * 0.1}s` }}>
        🔥
      </span>
    ));
  };

  const handleGameEnd = async (tokensCollected: number) => {
    setClaiming(true);
    setError(null);

    try {
      const result = await claimFromFaucetGame(pkHash, tokensCollected);
      setClaimResult(result);
      setMode('default');
      setShowCelebration(true);

      setTimeout(() => {
        setShowCelebration(false);
        fetchStatus();
      }, 4000);
    } catch (e) {
      setError((e as Error).message);
      setMode('default');
    } finally {
      setClaiming(false);
    }
  };

  const handleGameCancel = () => {
    setMode('default');
  };

  const dismissCelebration = () => {
    setShowCelebration(false);
    fetchStatus();
  };

  if (loading) {
    return (
      <div className="faucet-container">
        <div className="faucet-loading">Loading faucet...</div>
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="faucet-container">
        <div className="faucet-message">
          <p>Failed to load faucet: {error}</p>
          <button onClick={fetchStatus} className="secondary">Retry</button>
        </div>
      </div>
    );
  }

  if (stats && !stats.enabled) {
    return (
      <div className="faucet-container">
        <div className="faucet-message">
          <p>The faucet is not currently enabled on this node.</p>
        </div>
      </div>
    );
  }

  // Game mode - full width, transparent background
  if (mode === 'game') {
    return (
      <div className="faucet-game-container">
        <FaucetGame onGameEnd={handleGameEnd} onCancel={handleGameCancel} />
      </div>
    );
  }

  return (
    <div className="faucet-container">
      {/* Celebration Overlay */}
      {showCelebration && claimResult && (
        <div className="celebration-overlay" onClick={dismissCelebration}>
          <div className="confetti-container">
            {Array.from({ length: 50 }, (_, i) => (
              <div
                key={i}
                className="confetti"
                style={{
                  left: `${Math.random() * 100}%`,
                  animationDelay: `${Math.random() * 0.5}s`,
                  backgroundColor: ['#58a6ff', '#a371f7', '#4ECDC4', '#45B7D1', '#96CEB4'][
                    Math.floor(Math.random() * 5)
                  ],
                }}
              />
            ))}
          </div>
          <div className="celebration-content">
            <div className="celebration-amount">+{claimResult.amount}</div>
            <div className="celebration-message">{claimResult.message}</div>
            {claimResult.new_streak > 1 && (
              <div className="celebration-streak">
                {renderFlames(claimResult.new_streak)}
                <span className="streak-text">{claimResult.new_streak} day streak!</span>
              </div>
            )}
            <p className="tap-dismiss">Tap anywhere to dismiss</p>
          </div>
        </div>
      )}

      {/* Main Action */}
      {status?.can_claim ? (
        <button
          className="play-game-button"
          onClick={() => setMode('game')}
          disabled={claiming}
        >
          <img src="/logo.png" alt="" className="button-logo" />
          <span className="button-content">
            <span className="button-title">Play to Claim</span>
            <span className="button-reward">Earn 5-50 TSN</span>
          </span>
          <span className="button-icon">⛏️</span>
        </button>
      ) : (
        <div className="countdown-section">
          <div className="countdown-display">
            <svg className="progress-ring" viewBox="0 0 120 120">
              <circle
                className="progress-ring-bg"
                cx="60"
                cy="60"
                r="52"
                fill="none"
                strokeWidth="8"
              />
              <circle
                className="progress-ring-fill"
                cx="60"
                cy="60"
                r="52"
                fill="none"
                strokeWidth="8"
                strokeDasharray={`${2 * Math.PI * 52}`}
                strokeDashoffset={`${2 * Math.PI * 52 * (1 - getProgress() / 100)}`}
              />
            </svg>
            <div className="countdown-text">
              <div className="countdown-time">{formatCountdown(countdown)}</div>
              <div className="countdown-label">until next claim</div>
            </div>
          </div>

          {/* Streak Display - under countdown */}
          {status && status.streak > 0 && (
            <div className="streak-inline">
              {renderFlames(status.streak)}
              <span className="streak-number">{status.streak}</span>
              <span className="streak-label">day streak</span>
            </div>
          )}
        </div>
      )}

      {error && <div className="faucet-error">{error}</div>}
    </div>
  );
}
