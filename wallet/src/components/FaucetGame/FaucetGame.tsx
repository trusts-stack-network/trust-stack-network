import { useRef, useEffect, useState, useCallback } from 'react';
import type { GameState, CanvasDimensions } from './gameTypes';
import { useGameLoop } from './useGameLoop';
import {
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  PLAYER_X,
  PLAYER_START_Y,
  PLAYER_WIDTH,
  PLAYER_HEIGHT,
  INITIAL_GAME_SPEED,
  MAX_GAME_SPEED,
  SPEED_INCREMENT,
  SPEED_INCREMENT_INTERVAL,
  DINO_ANIMATION_SPEED,
  BACKGROUND_SPEED_RATIO,
  TOTAL_OBSTACLES,
  TOKEN_VALUE,
} from './gameConstants';
import {
  updatePlayerPhysics,
  playerJump,
  playerReleaseJump,
  checkObstacleCollisions,
  checkTokenCollisions,
  updateObstacles,
  updateTokens,
  spawnObstacles,
  createCollectionParticles,
  updateParticles,
  isGameComplete,
} from './gamePhysics';
import { render } from './gameRenderer';
import './FaucetGame.css';

interface FaucetGameProps {
  onGameEnd: (tokensCollected: number) => void;
  onCancel: () => void;
}

function createInitialState(): GameState {
  return {
    phase: 'idle',
    player: {
      x: PLAYER_X,
      y: PLAYER_START_Y,
      vx: 0,
      vy: 0,
      width: PLAYER_WIDTH,
      height: PLAYER_HEIGHT,
      isJumping: false,
      isOnGround: true,
      animationFrame: 0,
      animationTimer: 0,
      jumpHeld: false,
      jumpTime: 0,
    },
    obstacles: [],
    tokens: [],
    particles: [],
    tokensCollected: 0,
    totalTokens: TOTAL_OBSTACLES,
    distance: 0,
    gameSpeed: INITIAL_GAME_SPEED,
    groundOffset: 0,
    backgroundOffset: 0,
    obstaclesSpawned: 0,
    nextObstacleDistance: 200,
  };
}

export default function FaucetGame({ onGameEnd, onCancel: _onCancel }: FaucetGameProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef<GameState>(createInitialState());
  const dimensionsRef = useRef<CanvasDimensions>({
    width: CANVAS_WIDTH,
    height: CANVAS_HEIGHT,
    scale: 1,
  });
  const collisionRef = useRef(false);
  const [, forceUpdate] = useState({});

  // Initialize canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const updateCanvasSize = () => {
      const container = canvas.parentElement;
      if (!container) return;

      // Use container width, show more on larger screens
      const containerWidth = container.clientWidth;
      const canvasWidth = Math.max(CANVAS_WIDTH, containerWidth);
      const displayWidth = containerWidth;
      const displayHeight = (CANVAS_HEIGHT / canvasWidth) * displayWidth;

      // Set display size
      canvas.style.width = `${displayWidth}px`;
      canvas.style.height = `${displayHeight}px`;

      // Set actual canvas size for rendering
      const dpr = window.devicePixelRatio || 1;
      canvas.width = canvasWidth * dpr;
      canvas.height = CANVAS_HEIGHT * dpr;

      dimensionsRef.current = {
        width: canvasWidth,
        height: CANVAS_HEIGHT,
        scale: dpr,
      };
    };

    updateCanvasSize();
    window.addEventListener('resize', updateCanvasSize);

    // Initial render
    const ctx = canvas.getContext('2d');
    if (ctx) {
      render(ctx, stateRef.current, dimensionsRef.current);
    }

    return () => {
      window.removeEventListener('resize', updateCanvasSize);
    };
  }, []);

  // Game update logic
  const update = useCallback((_deltaTime: number) => {
    const state = stateRef.current;
    if (state.phase !== 'playing') return;

    // Update distance
    state.distance += state.gameSpeed;
    state.groundOffset += state.gameSpeed;
    state.backgroundOffset += state.gameSpeed * BACKGROUND_SPEED_RATIO;

    // Update player animation
    state.player.animationTimer++;
    if (state.player.animationTimer >= DINO_ANIMATION_SPEED) {
      state.player.animationTimer = 0;
      state.player.animationFrame++;
    }

    // Update player physics
    updatePlayerPhysics(state.player);

    // Spawn obstacles
    spawnObstacles(state);

    // Update obstacles and tokens
    updateObstacles(state.obstacles, state.gameSpeed, state.player.x);
    updateTokens(state.tokens, state.gameSpeed);

    // Check token collection
    const collectedIndices = checkTokenCollisions(state.player, state.tokens);
    for (const index of collectedIndices) {
      const token = state.tokens[index];
      token.collected = true;
      state.tokensCollected++;

      // Create particles
      const newParticles = createCollectionParticles(
        token.x + token.width / 2,
        token.y + token.height / 2
      );
      state.particles.push(...newParticles);
    }

    // Update particles
    state.particles = updateParticles(state.particles);

    // Check obstacle collisions
    if (checkObstacleCollisions(state.player, state.obstacles)) {
      collisionRef.current = true;
      state.phase = 'ended';
      forceUpdate({});
      return;
    }

    // Increase game speed progressively
    const passedCount = state.obstacles.filter((o) => o.passed).length;
    const speedLevel = Math.floor(passedCount / SPEED_INCREMENT_INTERVAL);
    state.gameSpeed = Math.min(
      INITIAL_GAME_SPEED + speedLevel * SPEED_INCREMENT,
      MAX_GAME_SPEED
    );

    // Check game completion
    if (isGameComplete(state)) {
      state.phase = 'ended';
      forceUpdate({});
    }
  }, []);

  // Render logic
  const renderGame = useCallback(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!ctx) return;

    render(ctx, stateRef.current, dimensionsRef.current, collisionRef.current);
  }, []);

  // Game loop
  const { start, stop } = useGameLoop({
    onUpdate: update,
    onRender: renderGame,
  });

  // Handle game start/jump
  const handleAction = useCallback(() => {
    const state = stateRef.current;

    if (state.phase === 'idle') {
      state.phase = 'playing';
      start();
      forceUpdate({});
    } else if (state.phase === 'playing') {
      playerJump(state.player);
    }
  }, [start]);

  // Handle jump release (for variable height)
  const handleActionRelease = useCallback(() => {
    const state = stateRef.current;
    if (state.phase === 'playing') {
      playerReleaseJump(state.player);
    }
  }, []);

  // Handle game end claim
  const handleClaim = useCallback(() => {
    const state = stateRef.current;
    // Only count non-bonus tokens for claiming
    const claimable = state.tokens.filter(t => t.collected && !t.isBonus).length;
    if (state.phase === 'ended' && claimable > 0) {
      stop();
      onGameEnd(Math.min(claimable, TOTAL_OBSTACLES));
    }
  }, [stop, onGameEnd]);

  // Handle play again
  const handlePlayAgain = useCallback(() => {
    stateRef.current = createInitialState();
    collisionRef.current = false;
    forceUpdate({});
  }, []);

  // Keyboard input
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore key repeat events to prevent infinite jumping
      if (e.repeat) return;

      if (e.code === 'Space' || e.code === 'ArrowUp') {
        e.preventDefault();
        handleAction();
      }
    };

    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.code === 'Space' || e.code === 'ArrowUp') {
        e.preventDefault();
        handleActionRelease();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
    };
  }, [handleAction, handleActionRelease]);

  // Touch input
  const handleTouchStart = useCallback(
    (e: React.TouchEvent | React.MouseEvent) => {
      e.preventDefault();
      handleAction();
    },
    [handleAction]
  );

  const handleTouchEnd = useCallback(
    (e: React.TouchEvent | React.MouseEvent) => {
      e.preventDefault();
      handleActionRelease();
    },
    [handleActionRelease]
  );

  const state = stateRef.current;
  // Only count non-bonus tokens (first TOTAL_OBSTACLES) for claiming
  const claimableTokens = state.tokens.filter(t => t.collected && !t.isBonus).length;
  const earnings = Math.min(claimableTokens, TOTAL_OBSTACLES) * TOKEN_VALUE;
  const canClaim = state.phase === 'ended' && claimableTokens > 0;

  return (
    <div className="faucet-game">
      <div
        className="game-canvas-container"
        onTouchStart={handleTouchStart}
        onTouchEnd={handleTouchEnd}
        onMouseDown={handleTouchStart}
        onMouseUp={handleTouchEnd}
      >
        <canvas ref={canvasRef} className="game-canvas" />
      </div>

      <div className="game-controls">

        {state.phase === 'ended' && (
          <div className="game-results">
            <div className="results-actions">
              {canClaim ? (
                <>
                  <button className="claim-game-button" onClick={handleClaim}>
                    <span className="claim-logo">
                      <span className="logo-circle left"></span>
                      <span className="logo-circle right"></span>
                    </span>
                    <span className="claim-text">Claim {earnings} TSN</span>
                  </button>
                  <button className="play-again-button" onClick={handlePlayAgain}>
                    Play Again
                  </button>
                </>
              ) : (
                <>
                  <p className="no-tokens-message">
                    Collect at least 1 coin to claim!
                  </p>
                  <button className="play-again-button" onClick={handlePlayAgain}>
                    Play Again
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
