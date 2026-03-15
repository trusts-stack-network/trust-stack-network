// Game type definitions for Dino Jump Faucet Game

export interface Position {
  x: number;
  y: number;
}

export interface Velocity {
  vx: number;
  vy: number;
}

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface Player extends Position, Velocity {
  width: number;
  height: number;
  isJumping: boolean;
  isOnGround: boolean;
  animationFrame: number;
  animationTimer: number;
  jumpHeld: boolean;
  jumpTime: number;
}

export interface Obstacle extends Position {
  width: number;
  height: number;
  passed: boolean;
}

export interface Token extends Position {
  width: number;
  height: number;
  collected: boolean;
  pulsePhase: number;
  obstacleIndex: number;
  isBonus: boolean;
}

export interface Particle extends Position, Velocity {
  size: number;
  color: string;
  alpha: number;
  life: number;
  maxLife: number;
}

export type GamePhase = 'idle' | 'playing' | 'ended';

export interface GameState {
  phase: GamePhase;
  player: Player;
  obstacles: Obstacle[];
  tokens: Token[];
  particles: Particle[];
  tokensCollected: number;
  totalTokens: number;
  distance: number;
  gameSpeed: number;
  groundOffset: number;
  backgroundOffset: number;
  obstaclesSpawned: number;
  nextObstacleDistance: number;
}

export interface GameCallbacks {
  onGameEnd: (tokensCollected: number) => void;
  onTokenCollect: (total: number) => void;
}

export interface CanvasDimensions {
  width: number;
  height: number;
  scale: number;
}
