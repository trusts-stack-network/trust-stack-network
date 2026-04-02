import type { Player, Obstacle, Token, BoundingBox, GameState, Particle } from './gameTypes';
import {
  GRAVITY,
  GRAVITY_FAST,
  JUMP_VELOCITY,
  MAX_JUMP_TIME,
  JUMP_HOLD_BOOST,
  TERMINAL_VELOCITY,
  GROUND_Y,
  PLAYER_HEIGHT,
  HITBOX_SHRINK_PLAYER,
  HITBOX_SHRINK_OBSTACLE,
  CANVAS_WIDTH,
  OBSTACLE_WIDTH,
  OBSTACLE_MIN_HEIGHT,
  OBSTACLE_MAX_HEIGHT,
  MIN_OBSTACLE_GAP,
  MAX_OBSTACLE_GAP,
  TOKEN_SIZE,
  TOKEN_FLOAT_OFFSET,
  TOKEN_FLOAT_SPEED,
  TOTAL_OBSTACLES,
  PARTICLE_COUNT,
  PARTICLE_MIN_SPEED,
  PARTICLE_MAX_SPEED,
  PARTICLE_LIFE,
  COLORS,
} from './gameConstants';

// Apply gravity and update player position
export function updatePlayerPhysics(player: Player): void {
  // Apply variable gravity based on jump state
  // If jump is held and player is rising, use normal gravity and add boost
  // If jump is released early and player is rising, use faster gravity
  if (player.vy < 0 && player.jumpHeld && player.jumpTime < MAX_JUMP_TIME) {
    // Still holding jump and going up - add boost for higher jump
    player.vy += JUMP_HOLD_BOOST;
    player.jumpTime++;
    player.vy += GRAVITY;
  } else if (player.vy < 0 && !player.jumpHeld) {
    // Released jump early while going up - fast fall
    player.vy += GRAVITY_FAST;
  } else {
    // Normal gravity (falling or on ground)
    player.vy += GRAVITY;
  }

  // Clamp vertical velocity
  if (player.vy > TERMINAL_VELOCITY) {
    player.vy = TERMINAL_VELOCITY;
  }

  // Update position
  player.y += player.vy;

  // Ground collision
  const groundLevel = GROUND_Y - PLAYER_HEIGHT;
  if (player.y >= groundLevel) {
    player.y = groundLevel;
    player.vy = 0;
    player.isJumping = false;
    player.isOnGround = true;
    player.jumpTime = 0;
  } else {
    player.isOnGround = false;
  }
}

// Make the player jump
export function playerJump(player: Player): boolean {
  if (player.isOnGround && !player.isJumping) {
    player.vy = JUMP_VELOCITY;
    player.isJumping = true;
    player.isOnGround = false;
    player.jumpHeld = true;
    player.jumpTime = 0;
    return true;
  }
  return false;
}

// Release jump (for variable height)
export function playerReleaseJump(player: Player): void {
  player.jumpHeld = false;
}

// Get player bounding box with shrink for forgiving hitbox
export function getPlayerBoundingBox(player: Player): BoundingBox {
  return {
    x: player.x + HITBOX_SHRINK_PLAYER,
    y: player.y + HITBOX_SHRINK_PLAYER,
    width: player.width - HITBOX_SHRINK_PLAYER * 2,
    height: player.height - HITBOX_SHRINK_PLAYER * 2,
  };
}

// Get obstacle bounding box with shrink
export function getObstacleBoundingBox(obstacle: Obstacle): BoundingBox {
  return {
    x: obstacle.x + HITBOX_SHRINK_OBSTACLE,
    y: obstacle.y + HITBOX_SHRINK_OBSTACLE,
    width: obstacle.width - HITBOX_SHRINK_OBSTACLE * 2,
    height: obstacle.height - HITBOX_SHRINK_OBSTACLE * 2,
  };
}

// Get token bounding box (tokens have generous hitboxes)
export function getTokenBoundingBox(token: Token): BoundingBox {
  return {
    x: token.x,
    y: token.y,
    width: token.width,
    height: token.height,
  };
}

// AABB collision detection
export function checkCollision(a: BoundingBox, b: BoundingBox): boolean {
  return (
    a.x < b.x + b.width &&
    a.x + a.width > b.x &&
    a.y < b.y + b.height &&
    a.y + a.height > b.y
  );
}

// Check if player collides with any obstacle
export function checkObstacleCollisions(player: Player, obstacles: Obstacle[]): boolean {
  const playerBox = getPlayerBoundingBox(player);

  for (const obstacle of obstacles) {
    if (obstacle.passed) continue;

    const obstacleBox = getObstacleBoundingBox(obstacle);
    if (checkCollision(playerBox, obstacleBox)) {
      return true;
    }
  }

  return false;
}

// Check and collect tokens
export function checkTokenCollisions(
  player: Player,
  tokens: Token[]
): number[] {
  const playerBox = getPlayerBoundingBox(player);
  const collectedIndices: number[] = [];

  tokens.forEach((token, index) => {
    if (token.collected) return;

    const tokenBox = getTokenBoundingBox(token);
    if (checkCollision(playerBox, tokenBox)) {
      collectedIndices.push(index);
    }
  });

  return collectedIndices;
}

// Update obstacles - move left and mark as passed
export function updateObstacles(obstacles: Obstacle[], gameSpeed: number, playerX: number): void {
  for (const obstacle of obstacles) {
    obstacle.x -= gameSpeed;

    // Mark as passed when fully past player
    if (!obstacle.passed && obstacle.x + obstacle.width < playerX) {
      obstacle.passed = true;
    }
  }
}

// Update tokens - move with obstacles
export function updateTokens(tokens: Token[], gameSpeed: number): void {
  for (const token of tokens) {
    if (!token.collected) {
      token.x -= gameSpeed;
      token.pulsePhase += TOKEN_FLOAT_SPEED;
    }
  }
}

// Create a new obstacle
export function createObstacle(x: number): Obstacle {
  const height = OBSTACLE_MIN_HEIGHT + Math.random() * (OBSTACLE_MAX_HEIGHT - OBSTACLE_MIN_HEIGHT);
  return {
    x,
    y: GROUND_Y - height,
    width: OBSTACLE_WIDTH,
    height,
    passed: false,
  };
}

// Create a token above an obstacle
export function createToken(obstacle: Obstacle, obstacleIndex: number): Token {
  return {
    x: obstacle.x + (obstacle.width - TOKEN_SIZE) / 2,
    y: obstacle.y - TOKEN_SIZE - TOKEN_FLOAT_OFFSET,
    width: TOKEN_SIZE,
    height: TOKEN_SIZE,
    collected: false,
    pulsePhase: Math.random() * Math.PI * 2,
    obstacleIndex,
    isBonus: obstacleIndex >= TOTAL_OBSTACLES,
  };
}

// Spawn obstacles and tokens as needed (continues indefinitely)
export function spawnObstacles(state: GameState): void {
  if (state.distance >= state.nextObstacleDistance) {
    const newObstacle = createObstacle(CANVAS_WIDTH + 50);
    const newToken = createToken(newObstacle, state.obstaclesSpawned);

    state.obstacles.push(newObstacle);
    state.tokens.push(newToken);
    state.obstaclesSpawned++;

    // Calculate next obstacle distance
    const gap = MIN_OBSTACLE_GAP + Math.random() * (MAX_OBSTACLE_GAP - MIN_OBSTACLE_GAP);
    state.nextObstacleDistance = state.distance + gap;
  }
}

// Create particles for token collection effect
export function createCollectionParticles(x: number, y: number): Particle[] {
  const particles: Particle[] = [];

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const angle = (Math.PI * 2 * i) / PARTICLE_COUNT + Math.random() * 0.5;
    const speed = PARTICLE_MIN_SPEED + Math.random() * (PARTICLE_MAX_SPEED - PARTICLE_MIN_SPEED);
    const color = COLORS.particle[Math.floor(Math.random() * COLORS.particle.length)];

    particles.push({
      x,
      y,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed - 2, // Slight upward bias
      size: 3 + Math.random() * 4,
      color,
      alpha: 1,
      life: PARTICLE_LIFE,
      maxLife: PARTICLE_LIFE,
    });
  }

  return particles;
}

// Update particles
export function updateParticles(particles: Particle[]): Particle[] {
  return particles.filter((particle) => {
    particle.x += particle.vx;
    particle.y += particle.vy;
    particle.vy += 0.2; // Gravity
    particle.life--;
    particle.alpha = particle.life / particle.maxLife;
    return particle.life > 0;
  });
}

// Check if game is complete (only when player hits obstacle - game continues indefinitely)
export function isGameComplete(_state: GameState): boolean {
  // Game never auto-ends - player must hit obstacle or claim
  return false;
}

// Calculate number of passed obstacles
export function getPassedObstacles(obstacles: Obstacle[]): number {
  return obstacles.filter((o) => o.passed).length;
}
