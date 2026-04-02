// Game constants and configuration

// Canvas dimensions
export const CANVAS_WIDTH = 800;
export const CANVAS_HEIGHT = 300;
export const GROUND_HEIGHT = 40;
export const GROUND_Y = CANVAS_HEIGHT - GROUND_HEIGHT;

// Player (Dino) settings
export const PLAYER_WIDTH = 44;
export const PLAYER_HEIGHT = 48;
export const PLAYER_X = 80;
export const PLAYER_START_Y = GROUND_Y - 48;

// Physics
export const GRAVITY = 0.85;
export const GRAVITY_FAST = 1.6; // Fast fall when jump released early
export const JUMP_VELOCITY = -12; // Slightly higher than -10
export const MAX_JUMP_TIME = 8; // Allow a bit more hold time
export const JUMP_HOLD_BOOST = -0.5; // Slight boost while holding
export const TERMINAL_VELOCITY = 20;

// Game speed
export const INITIAL_GAME_SPEED = 6;
export const MAX_GAME_SPEED = 12;
export const SPEED_INCREMENT = 0.5;
export const SPEED_INCREMENT_INTERVAL = 2; // Increase speed every N obstacles

// Obstacles
export const OBSTACLE_WIDTH = 30;
export const OBSTACLE_MIN_HEIGHT = 40;
export const OBSTACLE_MAX_HEIGHT = 60;
export const MIN_OBSTACLE_GAP = 300;
export const MAX_OBSTACLE_GAP = 500;
export const TOTAL_OBSTACLES = 10;

// Tokens
export const TOKEN_SIZE = 28;
export const TOKEN_FLOAT_OFFSET = 30; // How high above obstacle
export const TOKEN_VALUE = 5; // 5 TSN per token
export const MAX_TOKENS = 10;
export const TOKEN_FLOAT_AMPLITUDE = 8; // Pixels to float up/down
export const TOKEN_FLOAT_SPEED = 0.08; // Speed of floating animation

// Particles
export const PARTICLE_COUNT = 12;
export const PARTICLE_MIN_SPEED = 2;
export const PARTICLE_MAX_SPEED = 6;
export const PARTICLE_LIFE = 30;

// Animation
export const DINO_ANIMATION_SPEED = 6; // frames per animation step
export const TOKEN_PULSE_SPEED = 0.1;

// Parallax background
export const BACKGROUND_SPEED_RATIO = 0.3;

// Colors (matching glassmorphism theme)
export const COLORS = {
  background: '#0a0e14',
  ground: '#1a1f2e',
  groundLine: '#667eea',
  groundGlow: 'rgba(102, 126, 234, 0.3)',
  obstacle: 'rgba(102, 126, 234, 0.6)',
  obstacleBorder: 'rgba(102, 126, 234, 0.8)',
  obstacleGlow: 'rgba(102, 126, 234, 0.2)',
  token: '#ffd700',
  tokenGlow: 'rgba(255, 215, 0, 0.5)',
  tokenInner: '#ffaa00',
  player: '#667eea',
  playerShadow: 'rgba(102, 126, 234, 0.3)',
  text: '#ffffff',
  textSecondary: 'rgba(255, 255, 255, 0.7)',
  gridLine: 'rgba(102, 126, 234, 0.05)',
  particle: ['#ffd700', '#ffaa00', '#ff6b6b', '#4ecdc4', '#667eea'],
};

// Hitbox adjustments (shrink hitboxes for more forgiving collisions)
export const HITBOX_SHRINK_PLAYER = 8;
export const HITBOX_SHRINK_OBSTACLE = 4;
