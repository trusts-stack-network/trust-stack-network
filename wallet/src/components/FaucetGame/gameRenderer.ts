import type { GameState, Player, Obstacle, Token, Particle, CanvasDimensions } from './gameTypes';
import {
  CANVAS_HEIGHT,
  GROUND_Y,
  COLORS,
  PLAYER_WIDTH,
  TOKEN_FLOAT_AMPLITUDE,
  TOTAL_OBSTACLES,
} from './gameConstants';

// Clear the background (transparent)
export function drawBackground(ctx: CanvasRenderingContext2D, _offset: number, canvasWidth: number): void {
  // Clear to transparent
  ctx.clearRect(0, 0, canvasWidth, CANVAS_HEIGHT);
}

// Draw the ground
export function drawGround(ctx: CanvasRenderingContext2D, _offset: number, canvasWidth: number): void {
  // Simple ground line
  ctx.strokeStyle = COLORS.groundLine;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(0, GROUND_Y);
  ctx.lineTo(canvasWidth, GROUND_Y);
  ctx.stroke();
}

// Draw pixel-art miner with pickaxe, purple hardhat, and TSN logo on shirt
export function drawPlayer(ctx: CanvasRenderingContext2D, player: Player): void {
  const { x, y, animationFrame, isJumping, isOnGround } = player;

  // Shadow
  ctx.fillStyle = COLORS.playerShadow;
  ctx.beginPath();
  ctx.ellipse(x + PLAYER_WIDTH / 2, GROUND_Y - 2, 16, 5, 0, 0, Math.PI * 2);
  ctx.fill();

  // Colors
  const skinColor = '#e8b89d';
  const shirtColor = '#1a1a2e'; // Dark shirt for logo visibility
  const pantsColor = '#3d5a80'; // Blue jeans
  const bootColor = '#5c4033'; // Brown boots
  const hatColor = '#a855f7'; // Purple hard hat
  const hatDark = '#7c3aed'; // Darker purple
  const pickHandle = '#8b4513'; // Wood brown
  const pickHead = '#708090'; // Steel gray

  // Use animation frame for leg movement when on ground
  const legOffset = isOnGround && !isJumping ? (animationFrame % 2) * 4 : 0;
  const pickSwing = isOnGround && !isJumping ? Math.sin(animationFrame * 0.5) * 0.3 : 0;

  // === PICKAXE (behind body when running, above when jumping) ===
  ctx.save();
  if (isJumping) {
    // Pickaxe held up while jumping
    ctx.translate(x + 32, y + 8);
    ctx.rotate(-0.5);
  } else {
    // Pickaxe swinging while running
    ctx.translate(x + 38, y + 18);
    ctx.rotate(0.3 + pickSwing);
  }

  // Pickaxe handle
  ctx.fillStyle = pickHandle;
  ctx.fillRect(-2, 0, 4, 22);

  // Pickaxe head
  ctx.fillStyle = pickHead;
  ctx.beginPath();
  ctx.moveTo(-12, -2);
  ctx.lineTo(12, -2);
  ctx.lineTo(14, 2);
  ctx.lineTo(8, 4);
  ctx.lineTo(-8, 4);
  ctx.lineTo(-14, 2);
  ctx.closePath();
  ctx.fill();

  // Pickaxe point
  ctx.fillStyle = '#5a6a7a';
  ctx.beginPath();
  ctx.moveTo(12, -2);
  ctx.lineTo(18, 0);
  ctx.lineTo(14, 2);
  ctx.closePath();
  ctx.fill();

  ctx.restore();

  // === LEGS ===
  if (isJumping) {
    // Tucked legs when jumping
    ctx.fillStyle = pantsColor;
    ctx.fillRect(x + 14, y + 34, 8, 10);
    ctx.fillRect(x + 24, y + 34, 8, 10);
    // Boots
    ctx.fillStyle = bootColor;
    ctx.fillRect(x + 13, y + 42, 10, 6);
    ctx.fillRect(x + 23, y + 42, 10, 6);
  } else {
    // Running legs
    // Back leg
    ctx.fillStyle = pantsColor;
    ctx.fillRect(x + 14 + legOffset, y + 32, 8, 12);
    ctx.fillStyle = bootColor;
    ctx.fillRect(x + 13 + legOffset, y + 42, 10, 6);

    // Front leg
    ctx.fillStyle = pantsColor;
    ctx.fillRect(x + 24 - legOffset, y + 32, 8, 12);
    ctx.fillStyle = bootColor;
    ctx.fillRect(x + 23 - legOffset, y + 42, 10, 6);
  }

  // === BODY (torso) ===
  ctx.fillStyle = shirtColor;
  ctx.fillRect(x + 12, y + 18, 22, 16);

  // TSN logo on shirt (two overlapping circles)
  const logoX = x + 23;
  const logoY = y + 26;
  const logoSize = 4;

  // Left circle (cyan)
  ctx.globalAlpha = 0.9;
  ctx.fillStyle = '#38bdf8';
  ctx.beginPath();
  ctx.arc(logoX - logoSize * 0.3, logoY, logoSize, 0, Math.PI * 2);
  ctx.fill();

  // Right circle (purple)
  ctx.globalAlpha = 0.85;
  ctx.fillStyle = '#c026d3';
  ctx.beginPath();
  ctx.arc(logoX + logoSize * 0.3, logoY, logoSize, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalAlpha = 1;

  // === ARMS ===
  ctx.fillStyle = shirtColor;
  if (isJumping) {
    // Arms up holding pickaxe
    ctx.fillRect(x + 8, y + 16, 6, 12);
    ctx.fillRect(x + 32, y + 14, 6, 10);
    // Hands
    ctx.fillStyle = skinColor;
    ctx.fillRect(x + 9, y + 14, 4, 4);
    ctx.fillRect(x + 33, y + 12, 4, 4);
  } else {
    // Arms in running/swinging position
    ctx.fillRect(x + 8, y + 18, 6, 12);
    ctx.fillRect(x + 32, y + 16, 6, 14);
    // Hands
    ctx.fillStyle = skinColor;
    ctx.fillRect(x + 9, y + 28, 4, 4);
    ctx.fillRect(x + 33, y + 28, 4, 4);
  }

  // === HEAD ===
  // Face
  ctx.fillStyle = skinColor;
  ctx.beginPath();
  ctx.arc(x + 23, y + 10, 10, 0, Math.PI * 2);
  ctx.fill();

  // Hard hat (purple)
  ctx.fillStyle = hatColor;
  ctx.beginPath();
  ctx.ellipse(x + 23, y + 4, 12, 6, 0, Math.PI, 2 * Math.PI);
  ctx.fill();

  // Hat brim
  ctx.fillStyle = hatDark;
  ctx.fillRect(x + 10, y + 4, 26, 3);

  // Hat light/lamp
  ctx.fillStyle = '#ffffff';
  ctx.beginPath();
  ctx.arc(x + 23, y + 2, 3, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = '#ffff88';
  ctx.beginPath();
  ctx.arc(x + 23, y + 2, 2, 0, Math.PI * 2);
  ctx.fill();

  // Eyes
  ctx.fillStyle = '#ffffff';
  ctx.beginPath();
  ctx.arc(x + 19, y + 9, 3, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.arc(x + 27, y + 9, 3, 0, Math.PI * 2);
  ctx.fill();

  // Pupils
  ctx.fillStyle = '#1a1f2e';
  ctx.beginPath();
  ctx.arc(x + 20, y + 9, 1.5, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.arc(x + 28, y + 9, 1.5, 0, Math.PI * 2);
  ctx.fill();

  // Smile
  ctx.strokeStyle = '#8b6914';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(x + 23, y + 12, 4, 0.2, Math.PI - 0.2);
  ctx.stroke();
}

// Draw obstacle with glass effect
export function drawObstacle(ctx: CanvasRenderingContext2D, obstacle: Obstacle): void {
  const { x, y, width, height } = obstacle;

  // Glow effect
  ctx.shadowColor = COLORS.obstacleGlow;
  ctx.shadowBlur = 15;

  // Glass fill
  const gradient = ctx.createLinearGradient(x, y, x + width, y + height);
  gradient.addColorStop(0, 'rgba(102, 126, 234, 0.4)');
  gradient.addColorStop(0.5, 'rgba(118, 75, 162, 0.5)');
  gradient.addColorStop(1, 'rgba(102, 126, 234, 0.4)');
  ctx.fillStyle = gradient;

  // Rounded rectangle
  const radius = 4;
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height);
  ctx.lineTo(x, y + height);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
  ctx.fill();

  // Border
  ctx.shadowBlur = 0;
  ctx.strokeStyle = COLORS.obstacleBorder;
  ctx.lineWidth = 2;
  ctx.stroke();

  // Inner highlight
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(x + radius, y + 2);
  ctx.lineTo(x + width - radius, y + 2);
  ctx.stroke();
}

// Draw TSN coin (overlapping circles logo) with floating animation
// Bonus tokens (after first 10) are drawn gray
export function drawToken(ctx: CanvasRenderingContext2D, token: Token): void {
  if (token.collected) return;

  const { x, y, width, height, pulsePhase, isBonus } = token;

  // Floating animation - bob up and down
  const floatOffset = Math.sin(pulsePhase) * TOKEN_FLOAT_AMPLITUDE;

  const centerX = x + width / 2;
  const centerY = y + height / 2 + floatOffset;

  // Pulse scale for subtle breathing effect
  const pulse = 1 + Math.sin(pulsePhase * 2) * 0.05;
  const baseSize = (width / 2) * 0.7 * pulse;

  // Glow effect - gray for bonus, blue for normal
  ctx.shadowColor = isBonus ? 'rgba(150, 150, 150, 0.4)' : 'rgba(140, 180, 255, 0.6)';
  ctx.shadowBlur = 12 + Math.sin(pulsePhase) * 4;

  // Draw two overlapping circles (TSN logo style)
  // Left circle - gray for bonus, cyan/blue for normal
  const leftGradient = ctx.createRadialGradient(
    centerX - baseSize * 0.4,
    centerY - baseSize * 0.3,
    0,
    centerX - baseSize * 0.3,
    centerY,
    baseSize * 1.2
  );
  if (isBonus) {
    leftGradient.addColorStop(0, '#a0a0a0'); // Light gray
    leftGradient.addColorStop(0.5, '#808080'); // Gray
    leftGradient.addColorStop(1, '#606060'); // Dark gray
  } else {
    leftGradient.addColorStop(0, '#7dd3fc'); // Light cyan
    leftGradient.addColorStop(0.5, '#38bdf8'); // Cyan
    leftGradient.addColorStop(1, '#0ea5e9'); // Blue
  }

  ctx.globalAlpha = 0.9;
  ctx.fillStyle = leftGradient;
  ctx.beginPath();
  ctx.arc(centerX - baseSize * 0.35, centerY, baseSize, 0, Math.PI * 2);
  ctx.fill();

  // Right circle - gray for bonus, purple/magenta for normal
  const rightGradient = ctx.createRadialGradient(
    centerX + baseSize * 0.4,
    centerY - baseSize * 0.3,
    0,
    centerX + baseSize * 0.3,
    centerY,
    baseSize * 1.2
  );
  if (isBonus) {
    rightGradient.addColorStop(0, '#909090'); // Light gray
    rightGradient.addColorStop(0.5, '#707070'); // Gray
    rightGradient.addColorStop(1, '#505050'); // Dark gray
  } else {
    rightGradient.addColorStop(0, '#e879f9'); // Light magenta
    rightGradient.addColorStop(0.5, '#c026d3'); // Magenta
    rightGradient.addColorStop(1, '#a21caf'); // Purple
  }

  ctx.globalAlpha = 0.85;
  ctx.fillStyle = rightGradient;
  ctx.beginPath();
  ctx.arc(centerX + baseSize * 0.35, centerY, baseSize, 0, Math.PI * 2);
  ctx.fill();

  // Overlap blend area - draw a subtle highlight in the middle
  ctx.globalAlpha = 0.4;
  const blendGradient = ctx.createRadialGradient(
    centerX,
    centerY - baseSize * 0.2,
    0,
    centerX,
    centerY,
    baseSize * 0.6
  );
  blendGradient.addColorStop(0, '#ffffff');
  if (isBonus) {
    blendGradient.addColorStop(0.5, 'rgba(150, 150, 150, 0.5)');
    blendGradient.addColorStop(1, 'rgba(100, 100, 100, 0)');
  } else {
    blendGradient.addColorStop(0.5, 'rgba(160, 140, 240, 0.5)');
    blendGradient.addColorStop(1, 'rgba(100, 80, 200, 0)');
  }
  ctx.fillStyle = blendGradient;
  ctx.beginPath();
  ctx.arc(centerX, centerY, baseSize * 0.6, 0, Math.PI * 2);
  ctx.fill();

  ctx.globalAlpha = 1;
  ctx.shadowBlur = 0;
}

// Draw particles
export function drawParticles(ctx: CanvasRenderingContext2D, particles: Particle[]): void {
  for (const particle of particles) {
    ctx.globalAlpha = particle.alpha;
    ctx.fillStyle = particle.color;
    ctx.beginPath();
    ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;
}

// Draw "Press SPACE to start" prompt
export function drawInstructions(ctx: CanvasRenderingContext2D, phase: 'idle' | 'playing' | 'ended', canvasWidth: number): void {
  if (phase !== 'idle') return;

  ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
  ctx.font = '16px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('Press SPACE or tap to start', canvasWidth / 2, CANVAS_HEIGHT / 2);
}

// Draw mini TSN logo
function drawMiniLogo(ctx: CanvasRenderingContext2D, x: number, y: number, size: number): void {
  // Left circle (cyan)
  ctx.globalAlpha = 0.9;
  ctx.fillStyle = '#38bdf8';
  ctx.beginPath();
  ctx.arc(x - size * 0.3, y, size, 0, Math.PI * 2);
  ctx.fill();

  // Right circle (purple)
  ctx.globalAlpha = 0.85;
  ctx.fillStyle = '#c026d3';
  ctx.beginPath();
  ctx.arc(x + size * 0.3, y, size, 0, Math.PI * 2);
  ctx.fill();

  ctx.globalAlpha = 1;
}

// Draw score in top right with TSN logo
export function drawScore(ctx: CanvasRenderingContext2D, claimableCount: number, totalScore: number, canvasWidth: number): void {
  // Claimable count (X/10) with logo
  const scoreX = canvasWidth - 16;

  // Draw logo
  drawMiniLogo(ctx, scoreX - 70, 24, 8);

  // Draw claimable count
  ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
  ctx.font = 'bold 18px sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'top';
  ctx.fillText(`${claimableCount}/${TOTAL_OBSTACLES}`, scoreX, 16);

  // Draw total score below
  ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
  ctx.font = '14px sans-serif';
  ctx.fillText(`Score: ${totalScore}`, scoreX, 38);
}

// Draw game over with score celebration
export function drawGameOver(
  ctx: CanvasRenderingContext2D,
  totalScore: number,
  collision: boolean,
  canvasWidth: number,
  frameCount: number
): void {
  if (!collision) return;

  // Score celebration in center
  const centerX = canvasWidth / 2;
  const centerY = CANVAS_HEIGHT / 2;

  // Glimmer particles around score
  const glimmerCount = 12;
  for (let i = 0; i < glimmerCount; i++) {
    const angle = (Math.PI * 2 * i) / glimmerCount + frameCount * 0.02;
    const radius = 60 + Math.sin(frameCount * 0.1 + i) * 10;
    const px = centerX + Math.cos(angle) * radius;
    const py = centerY + Math.sin(angle) * radius;
    const size = 3 + Math.sin(frameCount * 0.15 + i * 0.5) * 2;

    // Alternate colors
    const colors = ['#38bdf8', '#c026d3', '#fbbf24', '#4ade80'];
    ctx.fillStyle = colors[i % colors.length];
    ctx.globalAlpha = 0.6 + Math.sin(frameCount * 0.1 + i) * 0.3;
    ctx.beginPath();
    ctx.arc(px, py, size, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  // Score background glow
  ctx.shadowColor = 'rgba(56, 189, 248, 0.5)';
  ctx.shadowBlur = 20;

  // Score text
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 48px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${totalScore}`, centerX, centerY - 10);

  ctx.shadowBlur = 0;

  // "Score" label
  ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
  ctx.font = '16px sans-serif';
  ctx.fillText('SCORE', centerX, centerY + 30);
}

// Frame counter for animations
let frameCount = 0;

// Main render function
export function render(
  ctx: CanvasRenderingContext2D,
  state: GameState,
  dimensions: CanvasDimensions,
  collision: boolean = false
): void {
  frameCount++;

  // Clear and scale
  ctx.save();

  // Scale for high-DPI displays
  ctx.scale(dimensions.scale, dimensions.scale);

  const canvasWidth = dimensions.width;

  // Draw all elements
  drawBackground(ctx, state.backgroundOffset, canvasWidth);
  drawGround(ctx, state.groundOffset, canvasWidth);

  // Draw obstacles
  for (const obstacle of state.obstacles) {
    drawObstacle(ctx, obstacle);
  }

  // Draw tokens
  for (const token of state.tokens) {
    drawToken(ctx, token);
  }

  // Draw player
  drawPlayer(ctx, state.player);

  // Draw particles
  drawParticles(ctx, state.particles);

  // Count tokens
  const claimableCount = state.tokens.filter(t => t.collected && !t.isBonus).length;
  const totalScore = state.tokensCollected;

  // Draw score in top right when playing or ended
  if (state.phase === 'playing' || state.phase === 'ended') {
    drawScore(ctx, claimableCount, totalScore, canvasWidth);
  }

  // Draw overlays
  if (state.phase === 'idle') {
    drawInstructions(ctx, state.phase, canvasWidth);
  } else if (state.phase === 'ended') {
    drawGameOver(ctx, totalScore, collision, canvasWidth, frameCount);
  }

  ctx.restore();
}
