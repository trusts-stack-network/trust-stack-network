import { useRef, useCallback, useEffect } from 'react';

interface UseGameLoopOptions {
  onUpdate: (deltaTime: number) => void;
  onRender: () => void;
  targetFPS?: number;
}

export function useGameLoop({ onUpdate, onRender, targetFPS = 60 }: UseGameLoopOptions) {
  const frameRef = useRef<number>(0);
  const lastTimeRef = useRef<number>(0);
  const isRunningRef = useRef<boolean>(false);
  const accumulatorRef = useRef<number>(0);

  const frameTime = 1000 / targetFPS;

  const gameLoop = useCallback((timestamp: number) => {
    if (!isRunningRef.current) return;

    if (lastTimeRef.current === 0) {
      lastTimeRef.current = timestamp;
    }

    const deltaTime = timestamp - lastTimeRef.current;
    lastTimeRef.current = timestamp;

    // Accumulator for fixed timestep
    accumulatorRef.current += deltaTime;

    // Limit accumulated time to prevent spiral of death
    if (accumulatorRef.current > frameTime * 5) {
      accumulatorRef.current = frameTime * 5;
    }

    // Fixed timestep updates
    while (accumulatorRef.current >= frameTime) {
      onUpdate(frameTime / 1000); // Convert to seconds
      accumulatorRef.current -= frameTime;
    }

    // Render
    onRender();

    // Schedule next frame
    frameRef.current = requestAnimationFrame(gameLoop);
  }, [onUpdate, onRender, frameTime]);

  const start = useCallback(() => {
    if (isRunningRef.current) return;

    isRunningRef.current = true;
    lastTimeRef.current = 0;
    accumulatorRef.current = 0;
    frameRef.current = requestAnimationFrame(gameLoop);
  }, [gameLoop]);

  const stop = useCallback(() => {
    isRunningRef.current = false;
    if (frameRef.current) {
      cancelAnimationFrame(frameRef.current);
      frameRef.current = 0;
    }
  }, []);

  const isRunning = useCallback(() => isRunningRef.current, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stop();
    };
  }, [stop]);

  return { start, stop, isRunning };
}
