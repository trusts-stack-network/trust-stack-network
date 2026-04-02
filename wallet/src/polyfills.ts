/**
 * Polyfills for Node.js APIs needed by circomlibjs and snarkjs in browser.
 * This file must be imported before any other imports that use these APIs.
 */

import { Buffer } from 'buffer';

// Make Buffer available globally
(window as unknown as { Buffer: typeof Buffer }).Buffer = Buffer;
(globalThis as unknown as { Buffer: typeof Buffer }).Buffer = Buffer;
