/**
 * Type declarations for ffjavascript library.
 * Minimal types covering BN254/BN128 curve operations used in binding signatures.
 */

declare module 'ffjavascript' {
  export interface FieldElement {
    // Fr field element (opaque type)
  }

  export interface G1Point {
    // G1 curve point (opaque type)
  }

  export interface Fr {
    zero: FieldElement;
    one: FieldElement;
    e(value: bigint | number | string): FieldElement;
    fromRprLE(buffer: Uint8Array, offset: number): FieldElement;
    toRprLE(buffer: Uint8Array, offset: number, element: unknown): void;
    add(a: unknown, b: unknown): FieldElement;
    sub(a: unknown, b: unknown): FieldElement;
    mul(a: unknown, b: unknown): FieldElement;
    neg(a: unknown): FieldElement;
    inv(a: unknown): FieldElement;
    eq(a: unknown, b: unknown): boolean;
    isZero(a: unknown): boolean;
    random(): FieldElement;
  }

  export interface G1 {
    g: G1Point; // Generator point
    zero: G1Point;
    add(a: unknown, b: unknown): G1Point;
    sub(a: unknown, b: unknown): G1Point;
    neg(a: unknown): G1Point;
    timesFr(point: unknown, scalar: unknown): G1Point;
    eq(a: unknown, b: unknown): boolean;
    isZero(a: unknown): boolean;
    toAffine(point: unknown): G1Point;
    toRprUncompressed(buffer: Uint8Array, offset: number, point: unknown): void;
    fromRprUncompressed(buffer: Uint8Array, offset: number): G1Point;
  }

  export interface Bn128Curve {
    Fr: Fr;
    G1: G1;
    terminate(): Promise<void>;
  }

  export function buildBn128(singleThread?: boolean): Promise<Bn128Curve>;
}
