/**
 * Type declarations for circomlibjs.
 * @see https://github.com/iden3/circomlibjs
 */

declare module 'circomlibjs' {
  export interface PoseidonField {
    toObject(element: unknown): bigint;
    fromObject(n: bigint): unknown;
  }

  export interface Poseidon {
    (inputs: bigint[]): unknown;
    F: PoseidonField;
  }

  export function buildPoseidon(): Promise<Poseidon>;
}
