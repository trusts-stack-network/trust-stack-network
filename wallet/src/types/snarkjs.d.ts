/**
 * Type declarations for snarkjs.
 * @see https://github.com/iden3/snarkjs
 */

declare module 'snarkjs' {
  export interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }

  export interface FullProveResult {
    proof: Groth16Proof;
    publicSignals: string[];
  }

  export interface Groth16 {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string | Uint8Array,
      zkeyFile: string | Uint8Array
    ): Promise<FullProveResult>;

    verify(
      vkey: unknown,
      publicSignals: string[],
      proof: Groth16Proof
    ): Promise<boolean>;

    exportSolidityCallData(
      proof: Groth16Proof,
      publicSignals: string[]
    ): Promise<string>;
  }

  export const groth16: Groth16;
}
