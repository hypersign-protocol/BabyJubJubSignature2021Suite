import { Signature } from "@iden3/js-crypto";
export declare function w3cDate(date?: number | string): string;
export declare function convertMultiBase(data: Uint8Array): string;
export declare function multibaseDecode(signature: string): Uint8Array;
export declare function compactSignature(signature: Signature): Uint8Array;
export declare function decompactSignature(sign: string): Signature;
//# sourceMappingURL=index.d.ts.map