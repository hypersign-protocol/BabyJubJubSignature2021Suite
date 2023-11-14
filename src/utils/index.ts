import { Signature } from "@iden3/js-crypto";
import multibase from "multibase";

export function w3cDate(date?: number | string): string {
  let result = new Date();
  if (typeof date === "number" || typeof date === "string") {
    result = new Date(date);
  }
  const str = result.toISOString();
  return str.substr(0, str.length - 5) + "Z";
}

export function convertMultiBase(data: Uint8Array) {
  return Buffer.from(multibase.encode("base58btc", data)).toString();
}
export function multibaseDecode(signature: string): Uint8Array {
  return multibase.decode(signature);
}

export function compactSignature(signature: Signature) {
  return signature.compress();
}

export function decompactSignature(sign: string): Signature {
  const decoded = multibaseDecode(sign);
  const signature = Signature.newFromCompressed(decoded);
  return signature;
}
