declare const LinkedDataSignature: any;
import { Merklizer, getDocumentLoader } from "@iden3/js-jsonld-merklization";
import { Signature } from "@iden3/js-crypto";
declare class BabyJubJubSignature2021Suite extends LinkedDataSignature {
    signer: any;
    verifier: any;
    LDKeyClass: any;
    useNativeCanonize: any;
    canonizeOptions: any;
    verificationMethod?: string;
    type: any;
    proofSignatureKey: string;
    key?: any;
    _hashCache: any;
    constructor(options: {
        key?: any;
        signer?: any;
        verifier?: any;
        proof?: any;
        date?: any;
        useNativeCanonize?: any;
        canonizeOptions?: any;
        verificationMethod?: string;
    });
    ensureSuiteContext(params: {
        document: any;
        addSuiteContext: any;
    }): void;
    canonize(input: Record<string, any>): Promise<Merklizer>;
    compactSignature(signature: Signature): Uint8Array;
    convertMultiBase(data: Uint8Array): string;
    multibaseDecode(signature: string): Uint8Array;
    decompactSignature(sign: string): Signature;
    createProof(options: {
        document: any;
        suite: BabyJubJubSignature2021Suite;
        purpose: any;
        proofSet: any;
        documentLoader: any;
        expansionMap: boolean;
        readonly date?: string | Date;
    }): Promise<Record<string, any>>;
    sign(params: {
        verifyData: bigint;
        proof: any;
    }): Promise<Signature>;
    verifyProof(options: {
        document: any;
        proof: any;
    }): Promise<{
        verified: any;
        verificationMethod: {
            id: any;
            controller: any;
            publickeyMultibase: any;
            type: any;
        };
        e?: undefined;
    } | {
        verified: boolean;
        e: unknown;
        verificationMethod?: undefined;
    }>;
    verifySignature(options: {
        verifyData: bigint;
        signature: Signature;
    }): Promise<any>;
}
declare const documentLoader: typeof getDocumentLoader;
export { BabyJubJubSignature2021Suite, documentLoader };
//# sourceMappingURL=BabyJubJubSignatureSuite.d.ts.map