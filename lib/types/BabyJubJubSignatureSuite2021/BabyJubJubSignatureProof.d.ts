import { BabyJubJubKeys2021 } from "@hypersign-protocol/babyjubjub2021";
declare const LinkedDataProof: any;
export declare class BabyJubJubSignatureProof2021 extends LinkedDataProof {
    private type;
    private proofSignatureKey;
    private LDKeyClass;
    private key;
    private useNativeCanonize;
    constructor({ useNativeCanonize, key, LDKeyClass }?: any);
    deriveProof(proofDocument: any, revealDocument: any, params: {
        suite: BabyJubJubKeys2021;
        documentLoader?: any;
        expansionMap?: any;
        skipProofCompaction?: any;
        nonce?: any;
    }): Promise<any>;
    verifyProof(options: {
        proof: any;
        document: any;
        purpose: any;
        documentLoader: any;
        expansionMap: any;
    }): {
        verified: boolean;
        verificationMethod: {
            id: any;
            controller: string | undefined;
            publickeyMultibase: string | undefined;
            type: string;
        };
    };
    matchProof(options: {
        proof: any;
        document: any;
        documentLoader: any;
        expansionMap: any;
    }): Promise<boolean>;
}
export declare function deriveProof(proofDocument: any, revealDocument: any, params: {
    suite: BabyJubJubKeys2021;
    documentLoader: any;
}): Promise<any>;
export {};
//# sourceMappingURL=BabyJubJubSignatureProof.d.ts.map