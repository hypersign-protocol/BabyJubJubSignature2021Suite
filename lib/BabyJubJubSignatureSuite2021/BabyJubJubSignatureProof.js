"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveProof = exports.BabyJubJubSignatureProof2021 = void 0;
// @ts-ignore
const jsonld_signatures_1 = __importDefault(require("jsonld-signatures"));
const babyjubjub2021_1 = require("@hypersign-protocol/babyjubjub2021");
const js_jsonld_merklization_1 = require("@iden3/js-jsonld-merklization");
// @ts-ignore
const jsonld_1 = __importDefault(require("jsonld"));
const js_jsonld_merklization_2 = require("@iden3/js-jsonld-merklization");
const utils_1 = require("../utils");
const { suites: { LinkedDataProof }, } = jsonld_signatures_1.default;
class BabyJubJubSignatureProof2021 extends LinkedDataProof {
    constructor({ useNativeCanonize, key, LDKeyClass } = {}) {
        super({
            type: "BabyJubJubSignatureProof2021",
        });
        this.proofSignatureKey = "proofValue";
        this.LDKeyClass = LDKeyClass !== null && LDKeyClass !== void 0 ? LDKeyClass : babyjubjub2021_1.BabyJubJubKeys2021;
        this.key = key;
        this.useNativeCanonize = useNativeCanonize;
    }
    deriveProof(proofDocument, revealDocument, params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!params.suite) {
                throw new TypeError('"options.suite" is required.');
            }
            if (Array.isArray(proofDocument)) {
                throw new TypeError("proofDocument should be an object not an array.");
            }
            if (Array.isArray(revealDocument)) {
                throw new TypeError("revealDocument should be an object not an array.");
            }
            if (!proofDocument.proof) {
                throw new TypeError("proofDocument should have a proof property.");
            }
            const proof = proofDocument.proof;
            // ToDo: Comented Because when transpiling with typescript something changes and causes errors (Non Deterministic )
            // const verifyCredential = await jsigs.verify(proofDocument, {
            //   suite: new BabyJubJubSignature2021Suite({
            //     key: params.suite,
            //     verificationMethod:params.suite.id
            //   }),
            //   purpose: new jsigs.purposes.AssertionProofPurpose({
            //     controller: {
            //       "@context": ["https://www.w3.org/ns/did/v1"],
            //       id: proof.verificationMethod.split,
            //       assertionMethod: [proof.verificationMethod],
            //     },
            //     documentLoader: params.documentLoader,
            //   }),
            // });
            // if (!verifyCredential.verified) {
            //   throw new Error("proofDocument cannot be verified");
            // }
            delete proofDocument.proof;
            const frame = yield jsonld_1.default.frame(proofDocument, revealDocument, {
                documentLoader: params.documentLoader,
            });
            const proofDocument_mt = yield js_jsonld_merklization_2.Merklizer.merklizeJSONLD(JSON.stringify(proofDocument), {
                documentLoader: params.documentLoader,
            });
            const proofDocument_mt2 = yield js_jsonld_merklization_2.Merklizer.merklizeJSONLD(JSON.stringify(frame), {
                documentLoader: params.documentLoader,
            });
            const selectiveDisclosureRoot = (0, utils_1.convertMultiBase)((yield proofDocument_mt2.root()).bytes);
            const actualCredentialRoot = (0, utils_1.convertMultiBase)(Buffer.from((yield proofDocument_mt.root()).bigInt().toString()));
            const claim = actualCredentialRoot + "." + selectiveDisclosureRoot;
            const derivedProof = {
                type: this.type,
                created: new Date().toISOString(),
                verificationMethod: proof.verificationMethod,
                proofPurpose: proof.proofPurpose,
                credentialRoot: claim,
                proofValue: proof.proofValue,
            };
            frame["proof"] = derivedProof;
            return frame;
        });
    }
    verifyProof(options) {
        const { proof } = options;
        if (!proof.credentialRoot) {
            throw new Error("Credential Root is missing");
        }
        if (!proof.proofValue) {
            throw new Error("Proof Value is missing");
        }
        if (!proof.credentialRoot) {
            throw new Error("Credential Root is missing");
        }
        const credentialRoot = proof.credentialRoot;
        const vc_root = credentialRoot.split(".")[0];
        const vcRoot = (0, utils_1.multibaseDecode)(vc_root);
        const root = Buffer.from(vcRoot).toString();
        const verified = this.key.publicKey.verifyPoseidon(BigInt(root), (0, utils_1.decompactSignature)(proof.proofValue));
        return {
            verified,
            verificationMethod: {
                id: options.proof.verificationMethod,
                controller: this.key.controller,
                publickeyMultibase: this.key.publicKeyMultibase,
                type: this.key.type,
            },
        };
    }
    matchProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            //  match Proof Called First
            const { proof } = options;
            if (!proof.credentialRoot) {
                throw new Error("Credential Root is missing");
            }
            const credentialRoot = proof.credentialRoot;
            const vc_root_multibase = credentialRoot.split(".")[0];
            const selectiveDisclosureRoot = credentialRoot.split(".")[1];
            const opt = options.documentLoader
                ? {
                    documentLoader: options.documentLoader,
                }
                : undefined;
            const mtsd = yield js_jsonld_merklization_2.Merklizer.merklizeJSONLD(JSON.stringify(options.document), opt);
            const mtsdmultibase = (0, utils_1.convertMultiBase)((yield mtsd.root()).bytes);
            return mtsdmultibase === selectiveDisclosureRoot;
        });
    }
}
exports.BabyJubJubSignatureProof2021 = BabyJubJubSignatureProof2021;
function deriveProof(proofDocument, revealDocument, params) {
    return __awaiter(this, void 0, void 0, function* () {
        const expansionMap = true;
        const skipProofCompaction = true;
        const documentLoader = params.documentLoader
            ? params.documentLoader
            : js_jsonld_merklization_1.getDocumentLoader;
        const bjjSignatureProof = new BabyJubJubSignatureProof2021();
        return bjjSignatureProof.deriveProof(proofDocument, revealDocument, {
            suite: params.suite,
            documentLoader: documentLoader,
            expansionMap: expansionMap,
            skipProofCompaction: skipProofCompaction,
        });
    });
}
exports.deriveProof = deriveProof;
//# sourceMappingURL=BabyJubJubSignatureProof.js.map