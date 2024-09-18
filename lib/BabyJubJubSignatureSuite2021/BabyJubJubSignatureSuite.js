"use strict";
//@ts-ignore
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
exports.documentLoader = exports.BabyJubJubSignature2021Suite = void 0;
const jsonld_signatures_1 = __importDefault(require("jsonld-signatures"));
const { suites: { LinkedDataSignature }, } = jsonld_signatures_1.default;
const js_jsonld_merklization_1 = require("@iden3/js-jsonld-merklization");
//@ts-ignore
const { purposes: { AssertionProofPurpose }, } = jsonld_signatures_1.default;
const utils_1 = require("../utils");
const babyjubjub2021_1 = require("babyjubjub2021");
const utils_2 = require("../utils");
class BabyJubJubSignature2021Suite extends LinkedDataSignature {
    constructor(options) {
        super({
            type: "BJJSignature2021",
            LDKeyClass: babyjubjub2021_1.BabyJubJubKeys2021,
            date: (0, utils_2.w3cDate)(options.date ? options.date : new Date()),
            key: options.key,
            proof: options.proof,
            signer: options.signer,
            verifier: options.verifier,
            verificationMethod: options.verificationMethod,
            useNativeCanonize: options.useNativeCanonize
                ? options.useNativeCanonize
                : false,
        });
        this.proofSignatureKey = "proofValue";
        this.verificationMethod = options.verificationMethod
            ? options.verificationMethod
            : this.LDKeyClass.verificationMethod;
        this._hashCache = {};
    }
    ensureSuiteContext(params) {
        return;
    }
    canonize(input, documentLoader) {
        return __awaiter(this, void 0, void 0, function* () {
            const merklized = yield js_jsonld_merklization_1.Merklizer.merklizeJSONLD(JSON.stringify(input), {
                documentLoader,
            });
            return merklized;
        });
    }
    createProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let proof = {
                type: this.type,
            };
            let date = options.date
                ? new Date(options.date).getTime()
                : undefined;
            if (date === undefined) {
                date = Date.now();
            }
            if (date !== undefined && typeof date !== "string") {
                date = (0, utils_2.w3cDate)(date);
            }
            if (date !== undefined) {
                proof.created = date;
            }
            proof.verificationMethod = this.key.id;
            proof = yield options.purpose.update(proof, {
                document: options.document,
                suite: options.suite,
                documentLoader: options.documentLoader,
                expansionMap: options.expansionMap,
            });
            options.document.proof = proof;
            const merklized = yield this.canonize(options.document, options.documentLoader);
            const verifyData = (yield merklized.root()).bigInt();
            const signature = yield this.sign({
                verifyData: verifyData,
                proof: proof,
            });
            proof[this.proofSignatureKey] = (0, utils_1.convertMultiBase)((0, utils_1.compactSignature)(signature));
            return proof;
        });
    }
    sign(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(this.signer && typeof this.signer.sign === "function")) {
                throw new Error("A signer API has not been specified.");
            }
            const signatureBytes = yield this.signer.sign({
                data: params.verifyData,
            });
            return signatureBytes;
        });
    }
    verifyProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                delete options.proof["@context"];
                const proofValue = options.proof.proofValue;
                delete options.proof.proofValue;
                options.document.proof = options.proof;
                const merklized = yield this.canonize(options.document, options.documentLoader);
                const verifyData = (yield merklized.root()).bigInt();
                const { verificationMethod } = options.proof;
                const verified = yield this.verifySignature({
                    verifyData,
                    signature: (0, utils_1.decompactSignature)(proofValue),
                });
                return {
                    verified,
                    verificationMethod: {
                        id: verificationMethod,
                        controller: this.key.controller,
                        publickeyMultibase: this.key.publickeyMultibase,
                        type: this.key.type,
                    },
                };
            }
            catch (e) {
                return { verified: false, e };
            }
        });
    }
    verifySignature(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { verifier } = this;
            if (!verifier) {
                const key = yield this.LDKeyClass.from(this.verificationMethod);
                verifier = key.verifier();
            }
            const verified = yield verifier.verify({
                data: options.verifyData,
                signature: options.signature,
            });
            return verified;
        });
    }
}
exports.BabyJubJubSignature2021Suite = BabyJubJubSignature2021Suite;
const documentLoader = js_jsonld_merklization_1.getDocumentLoader;
exports.documentLoader = documentLoader;
//# sourceMappingURL=BabyJubJubSignatureSuite.js.map