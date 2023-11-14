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
exports.BabyJubJubSignatureProof2021 = void 0;
// @ts-ignore
const jsonld_signatures_1 = __importDefault(require("jsonld-signatures"));
const babyjubjub2021_1 = require("babyjubjub2021");
// @ts-ignore
const jsonld_1 = __importDefault(require("jsonld"));
const js_jsonld_merklization_1 = require("@iden3/js-jsonld-merklization");
const BabyJubJubSignatureSuite_1 = require("./BabyJubJubSignatureSuite");
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
            const verifyCredential = yield jsonld_signatures_1.default.verify(proofDocument, {
                suite: new BabyJubJubSignatureSuite_1.BabyJubJubSignature2021Suite({
                    key: params.suite,
                }),
                purpose: new jsonld_signatures_1.default.purposes.AssertionProofPurpose({
                    controller: {
                        "@context": ["https://www.w3.org/ns/did/v1"],
                        id: proof.verificationMethod,
                        assertionMethod: [proof.verificationMethod],
                    },
                    documentLoader: params.documentLoader,
                }),
            });
            if (!verifyCredential.verified) {
                throw new Error("proofDocument cannot be verified");
            }
            delete proofDocument.proof;
            const frame = yield jsonld_1.default.frame(proofDocument, revealDocument);
            const proofDocument_mt = yield js_jsonld_merklization_1.Merklizer.merklizeJSONLD(JSON.stringify(proofDocument));
            // console.log(proofDocument_mk.entries);
            const proofDocument_mt2 = yield js_jsonld_merklization_1.Merklizer.merklizeJSONLD(JSON.stringify(frame));
            const selectiveDisclosureRoot = (0, utils_1.convertMultiBase)((yield proofDocument_mt2.root()).bytes);
            const actualCredentialRoot = (0, utils_1.convertMultiBase)(Buffer.from((yield proofDocument_mt.root()).bigInt().toString(16), "hex"));
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
        return __awaiter(this, void 0, void 0, function* () {
            // console.log("Verifying proof");
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
            const hexRoot = ("0x" +
                Buffer.from(vcRoot).toString("hex"));
            const verified = yield this.key.publicKey.verifyPoseidon(BigInt(hexRoot), (0, utils_1.decompactSignature)(proof.proofValue));
            return {
                verified,
                verificationMethod: {
                    id: options.proof.verificationMethod,
                    controller: this.key.controller,
                    publickeyMultibase: this.key.publicKeyMultibase,
                    type: this.key.type,
                },
            };
        });
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
            const mtsd = yield js_jsonld_merklization_1.Merklizer.merklizeJSONLD(JSON.stringify(options.document));
            const mtsdmultibase = (0, utils_1.convertMultiBase)((yield mtsd.root()).bytes);
            return mtsdmultibase === selectiveDisclosureRoot;
        });
    }
}
exports.BabyJubJubSignatureProof2021 = BabyJubJubSignatureProof2021;
const main = () => __awaiter(void 0, void 0, void 0, function* () {
    const bjjSignatureProof = new BabyJubJubSignatureProof2021();
    const cred = {
        "@context": [
            {
                "@context": {
                    "@version": 1.1,
                    "@protected": true,
                    id: "@id",
                    type: "@type",
                    VerifiableCredential: {
                        "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            cred: "https://www.w3.org/2018/credentials#",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            credentialSchema: {
                                "@id": "cred:credentialSchema",
                                "@type": "@id",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    cred: "https://www.w3.org/2018/credentials#",
                                    JsonSchemaValidator2018: "cred:JsonSchemaValidator2018",
                                },
                            },
                            credentialStatus: {
                                "@id": "cred:credentialStatus",
                                "@type": "@id",
                            },
                            credentialSubject: {
                                "@id": "cred:credentialSubject",
                                "@type": "@id",
                            },
                            evidence: {
                                "@id": "cred:evidence",
                                "@type": "@id",
                            },
                            expirationDate: {
                                "@id": "cred:expirationDate",
                                "@type": "xsd:dateTime",
                            },
                            holder: {
                                "@id": "cred:holder",
                                "@type": "@id",
                            },
                            issued: {
                                "@id": "cred:issued",
                                "@type": "xsd:dateTime",
                            },
                            issuer: {
                                "@id": "cred:issuer",
                                "@type": "@id",
                            },
                            issuanceDate: {
                                "@id": "cred:issuanceDate",
                                "@type": "xsd:dateTime",
                            },
                            proof: {
                                "@id": "sec:proof",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                            refreshService: {
                                "@id": "cred:refreshService",
                                "@type": "@id",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    cred: "https://www.w3.org/2018/credentials#",
                                    ManualRefreshService2018: "cred:ManualRefreshService2018",
                                },
                            },
                            termsOfUse: {
                                "@id": "cred:termsOfUse",
                                "@type": "@id",
                            },
                            validFrom: {
                                "@id": "cred:validFrom",
                                "@type": "xsd:dateTime",
                            },
                            validUntil: {
                                "@id": "cred:validUntil",
                                "@type": "xsd:dateTime",
                            },
                        },
                    },
                    VerifiablePresentation: {
                        "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            cred: "https://www.w3.org/2018/credentials#",
                            sec: "https://w3id.org/security#",
                            holder: {
                                "@id": "cred:holder",
                                "@type": "@id",
                            },
                            proof: {
                                "@id": "sec:proof",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                            verifiableCredential: {
                                "@id": "cred:verifiableCredential",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                        },
                    },
                    EcdsaSecp256k1Signature2019: {
                        "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    EcdsaSecp256r1Signature2019: {
                        "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    Ed25519Signature2018: {
                        "@id": "https://w3id.org/security#Ed25519Signature2018",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    RsaSignature2018: {
                        "@id": "https://w3id.org/security#RsaSignature2018",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    proof: {
                        "@id": "https://w3id.org/security#proof",
                        "@type": "@id",
                        "@container": "@graph",
                    },
                },
            },
            {
                "@context": {
                    "@protected": true,
                    "@version": 1.1,
                    id: "@id",
                    type: "@type",
                    DayPassCredential: {
                        "@context": {
                            "@propagate": true,
                            "@protected": true,
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            fullName: {
                                "@id": "https://hypersign-schema.org/fullName",
                                "@type": "xsd:string",
                            },
                            companyName: {
                                "@id": "https://hypersign-schema.org/companyName",
                                "@type": "xsd:string",
                            },
                            address: {
                                "@id": "https://hypersign-schema.org",
                                "@type": "@id",
                            },
                            center: {
                                "@id": "https://hypersign-schema.org/center",
                                "@type": "xsd:string",
                            },
                            invoiceNumber: {
                                "@id": "https://hypersign-schema.org/invoiceNumber",
                                "@type": "xsd:string",
                            },
                        },
                        "@id": "https://hypersign-schema.org",
                    },
                },
            },
        ],
        credentialSubject: {
            "@explicit": true,
            id: "did:hid:testnet:z8Fo8daHrZrQ4NtDZ9byYgrkEKqK43dkBNxorxpAEm3rj",
            fullName: "Pratap Mridha",
            companyName: "HyperSign",
            address: {
                center: "Mumbai",
            },
            invoiceNumber: "1234567890",
        },
        id: "http://example.edu/credentials/3732",
        issuanceDate: "2023-10-10T05:03:27.153Z",
        issuer: "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM",
        type: ["VerifiableCredential", "DayPassCredential"],
        proof: {
            type: "BJJSignature2021",
            created: "2023-11-14T09:45:04Z",
            verificationMethod: "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM#key-1",
            proofPurpose: "assertionMethod",
            proofValue: "z2YwahAqBjGyndC2xcRepcH9N4HrRTqWH3cuT2u8Bj2i18cKHSn7odRTZwX4todL3D5bS5q2w6X5NVRppHQTfGBDi",
        },
    };
    const revealDocument = {
        "@context": [
            {
                "@context": {
                    "@version": 1.1,
                    "@protected": true,
                    id: "@id",
                    type: "@type",
                    VerifiableCredential: {
                        "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            cred: "https://www.w3.org/2018/credentials#",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            credentialSchema: {
                                "@id": "cred:credentialSchema",
                                "@type": "@id",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    cred: "https://www.w3.org/2018/credentials#",
                                    JsonSchemaValidator2018: "cred:JsonSchemaValidator2018",
                                },
                            },
                            credentialStatus: {
                                "@id": "cred:credentialStatus",
                                "@type": "@id",
                            },
                            credentialSubject: {
                                "@id": "cred:credentialSubject",
                                "@type": "@id",
                            },
                            evidence: {
                                "@id": "cred:evidence",
                                "@type": "@id",
                            },
                            expirationDate: {
                                "@id": "cred:expirationDate",
                                "@type": "xsd:dateTime",
                            },
                            holder: {
                                "@id": "cred:holder",
                                "@type": "@id",
                            },
                            issued: {
                                "@id": "cred:issued",
                                "@type": "xsd:dateTime",
                            },
                            issuer: {
                                "@id": "cred:issuer",
                                "@type": "@id",
                            },
                            issuanceDate: {
                                "@id": "cred:issuanceDate",
                                "@type": "xsd:dateTime",
                            },
                            proof: {
                                "@id": "sec:proof",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                            calim: {
                                "@id": "sec:calim",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                            refreshService: {
                                "@id": "cred:refreshService",
                                "@type": "@id",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    cred: "https://www.w3.org/2018/credentials#",
                                    ManualRefreshService2018: "cred:ManualRefreshService2018",
                                },
                            },
                            termsOfUse: {
                                "@id": "cred:termsOfUse",
                                "@type": "@id",
                            },
                            validFrom: {
                                "@id": "cred:validFrom",
                                "@type": "xsd:dateTime",
                            },
                            validUntil: {
                                "@id": "cred:validUntil",
                                "@type": "xsd:dateTime",
                            },
                        },
                    },
                    VerifiablePresentation: {
                        "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            cred: "https://www.w3.org/2018/credentials#",
                            sec: "https://w3id.org/security#",
                            holder: {
                                "@id": "cred:holder",
                                "@type": "@id",
                            },
                            proof: {
                                "@id": "sec:proof",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                            verifiableCredential: {
                                "@id": "cred:verifiableCredential",
                                "@type": "@id",
                                "@container": "@graph",
                            },
                        },
                    },
                    EcdsaSecp256k1Signature2019: {
                        "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    EcdsaSecp256r1Signature2019: {
                        "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    Ed25519Signature2018: {
                        "@id": "https://w3id.org/security#Ed25519Signature2018",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            id: "@id",
                            type: "@type",
                            sec: "https://w3id.org/security#",
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    RsaSignature2018: {
                        "@id": "https://w3id.org/security#RsaSignature2018",
                        "@context": {
                            "@version": 1.1,
                            "@protected": true,
                            challenge: "sec:challenge",
                            created: {
                                "@id": "http://purl.org/dc/terms/created",
                                "@type": "xsd:dateTime",
                            },
                            domain: "sec:domain",
                            expires: {
                                "@id": "sec:expiration",
                                "@type": "xsd:dateTime",
                            },
                            jws: "sec:jws",
                            nonce: "sec:nonce",
                            proofPurpose: {
                                "@id": "sec:proofPurpose",
                                "@type": "@vocab",
                                "@context": {
                                    "@version": 1.1,
                                    "@protected": true,
                                    id: "@id",
                                    type: "@type",
                                    sec: "https://w3id.org/security#",
                                    assertionMethod: {
                                        "@id": "sec:assertionMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                    authentication: {
                                        "@id": "sec:authenticationMethod",
                                        "@type": "@id",
                                        "@container": "@set",
                                    },
                                },
                            },
                            proofValue: "sec:proofValue",
                            verificationMethod: {
                                "@id": "sec:verificationMethod",
                                "@type": "@id",
                            },
                        },
                    },
                    proof: {
                        "@id": "https://w3id.org/security#proof",
                        "@type": "@id",
                        "@container": "@graph",
                    },
                },
            },
            {
                "@context": {
                    "@protected": true,
                    "@version": 1.1,
                    id: "@id",
                    type: "@type",
                    DayPassCredential: {
                        "@context": {
                            "@propagate": true,
                            "@protected": true,
                            xsd: "http://www.w3.org/2001/XMLSchema#",
                            fullName: {
                                "@id": "https://hypersign-schema.org/fullName",
                                "@type": "xsd:string",
                            },
                            companyName: {
                                "@id": "https://hypersign-schema.org/companyName",
                                "@type": "xsd:string",
                            },
                            address: {
                                "@id": "https://hypersign-schema.org",
                                "@type": "@id",
                            },
                            center: {
                                "@id": "https://hypersign-schema.org/center",
                                "@type": "xsd:string",
                            },
                            invoiceNumber: {
                                "@id": "https://hypersign-schema.org/invoiceNumber",
                                "@type": "xsd:string",
                            },
                        },
                        "@id": "https://hypersign-schema.org",
                    },
                },
            },
        ],
        credentialSubject: {
            "@explicit": true,
            id: {},
            fullName: {},
            address: {},
        },
        issuanceDate: {},
        issuer: {},
        type: ["VerifiableCredential", "DayPassCredential"],
    };
    const derived = yield bjjSignatureProof.deriveProof(cred, revealDocument, {
        suite: yield babyjubjub2021_1.BabyJubJubKeys2021.fromKeys({
            publicKeyMultibase: "z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM",
        }),
    });
    // console.log("========",derived);
    console.log(yield jsonld_signatures_1.default.verify(derived, {
        suite: new BabyJubJubSignatureProof2021({
            key: babyjubjub2021_1.BabyJubJubKeys2021.fromKeys({
                publicKeyMultibase: "z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM",
            }),
        }),
        purpose: new jsonld_signatures_1.default.purposes.AssertionProofPurpose({
            controller: {
                "@context": ["https://www.w3.org/ns/did/v1"],
                id: "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM" +
                    "#key-1",
                assertionMethod: [
                    "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM" +
                        "#key-1",
                ],
            },
        }),
    }));
});
main();
//# sourceMappingURL=BabyJubJubSignatureProof.js.map