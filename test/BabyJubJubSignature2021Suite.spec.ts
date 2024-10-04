import { BabyJubJubKeys2021 } from "babyjubjub2021";
import { BabyJubJubSignature2021Suite, documentLoader } from "../src/index";
import * as fs from "fs";
//@ts-ignore

import jsigs from "jsonld-signatures";

let publicKeyMultibase: any, privateKeyMultibase: any;
let cred: any;
let keys: any;
let DID: any;
describe("BbabyJubJubSignature2021", () => {
  beforeEach(async () => {
    const KeyPair = await BabyJubJubKeys2021.from(
      "liberty taste budget never right tent whip menu fog shine angle habit view between art perfect razor burger fence found scatter bounce laptop cruise"
    );
    publicKeyMultibase = KeyPair.publicKeyMultibase;

    privateKeyMultibase = KeyPair.privateKeyMultibase;
    DID = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: `did:hid:testnet:${publicKeyMultibase}`,
      controller: `did:hid:testnet:${publicKeyMultibase}`,
      assertionMethod: [`did:hid:testnet:${publicKeyMultibase}#key-1`],
      authentication: [`did:hid:testnet:${publicKeyMultibase}#key-1`],
      verificationMethod: [
        {
          id: `did:hid:testnet:${publicKeyMultibase}#key-1`,
          type: KeyPair.type,
          controller: `did:hid:testnet:${publicKeyMultibase}`,
          publicKeyMultibase,
        },
      ],
    };
    keys = await BabyJubJubKeys2021.fromKeys({
      publicKeyMultibase,
      privateKeyMultibase,
      options: {
        id: DID.id + "#key-1",
        controller: DID,
      },
    });
  });

  it("Sign Credential", async () => {
    cred = {
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
                    type: "https://www.w3.org/2018/credentials#JsonSchemaValidator2018",
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
              "@id":
                "https://www.w3.org/2018/credentials#VerifiablePresentation",
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
            BJJSignature2021: {
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
            "hypersign-vocab": "urn:uuid:13fe9318-bb82-4d95-8bf5-8e7fdf8b2026#",
            HypersignCredentialStatus2023: {
              "@id": "hypersign-vocab:HypersignCredentialStatus2023",
              "@context": {
                "@protected": true,
                id: "@id",
                type: "@type",
              },
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
      credentialSchema: {
        id: "sch:hid:testnet:z6MkipbPd8k6N8BSraPwdBafpM8W5HzNS6jy3F7SwWjDk5Cs:1.0",
        type: "JsonSchemaValidator2018",
      },
      credentialStatus: {
        id: "http://127.0.0.1:1317/hypersign-protocol/hidnode/ssi/credential/vc:hid:testnet:z6MktDeNN2ZuydfGHoFtbvGvaxMug7dxncZtNspc5H7BkeSo",
        type: "HypersignCredentialStatus2023",
      },
      id: "http://example.edu/credentials/3732",
      issuanceDate: "2023-10-10T05:03:27.153Z",
      issuer: "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM",
      type: ["VerifiableCredential", "DayPassCredential"],
    };

    const signedCredential = await jsigs.sign(cred, {
      suite: new BabyJubJubSignature2021Suite({
        key: keys,
      }),
      // @ts-ignore
      purpose: new jsigs.purposes.AssertionProofPurpose({
        // @ts-ignore

        controller: {
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: DID.id + "#key-1",
          assertionMethod: DID.assertionMethod,
        },
      }),
      documentLoader,
    });

    fs.writeFileSync(
      "./test/Data/signedCredential.json",
      JSON.stringify(signedCredential, null, 2)
    );

    const verified = await jsigs.verify(signedCredential, {
      suite: new BabyJubJubSignature2021Suite({
        key: BabyJubJubKeys2021.fromKeys({
          publicKeyMultibase: DID.verificationMethod[0].publicKeyMultibase,
          options: {
            id: DID.id + "#key-1",
            controller: DID.controller,
          },
        }),
      }),
      purpose: new jsigs.purposes.AssertionProofPurpose({
        // @ts-ignore

        controller: {
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: DID.id + "#key-1",
          assertionMethod: DID.assertionMethod,
        },
      }),
      documentLoader,
    });

    expect(verified.verified).toBe(true);
  });
});
