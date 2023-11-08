import { BabyJubJubKeys2021 } from "@hypersign-protocol/babyjubjub2021";
import { BabyJubJubSignature2021Suite, documentLoader } from "../src/index";
//@ts-ignore

import jsigs from "jsonld-signatures";

let publicKeyMultibase: any, privateKeyMultibase: any;
let signedCredential: any;
let cred: any;
describe("BbabyJubJubSignature2021", () => {
  beforeEach(async () => {});

  it("Sign Credential", async () => {
    cred = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://schema.org",
      ],
      credentialSubject: {
        id: "did:hid:testnet:z8Fo8daHrZrQ4NtDZ9byYgrkEKqK43dkBNxorxpAEm3rj",
        "@type": "Person",
        address: { "@type": "DefinedRegion", addressCountry: "India" },
        givenName: "Pratap Mridha",
        age: 25,
      },
      id: "http://example.edu/credentials/3732",
      issuanceDate: "2023-10-10T05:03:27.153Z",
      issuer: "did:hid:testnet:z543717GD36C5VSajKzLALZzcTakhmme2LgC1ywW1YwTM",
      type: ["VerifiableCredential", "KycCredential"],
    };

    const KeyPair = await BabyJubJubKeys2021.from(
      "liberty taste budget never right tent whip menu fog shine angle habit view between art perfect razor burger fence found scatter bounce laptop cruise"
    );
    publicKeyMultibase = KeyPair.publicKeyMultibase;

    privateKeyMultibase = KeyPair.privateKeyMultibase;
    const DID = {
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
    const keys = await BabyJubJubKeys2021.fromKeys({
      publicKeyMultibase,
      privateKeyMultibase,
      options: {
        id: DID.id + "#key-1",
        controller: DID,
      },
    });

    const signedCredential = await jsigs.sign(cred, {
      suite: new BabyJubJubSignature2021Suite({
        key: keys,
      }),
      // @ts-ignore
      purpose: new jsigs.purposes.AssertionProofPurpose({
        controller: {
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: DID.id + "#key-1",
          assertionMethod: DID.assertionMethod,
        },
      }),
      documentLoader,
    });

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
