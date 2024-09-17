// @ts-ignore
import jsigs from "jsonld-signatures";
import * as fs from "fs";
import { BabyJubJubKeys2021 } from "babyjubjub2021";
import {
  DocumentLoader,
  getDocumentLoader,
} from "@iden3/js-jsonld-merklization";
// @ts-ignore
import jsonLd from "jsonld";
import {
  Merklizer,
  Path,
  Value,
  PoseidonHasher,
} from "@iden3/js-jsonld-merklization";
import {
  BabyJubJubSignature2021Suite,
  documentLoader,
} from "./BabyJubJubSignatureSuite";
import {
  convertMultiBase,
  decompactSignature,
  multibaseDecode,
} from "../utils";
import { DEFAULT_HASHER } from "@iden3/js-jsonld-merklization/dist/types/lib/poseidon";
const {
  suites: { LinkedDataProof },
} = jsigs;
export class BabyJubJubSignatureProof2021 extends LinkedDataProof {
  private type: any;
  private proofSignatureKey: string;
  private LDKeyClass: BabyJubJubKeys2021;
  private key: BabyJubJubKeys2021;
  private useNativeCanonize: any;
  constructor({ useNativeCanonize, key, LDKeyClass }: any = {}) {
    super({
      type: "BabyJubJubSignatureProof2021",
    });

    this.proofSignatureKey = "proofValue";
    this.LDKeyClass = LDKeyClass ?? BabyJubJubKeys2021;
    this.key = key;
    this.useNativeCanonize = useNativeCanonize;
  }

  async deriveProof(
    proofDocument: any,
    revealDocument: any,
    params: {
      suite: BabyJubJubKeys2021;
      documentLoader?: any;
      expansionMap?: any;
      skipProofCompaction?: any;
      nonce?: any;
    }
  ) {
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


    const proofValue=proofDocument.proof.proofValue
    delete proofDocument.proof.proofValue;
    

    const proofDocument_mt = await Merklizer.merklizeJSONLD(
      JSON.stringify(proofDocument),
      {
        documentLoader: params.documentLoader,
      }
    );
    delete proofDocument.proof;

    const frame = await jsonLd.frame(proofDocument, revealDocument, {
      documentLoader: params.documentLoader,
    });
    const proofDocument_mt2 = await Merklizer.merklizeJSONLD(
      JSON.stringify(frame),
      {
        documentLoader: params.documentLoader,
      }
    );

    const selectiveDisclosureRoot = convertMultiBase(
      (await proofDocument_mt2.root()).bytes
    );

    const actualCredentialRoot = convertMultiBase(
      Buffer.from((await proofDocument_mt.root()).bigInt().toString())
    );

    const claim = actualCredentialRoot + "." + selectiveDisclosureRoot;

    const derivedProof = {
      type: this.type,
      created: new Date().toISOString(),
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose,
      credentialRoot: claim,
      proofValue: proofValue,
    };

    frame["proof"] = derivedProof;

    return frame;
  }

  verifyProof(options: {
    proof: any;
    document: any;
    purpose: any;
    documentLoader: any;
    expansionMap: any;
  }) {
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
    const vcRoot = multibaseDecode(vc_root);
    const root = Buffer.from(vcRoot).toString();

    const verified = this.key.publicKey.verifyPoseidon(
      BigInt(root),
      decompactSignature(proof.proofValue)
    );

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
  async matchProof(options: {
    proof: any;
    document: any;

    documentLoader: any;
    expansionMap: any;
  }) {
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
    const mtsd = await Merklizer.merklizeJSONLD(
      JSON.stringify(options.document),
      opt
    );
    const mtsdmultibase = convertMultiBase((await mtsd.root()).bytes);
    return mtsdmultibase === selectiveDisclosureRoot;
  }
}

export async function deriveProof(
  proofDocument: any,
  revealDocument: any,
  params: {
    suite: BabyJubJubKeys2021;
    documentLoader: any;
  }
) {
  const expansionMap = true;
  const skipProofCompaction = true;
  const documentLoader = params.documentLoader
    ? params.documentLoader
    : getDocumentLoader;

  const bjjSignatureProof = new BabyJubJubSignatureProof2021();
  return bjjSignatureProof.deriveProof(proofDocument, revealDocument, {
    suite: params.suite,
    documentLoader: documentLoader,
    expansionMap: expansionMap,
    skipProofCompaction: skipProofCompaction,
  });
}
