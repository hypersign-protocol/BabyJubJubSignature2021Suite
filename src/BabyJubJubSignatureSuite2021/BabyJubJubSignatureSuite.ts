//@ts-ignore

import jsigs from "jsonld-signatures";
const {
  suites: { LinkedDataSignature },
} = jsigs;

import { Merklizer, getDocumentLoader } from "@iden3/js-jsonld-merklization";
import multibase from "multibase";

import { Signature } from "@iden3/js-crypto";
//@ts-ignore
const {
  purposes: { AssertionProofPurpose },
} = jsigs;

import {
  compactSignature,
  convertMultiBase,
  decompactSignature,
  multibaseDecode,
} from "../utils";
import { BabyJubJubKeys2021 } from "babyjubjub2021";

import { w3cDate } from "../utils";

class BabyJubJubSignature2021Suite extends LinkedDataSignature {
  //   proof: Record<string, any>;
  signer: any;
  verifier: any;
  LDKeyClass: any;
  //   proofSignatureKey: string;
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
  }) {
    super({
      type: "BJJSignature2021",
      LDKeyClass: BabyJubJubKeys2021,
      date: w3cDate(options.date ? options.date : new Date()),
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
  ensureSuiteContext(params: { document: any; addSuiteContext: any }) {
    return;
  }

  async canonize(input: Record<string, any>, documentLoader: any) {
    const merklized = await Merklizer.merklizeJSONLD(JSON.stringify(input), {
      documentLoader,
    });

    return merklized;
  }

  async createProof(options: {
    document: any;
    suite: BabyJubJubSignature2021Suite;
    purpose: any;
    proofSet: any;
    documentLoader: any;
    expansionMap: boolean;
    readonly date?: string | Date;
  }) {
    let proof: Record<string, any> = {
      type: this.type,
    };

    let date: string | number | undefined = options.date
      ? new Date(options.date).getTime()
      : undefined;
    if (date === undefined) {
      date = Date.now();
    }
    if (date !== undefined && typeof date !== "string") {
      date = w3cDate(date);
    }
    if (date !== undefined) {
      proof.created = date;
    }

    proof.verificationMethod = this.key.id;
    proof = await options.purpose.update(proof, {
      document: options.document,
      suite: options.suite,
      documentLoader: options.documentLoader,
      expansionMap: options.expansionMap,
    });
    options.document.proof = proof;

    const merklized = await this.canonize(
      options.document,
      options.documentLoader
    );

    const verifyData = (await merklized.root()).bigInt();

    const signature = await this.sign({
      verifyData: verifyData,
      proof: proof,
    });
    proof[this.proofSignatureKey] = convertMultiBase(
      compactSignature(signature)
    );
    return proof;
  }
  async sign(params: { verifyData: bigint; proof: any }) {
    if (!(this.signer && typeof this.signer.sign === "function")) {
      throw new Error("A signer API has not been specified.");
    }

    const signatureBytes: Signature = await this.signer.sign({
      data: params.verifyData,
    });
    return signatureBytes;
  }
  async verifyProof(options: {
    document: any;
    proof: any;
    documentLoader?: any;
  }) {
    try {
      delete options.proof["@context"];
      const proofValue = options.proof.proofValue;
      delete options.proof.proofValue;
      options.document.proof = options.proof;

      const merklized = await this.canonize(
        options.document,
        options.documentLoader
      );

      options.proof.proofValue=proofValue
      const verifyData = (await merklized.root()).bigInt();

      const { verificationMethod } = options.proof;

      const verified = await this.verifySignature({
        verifyData,
        signature: decompactSignature(proofValue),
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
    } catch (e) {
      return { verified: false, e };
    }
  }
  async verifySignature(options: { verifyData: bigint; signature: Signature }) {
    let { verifier } = this;
    if (!verifier) {
      const key = await this.LDKeyClass.from(this.verificationMethod);
      verifier = key.verifier();
    }

    const verified = await verifier.verify({
      data: options.verifyData,
      signature: options.signature,
    });
    return verified;
  }
}

const documentLoader = getDocumentLoader;
export { BabyJubJubSignature2021Suite, documentLoader };
