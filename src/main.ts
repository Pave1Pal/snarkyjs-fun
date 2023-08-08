import { Experimental, Field, Poseidon, PrivateKey, PublicKey, Signature, } from "snarkyjs";
import { Util } from "./util.js";
import * as u8a from "uint8arrays";

export type Identifier = {
  id: {
    type: number;
    publickey: string;
  }
}

// Array can be only limited
export type ZKCredential = {
  issuer: {
    id: { type: number, publickey: string }
  };
  schema: number; // можно использовать type в качестве имени ключа
  issuanceDate: number;
  expirationDate: number; // 0 if expiration date is undefined
  subject: {
    id: { type: number, publickey: string }
  } & Record<string, any>
}


const isrPrivKey = PrivateKey.random();
console.log(`mina private key length`, isrPrivKey.toBase58().length);
const isrPubKey = PublicKey.fromPrivateKey(isrPrivKey);

const sbjPrivKey = PrivateKey.random();
const sbjPubKey = PublicKey.fromPrivateKey(sbjPrivKey);

const credential = Util.ZKC.sort({
  issuer: {
    id: {
      publickey: isrPubKey.toBase58(),
      type: 1,
    }
  },
  schema: 2,
  issuanceDate: new Date().getTime(),
  expirationDate: new Date().getTime() + 1000,
  subject: {
    id: {
      type: 1,
      publickey: sbjPubKey.toBase58()
    },
    twitter: {
      id: "twitter",
      username: "pvldshvv"
    }
  },
});

const usernameFD = new Field(toBigint("pvldshvv") % Field.ORDER);
const twitteridFD = new Field(toBigint("twitter") % Field.ORDER);


export function toFields(credential: ZKCredential): [Field, Field, Field, Field, Field, Field, Field, Field, Field] {
  const [
    issuer_id_type,
    issuer_id_pubkey,
    schema,
    issuanceDate,
    expirationDate,
    subject_id_type,
    subject_id_pubkey,
    twitter_id,
    twitter_username
  ] = Util.ZKC.toValues(credential);

  const issuerTypeFD = Field(toBigint(issuer_id_type!) % Field.ORDER);
  const issuerPubKeyFD = Poseidon.hash(PublicKey.fromBase58(issuer_id_pubkey as string).toFields());
  const schemaFD = Field(toBigint(schema!) % Field.ORDER);
  const issuanceDateFD = Field(toBigint(issuanceDate!) % Field.ORDER);
  const expirationDateFD = Field(toBigint(expirationDate!) % Field.ORDER);
  const subjectTypeFD = Field(toBigint(subject_id_type!) % Field.ORDER);
  const subjectPubKeyFD = Poseidon.hash(PublicKey.fromBase58(subject_id_pubkey as string).toFields());
  const twitterIdFD = Field(toBigint(twitter_id!) % Field.ORDER);
  const twitterNameFD = Field(toBigint(twitter_username!) % Field.ORDER);

  return [issuerTypeFD, issuerPubKeyFD, schemaFD, issuanceDateFD, expirationDateFD, subjectTypeFD, subjectPubKeyFD, twitterIdFD, twitterNameFD];
}

type ConvertOpt = {
  encoding: u8a.SupportedEncodings

}

function valueToBytes(value: string | number | bigint | boolean, opt?: ConvertOpt): Uint8Array {
  if (typeof value === "string") {
    return u8a.fromString(value, opt?.encoding);
  }
  if (typeof value === "number") {
    const bytes: number[] = [];
    let count = 0;
    while (value !== 0) {
      bytes[count] = value % 256;
      count++;
      value = Math.floor(value / 256);
    }
    return new Uint8Array(bytes);
  }
  if (typeof value === "bigint") {
    const bytes: number[] = [];
    let count = 0;
    while (value !== 0n) {
      bytes[count] = Number(value % 256n);
      count++;
      value = value / 256n;
    }
    return new Uint8Array(bytes);
  } else {
    return new Uint8Array([Number(value)]);
  }
}

function bytesToBigint(uint8arr: Uint8Array) {
  let result = BigInt(0);
  for (let i = uint8arr.length - 1; i >= 0; i--) {
    result = result * BigInt(256) + BigInt(uint8arr[i]!);
  }
  return result;
}

function toBigint(value: string | number | bigint | boolean, opt?: ConvertOpt): bigint {
  return bytesToBigint(valueToBytes(value, opt));
}

const Program = Experimental.ZkProgram({
  methods: {
    toProof: {
      privateInputs: [
        PublicKey,
        Signature,
        Field,
        Field,
        Field,
        Field,
        Field,
        Field,
        Field,
        Field,
        Field
      ],
      method(
        key: PublicKey,
        sign: Signature,
        issuerType: Field,
        issuerKey: Field,
        schema: Field,
        issuanceDate: Field,
        expirationDate: Field,
        subjectType: Field,
        subjectKey: Field,
        twitterId: Field,
        twitterName: Field
      ) {
        issuerType.assertEquals(new Field(1));
        twitterId.assertEquals(twitteridFD);
        twitterName.assertEquals(usernameFD);
        const msg = Poseidon.hash([
          issuerType, issuerKey, schema, issuanceDate, expirationDate, subjectType, subjectKey, twitterId, twitterName
        ]);
        const verified = sign.verify(key, [msg]);
        verified.assertTrue();
      }
    }
  }
});

const compileStart = new Date().getTime();
console.log(`Compilation start, time = ${compileStart} MS`);
const {} = await Program.compile();
console.log(`Compilation finished, spent = ${new Date().getTime() - compileStart} MS`);

async function main() {
  const fields = toFields(credential);
  const msg = Poseidon.hash(fields);
  const sign = Signature.create(isrPrivKey, [msg]);

  const proofStart = new Date().getTime();
  console.log(`Create proof start, time = ${proofStart} MS`);
  const proof = await Program.toProof(isrPubKey, sign, ...fields);
  console.log(`Proof created, spent = ${new Date().getTime() - proofStart} MS`);

  const verifyStart = new Date().getTime();
  console.log(`Verify proof start, time = ${verifyStart} MS`);
  const verified = await Program.verify(proof);
  console.log(`Proof verified, spent = ${new Date().getTime() - verifyStart} MS`);
  console.log("Verify result:", verified);
}

await main();