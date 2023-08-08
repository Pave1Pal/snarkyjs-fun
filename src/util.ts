import { ZKCredential } from "./main.js";
import sortKeys from "sort-keys";

const ZKC = {
  sort: <T extends ZKCredential>(credential: T): T => {
    const target: Record<string, any> = {};
    target.issuer = {
      id: {
        type: credential.issuer.id.type,
        publickey: credential.issuer.id.publickey
      }
    };

    target.schema = credential.schema;
    target.issuanceDate = credential.issuanceDate;
    target.expirationDate = credential.expirationDate;

    const subjectProps = Object.keys(credential.subject)
      .filter((key) => key !== "id")
      .reduce((subjectProps, prop) => {
        subjectProps[prop] = credential.subject[prop];
        return subjectProps;
      }, {} as Record<string, any>);

    target.subject = {
      id: {
        type: credential.subject.id.type,
        publickey: credential.subject.id.publickey
      },
      ...sortKeys(subjectProps, { deep: true })
    };
    return target as T;
  },

  toValues: (credential: ZKCredential) => {
    const sCredential = ZKC.sort(credential);
    return getValues(sCredential)
      .filter(value => value !== null) as (bigint | number | string | boolean)[];
  }

};


function getValues(obj: any, vector?: any[]): (bigint | number | string | boolean | null)[] {
  if (!vector) vector = [];
  if (!Array.isArray(obj)) {
    obj = Object.values(obj);
  }
  obj.forEach((value: any) => {
    if (typeof value === "object" && value !== null) {
      getValues(value, vector);
    } else if (typeof value !== "undefined") {
      vector?.push(value);
    }
  });
  return vector;
}


export const Util = {
  ZKC
};