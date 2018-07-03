import bigInt = require('big-integer')
import * as encoding from 'text-encoding';

export interface IRecord {
  perpId: string;
  userId: string;
}

export interface IEncryptedData {
  readonly matchingIndex: string;
  readonly eOC: string;
  readonly eRecord: string;
}

export interface IDecryptedData {
  readonly decryptedRecords: object;
  readonly slope: bigInt.BigInteger;
  readonly intercept: bigInt.BigInteger;
  readonly k: Uint8Array;
}

interface IShare {
  readonly x: bigInt.BigInteger;
  readonly y: bigInt.BigInteger
  readonly eRecordKey: string;
}

export namespace umbral {
  /* Uninitialized sodium instance */
  let sodium = null;

  const HEX: number = 16;
  const PRIME: bigInt.BigInteger = bigInt(
    '115792089237316195423570985008687907853269984665640564039457584007913129639936',
  ).plus(bigInt(297));

  /**
   * Initializes sodium
   * @param _sodium initialized sodium instance
   */
  export function init(_sodium): void {
    sodium = _sodium;
  }

   /**
    * Encrypts a user's record
    * @param {Uint8Array} randId - random ID
    * @param {IRecord} record - user record
    * @param {Uint8Array[]} pkOCs - options counselor public keys
    * @param {Uint8Array} skUser - user's secret key
    * @returns {IEncryptedData[]} an array of records encrypted under each public key
    */
  export function encryptData(randId: Uint8Array, record: IRecord, pkOCs: Uint8Array[], skUser: Uint8Array): IEncryptedData[] {
    if (pkOCs.length < 1) {
      return [];
    }

    const slope: bigInt.BigInteger = bigInt(bytesToString(sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId)));
    const k: Uint8Array = sodium.crypto_kdf_derive_from_key(32, 2, "derivation", randId);
    const matchingIndex: string = sodium.to_base64(sodium.crypto_kdf_derive_from_key(32, 3, "derivation", randId));

    const U: bigInt.BigInteger = bigInt(sodium.to_hex(sodium.crypto_hash(record.userId).slice(0, 32)), HEX);
    const kStr: string = bytesToString(k);
    const s: bigInt.BigInteger = (slope.times(U).plus(bigInt(kStr))).mod(PRIME);
    const recordKey: Uint8Array = sodium.crypto_secretbox_keygen();

    const eRecord: string = symmetricEncrypt(recordKey, JSON.stringify(record));
    const eRecordKey: string = symmetricEncrypt(k, sodium.to_base64(recordKey));
  
    const msg: IShare = { 
      x: U, 
      y: s, 
      eRecordKey };

    let encryptedData: IEncryptedData[] = [];

    for (const i in pkOCs) {
      let eOC = asymmetricEncrypt(JSON.stringify(msg), pkOCs[i], skUser);
      encryptedData.push({matchingIndex, eOC, eRecord});
    }

    return encryptedData;
  }  

  /**
   * Mathematically correct mod over a prime
   * @param {bigInt.BigInteger} val - input value 
   * @returns {bigInt.BigInteger}
   */
  function realMod(val: bigInt.BigInteger): bigInt.BigInteger {
    return val.mod(PRIME).add(PRIME).mod(PRIME);
  }

  /**
   * Computes a slope using two points
   * @param {IShare} c1 - 1st coordinate
   * @param {IShare} c2 - 2nd coordinate
   * @returns {bigInt.BigInteger} slope value
   */
  function deriveSlope(c1: IShare, c2: IShare): bigInt.BigInteger {
    const top: bigInt.BigInteger = realMod(c2.y.minus(c1.y));
    const bottom: bigInt.BigInteger = realMod(c2.x.minus(c1.x));

    return top.multiply(bottom.modInv(PRIME)).mod(PRIME);
  }

  /**
   * Decrypts an array of encrypted data
   * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users
   * @param {Uint8Array} skOC - secret key of an options counselor
   * @param pkUser - user's private key
   * @returns {IRecord[]} array of decrypted records from matched users
   */
  export function decryptData(encryptedData: IEncryptedData[], skOC: Uint8Array, pkUser: Uint8Array): IRecord[] {
   
    // TODO: CHECK MATCHES
    if (encryptedData.length < 2) {
      return null;
    }

    let shares: IShare[] = [];

    for (var i in encryptedData) {
      shares.push(asymmetricDecrypt(encryptedData[i], skOC, pkUser));
    }
    // todo: rename 0 and 1 to indicate they are parties
    const slope: bigInt.BigInteger = deriveSlope(shares[0], shares[1]);
    const intercept: bigInt.BigInteger = getIntercept(shares[0], slope);

    const k: Uint8Array = stringToBytes(intercept.toString());
 
    // todo: double check this function call is with 2 points
    const decryptedRecords: IRecord[] = decryptRecords(shares, [encryptedData[0].eRecord, encryptedData[1].eRecord], k);

    return decryptedRecords;
    
  }


  /**
   * Symmetric decryption
   * @param {Uint8Array} key 
   * @param {string} cipherText - in base 64 encoding with a nonce split on ("$")
   * @return {Uint8Array} decrypted data
   */
  function symmetricDecrypt(key: Uint8Array, cipherText: string): Uint8Array {
    const split: string[] = cipherText.split("$");

    if (key.length !== sodium.crypto_box_SECRETKEYBYTES) {
      return undefined;
    }

    const cT: Uint8Array = sodium.from_base64(split[0]);
    const nonce: Uint8Array = sodium.from_base64(split[1]);
    const decrypted: Uint8Array = sodium.crypto_secretbox_open_easy(cT, nonce, key);

    return decrypted;
  }

  /**
   * Decrypt all records
   * @param {IShare[]} data - coordinates
   * @param {string[]} eRecords - encrypted records
   * @param {Uint8Array} k - derived key from linear interpolation
   * @returns {IRecord[]} decrypted records
   */
  function decryptRecords(data: IShare[], eRecords: string[], k: Uint8Array): IRecord[] {

    const decryptedRecords: IRecord[] = [];

    for (const i in data) {
      const recordKey: Uint8Array = symmetricDecrypt(k, data[i].eRecordKey);
      const decryptedRecord: Uint8Array = symmetricDecrypt(sodium.from_base64(recordKey), eRecords[i]);
      const dStr: string = new encoding.TextDecoder("utf-8").decode(decryptedRecord);
      decryptedRecords.push(JSON.parse(dStr));
    }
    return decryptedRecords;
  }


  /**
   * Converts a string representation of a number to a Uint8Array of bytes
   * @param str - string representation
   * @returns {Uint8Array}
   */
  function stringToBytes(str: string): Uint8Array {
    let value: bigInt.BigInteger = bigInt(str);
    const result: number[] = [];

    for (let i: number = 0; i < 32; i++) {
      result.push(parseInt(value.and(255).toString(), 10));
      value = value.shiftRight(8);
    }

    return Uint8Array.from(result);
  }

  /**
   * Calculates the y-intercept using a coordinate and slope
   * @param {IShare} c1 - a coordinate
   * @param {bigInt.BigInteger} slope 
   * @returns {bigInt.BigInteger} y-intercept
   */
   function getIntercept(c1: IShare, slope: bigInt.BigInteger): bigInt.BigInteger {
    const x: bigInt.BigInteger = c1.x;
    const y: bigInt.BigInteger = c1.y;
    const mult: bigInt.BigInteger = (slope.times(x));

    return realMod(y.minus(mult));
  }

  /**
   * Asymmetric decryption
   * @param {IEncryptedData} encryptedData 
   * @param {Uint8Array} skOC - secret key of an options counselor
   * @param {Uint8Array} pkUser - public key of a user
   * @returns {IShare} a decrypted coordinate
   */
  function asymmetricDecrypt(encryptedData: IEncryptedData, skOC: Uint8Array, pkUser: Uint8Array): IShare {

    const split: string[] = encryptedData.eOC.split("$");
    const c: Uint8Array = sodium.from_base64(split[0]);
    const nonce: Uint8Array = sodium.from_base64(split[1]);
    const msg: Uint8Array = sodium.crypto_box_open_easy(c, nonce, pkUser, skOC);
    // todo: need type for msg obj
    const msgObj = JSON.parse(new encoding.TextDecoder("utf-8").decode(msg));
  
    return {
      x: bigInt(msgObj.x),
      y: bigInt(msgObj.y),
      eRecordKey: msgObj.eRecordKey
    };
  }




  /**
   * Asymmetric encryption
   * @param {string} message - a plaintext string
   * @param {Uint8Array} pkOC - the public key of an options counselor
   * @param {Uint8Array} skUser - secret key of a user
   * @returns {string} encrypted string in base 64 encoding 
   */
  function asymmetricEncrypt(message: string, pkOC: Uint8Array, skUser: Uint8Array): string {

    const nonce: Uint8Array = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const cY: Uint8Array = sodium.crypto_box_easy(
      message, nonce, pkOC, skUser);
    const encrypted: string = sodium.to_base64(cY) + "$" + sodium.to_base64(nonce);

    return encrypted;
  }

  /**
   * Symmetric encryption
   * @param {Uint8Array} key  
   * @param {string} msg plaintext string
   * @returns {string} encrypted string in base 64 encoding
   */
  function symmetricEncrypt(key: Uint8Array, msg: string): string {
    const nonce: Uint8Array = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const cT: Uint8Array = sodium.crypto_secretbox_easy(msg, nonce, key);
    const encrypted: string = sodium.to_base64(cT) + "$" + sodium.to_base64(nonce);

    return encrypted;
  }

  /**
   * Converts bytes to their string representation of a number
   * @param {Uint8Array} bytes 
   * @returns {string}
   */
  function bytesToString(bytes: Uint8Array): string {
    let result: bigInt.BigInteger = bigInt(0);

    for (let i: number = bytes.length - 1; i >= 0; i--) {
      result = result.or(bigInt(bytes[i]).shiftLeft((i * 8)));
    }

    return result.toString();
  }
}




