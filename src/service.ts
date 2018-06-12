import bigInt = require('big-integer')
import * as $ from 'jquery';
import _sodium = require('libsodium-wrappers');
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

export namespace CryptoService {
  let sodium = null;

  const HEX: number = 16;

  const PRIME: bigInt.BigInteger = bigInt(
    '115792089237316195423570985008687907853269984665640564039457584007913129639936',
  ).plus(bigInt(297));

  export function init(_sodium): void {
    sodium = _sodium;
  }

  /**
   * Function for taking user inputs and returning values to be encrypted
   * @param {string} perpId - inputted perpetrator name
   * @param {string} userName - inputted user name
   * @returns {IPlainTextData} promise resolving a IPlainTextData object
   */
  export function encryptData(randId: Uint8Array, record: IRecord, publicKeys: Uint8Array[], skUser: Uint8Array): IEncryptedData[] {
    if (publicKeys.length < 1) {
      return undefined;
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

    for (const i in publicKeys) {
      let eOC = asymmetricEncrypt(JSON.stringify(msg), publicKeys[i], skUser);
      encryptedData.push({matchingIndex, eOC, eRecord});
    }

    return encryptedData;
  }  


    /**
   * Get real mod of value, instead of bigInt's mod() which returns the remainder.
   * Necessary for negative values.
   * @param {bigInt} val Input value
   * @returns {bigInt.BigInteger} Value with real mod applied
   */
  function realMod(val: bigInt.BigInteger): bigInt.BigInteger {
    return val.mod(PRIME).add(PRIME).mod(PRIME);
  }

  /**
   * Computes a slope based on the slope formula
   * @param {IShare} c1 - 1st coordinate
   * @param {IShare} c2 - 2nd coordinate
   * @returns {bigInt.BigInteger} slope value
   */
  function deriveSlope(c1: IShare, c2: IShare): bigInt.BigInteger {
    const top: bigInt.BigInteger = realMod(c2.y.minus(c1.y));
    const bottom: bigInt.BigInteger = realMod(c2.x.minus(c1.x));

    return top.multiply(bottom.modInv(PRIME)).mod(PRIME);
  }


  export function decryptData(encryptedData: IEncryptedData[], skOC: Uint8Array, pkUser: Uint8Array): IRecord[] {
   
    if (encryptedData.length < 2) {
      return null;
    }

    let shares: IShare[] = [];

    for (var i in encryptedData) {
      shares.push(asymmetricDecrypt(encryptedData[i], skOC, pkUser));
    }
    const slope: bigInt.BigInteger = deriveSlope(shares[0], shares[1]);
    const intercept: bigInt.BigInteger = getIntercept(shares[0], slope);

    const k: Uint8Array = stringToBytes(intercept.toString());
 
    const decryptedRecords: IRecord[] = decryptRecords(shares, [encryptedData[0].eRecord, encryptedData[1].eRecord], k);



    return decryptedRecords;
    
  }


  /**
   * Symmetric decryption
   * @param {string} key - base 64 encoding
   * @param {string} cipherText - base 64 encoding
   * @returns {Uint8Array} decrypted value
   */
  function symmetricDecrypt(key: Uint8Array, cipherText: string): Uint8Array {
    const split: string[] = cipherText.split("$");

    if (key.length !== sodium.crypto_box_SECRETKEYBYTES) {
      return undefined;
    }

    // Uint8Arrays
    const cT: Uint8Array = sodium.from_base64(split[0]);
    const nonce: Uint8Array = sodium.from_base64(split[1]);
    const decrypted: Uint8Array = sodium.crypto_secretbox_open_easy(cT, nonce, key);

    return decrypted;
  }

  /**
   * Handles record decryption based on RID
   * @param {Array<IEncryptedData>} data - matched encrypted data
   * @param {string} rid - randomized perpetrator ID
   * @returns {Array<IRecord>} array of decrypted records
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
   * Converts a string representing an integer to a Uint8Array
   * @param {string} intercept
   * @returns {Uint8Array} 32-byte key
   */
  function stringToBytes(intercept: string): Uint8Array {
    let value: bigInt.BigInteger = bigInt(intercept);
    const result: number[] = [];

    for (let i: number = 0; i < 32; i++) {
      result.push(parseInt(value.and(255).toString(), 10));
      value = value.shiftRight(8);
    }

    return Uint8Array.from(result);
  }



    /**
   * Computes RID, which is the y-intercept
   * @param {IShare} c1 - a given coordinate
   * @param {bigInt.BigInteger} slope
   */
  function getIntercept(c1: IShare, slope: bigInt.BigInteger): bigInt.BigInteger {
    const x: bigInt.BigInteger = c1.x;
    const y: bigInt.BigInteger = c1.y;
    const mult: bigInt.BigInteger = (slope.times(x));

    return realMod(y.minus(mult));
  }




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
   * Encrypts y using public-key encryption with the OC's public key
   * @param {bigInt.BigInteger} y - value derived from mx + RID
   * @returns {string} the encrypted value in base 64 encoding
   */
  function asymmetricEncrypt(message: string, pkOC: Uint8Array, skUser): string {

    const nonce: Uint8Array = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const cY: Uint8Array = sodium.crypto_box_easy(
      message, nonce, pkOC, skUser);
    const encrypted: string = sodium.to_base64(cY) + "$" + sodium.to_base64(nonce);

    return encrypted;
  }

  /**
   * Symmetric encryption using given key
   * @param {Uint8Array} key - 32 byte key
   * @param {string} msg
   * @returns {string} ciphertext concatenated with a nonce, both in base 64 encoding
   */
  function symmetricEncrypt(key: Uint8Array, msg: string): string {
    const nonce: Uint8Array = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const cT: Uint8Array = sodium.crypto_secretbox_easy(msg, nonce, key);
    const encrypted: string = sodium.to_base64(cT) + "$" + sodium.to_base64(nonce);

    return encrypted;
  }




  /**
   * Converts a Uint8Array to a string representation of its integer value
   * @param {Uint8Array} k - 32 byte key
   * @returns {string}
   */
  function bytesToString(k: Uint8Array): string {
    let result: bigInt.BigInteger = bigInt(0);

    for (let i: number = k.length - 1; i >= 0; i--) {
      result = result.or(bigInt(k[i]).shiftLeft((i * 8)));
    }

    return result.toString();
  }
}




