import bigInt = require('big-integer')
import * as encoding from 'text-encoding';

export interface IRecord {
  readonly perpId: string;
  readonly userId: string;
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

export class umbral {
  private sodium = null;

  private HEX: number = 16;
  private PRIME: bigInt.BigInteger = bigInt(
    '115792089237316195423570985008687907853269984665640564039457584007913129639936',
  ).plus(bigInt(297));

  /**
   * Initializes sodium
   * @param sodium initialized sodium instance
   */
  constructor(sodium) {
    this.sodium = sodium;
  }

   /**
    * Encrypts a user's record
    * @param {Uint8Array} randId - random ID (pHat)
    * @param {IRecord} record - user record
    * @param {Uint8Array[]} pkOCs - options counselor public keys
    * @param {Uint8Array} skUser - user's secret key
    * @returns {IEncryptedData[]} an array of records encrypted under each public key
    */
  public encryptData(randId: Uint8Array, record: IRecord, pkOCs: Uint8Array[], skUser: Uint8Array): IEncryptedData[] {
    if (pkOCs.length < 1) {
      return [];
    }

    const slope: bigInt.BigInteger = bigInt(this.bytesToString(this.sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId)));
    const k: Uint8Array = this.sodium.crypto_kdf_derive_from_key(32, 2, "derivation", randId);
    const matchingIndex: string = this.sodium.to_base64(this.sodium.crypto_kdf_derive_from_key(32, 3, "derivation", randId));

    const U: bigInt.BigInteger = bigInt(this.sodium.to_hex(this.sodium.crypto_hash(record.userId).slice(0, 32)), this.HEX);
    const kStr: string = this.bytesToString(k);
    const s: bigInt.BigInteger = (slope.times(U).plus(bigInt(kStr))).mod(this.PRIME);
    const recordKey: Uint8Array = this.sodium.crypto_secretbox_keygen();

    const eRecord: string = this.symmetricEncrypt(recordKey, JSON.stringify(record));
    const eRecordKey: string = this.symmetricEncrypt(k, this.sodium.to_base64(recordKey));
  
    const msg: IShare = { 
      x: U, 
      y: s, 
      eRecordKey };

    let encryptedData: IEncryptedData[] = [];

    for (const i in pkOCs) {
      let eOC = this.asymmetricEncrypt(JSON.stringify(msg), pkOCs[i], skUser);
      encryptedData.push({matchingIndex, eOC, eRecord});
    }

    return encryptedData;
  }  

  /**
   * Mathematically correct mod over a prime
   * @param {bigInt.BigInteger} val - input value 
   * @returns {bigInt.BigInteger}
   */
  private realMod(val: bigInt.BigInteger): bigInt.BigInteger {
    return val.mod(this.PRIME).add(this.PRIME).mod(this.PRIME);
  }

  /**
   * Computes a slope using two points
   * @param {IShare} c1 - 1st coordinate
   * @param {IShare} c2 - 2nd coordinate
   * @returns {bigInt.BigInteger} slope value
   */
  private deriveSlope(c1: IShare, c2: IShare): bigInt.BigInteger {
    const top: bigInt.BigInteger = this.realMod(c2.y.minus(c1.y));
    const bottom: bigInt.BigInteger = this.realMod(c2.x.minus(c1.x));

    return top.multiply(bottom.modInv(this.PRIME)).mod(this.PRIME);
  }

  /**
   * Checks that all entries have matching index
   * @param encryptedData 
   */
  private checkMatches(encryptedData) {
    if (encryptedData.length < 2) {
      throw new Error('Not enough matches');
    }

    var m = encryptedData[0].matchingIndex;
    for (var i = 0; i < encryptedData.length; i++) {
      if (m != encryptedData[0].matchingIndex) {
        throw new Error('Incorrect match found');
      }
    }
  }

  /**
   * Decrypts an array of encrypted data
   * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users
   * @param {Uint8Array} skOC - secret key of an options counselor
   * @param {Uint8Array[]} pkUser - user's public key
   * @returns {IRecord[]} array of decrypted records from matched users
   */
  public decryptData(encryptedData: IEncryptedData[], skOC: Uint8Array, pkUsers: Uint8Array[]): IRecord[] {

    this.checkMatches(encryptedData);
    if (encryptedData.length != pkUsers.length) {
      throw new Error('Number of matches does not equal number of public keys for users');
    }

    let shares: IShare[] = [];

    for (let i in encryptedData) {
      shares.push(this.asymmetricDecrypt(encryptedData[i], skOC, pkUsers[i]));
    }
  
    const slope: bigInt.BigInteger = this.deriveSlope(shares[0], shares[1]);
    const intercept: bigInt.BigInteger = this.getIntercept(shares[0], slope);

    const k: Uint8Array = this.stringToBytes(intercept.toString());

    const records: string[] = [];

    for (let i = 0; i < encryptedData.length; i++) {
      records.push(encryptedData[i].eRecord)
    }
 
    const decryptedRecords: IRecord[] = this.decryptRecords(shares, records, k);

    return decryptedRecords;
    
  }


  /**
   * Symmetric decryption
   * @param {Uint8Array} key 
   * @param {string} cipherText - in base 64 encoding with a nonce split on ("$")
   * @return {Uint8Array} decrypted data
   */
  private symmetricDecrypt(key: Uint8Array, cipherText: string): Uint8Array {
    const split: string[] = cipherText.split("$");

    if (key.length !== this.sodium.crypto_box_SECRETKEYBYTES) {
      return undefined;
    }

    const cT: Uint8Array = this.sodium.from_base64(split[0]);
    const nonce: Uint8Array = this.sodium.from_base64(split[1]);
    const decrypted: Uint8Array = this.sodium.crypto_secretbox_open_easy(cT, nonce, key);

    return decrypted;
  }

  /**
   * Decrypt all records
   * @param {IShare[]} data - coordinates
   * @param {string[]} eRecords - encrypted records
   * @param {Uint8Array} k - derived key from linear interpolation
   * @returns {IRecord[]} decrypted records
   */
  private decryptRecords(data: IShare[], eRecords: string[], k: Uint8Array): IRecord[] {

    const decryptedRecords: IRecord[] = [];

    for (const i in data) {
      const recordKey: Uint8Array = this.symmetricDecrypt(k, data[i].eRecordKey);
      const decryptedRecord: Uint8Array = this.symmetricDecrypt(this.sodium.from_base64(recordKey), eRecords[i]);
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
  private stringToBytes(str: string): Uint8Array {
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
  private getIntercept(c1: IShare, slope: bigInt.BigInteger): bigInt.BigInteger {
    const x: bigInt.BigInteger = c1.x;
    const y: bigInt.BigInteger = c1.y;
    const mult: bigInt.BigInteger = (slope.times(x));

    return this.realMod(y.minus(mult));
  }

  /**
   * Asymmetric decryption
   * @param {IEncryptedData} encryptedData 
   * @param {Uint8Array} skOC - secret key of an options counselor
   * @param {Uint8Array} pkUser - public key of a user
   * @returns {IShare} a decrypted coordinate
   */
  private asymmetricDecrypt(encryptedData: IEncryptedData, skOC: Uint8Array, pkUser: Uint8Array): IShare {

    const split: string[] = encryptedData.eOC.split("$");
    const c: Uint8Array = this.sodium.from_base64(split[0]);
    const nonce: Uint8Array = this.sodium.from_base64(split[1]);
    const msg: Uint8Array = this.sodium.crypto_box_open_easy(c, nonce, pkUser, skOC);
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
  private asymmetricEncrypt(message: string, pkOC: Uint8Array, skUser: Uint8Array): string {

    const nonce: Uint8Array = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);
    const cY: Uint8Array = this.sodium.crypto_box_easy(
      message, nonce, pkOC, skUser);
    const encrypted: string = this.sodium.to_base64(cY) + "$" + this.sodium.to_base64(nonce);

    return encrypted;
  }

  /**
   * Symmetric encryption
   * @param {Uint8Array} key  
   * @param {string} msg plaintext string
   * @returns {string} encrypted string in base 64 encoding
   */
  private symmetricEncrypt(key: Uint8Array, msg: string): string {
    const nonce: Uint8Array = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);
    const cT: Uint8Array = this.sodium.crypto_secretbox_easy(msg, nonce, key);
    const encrypted: string = this.sodium.to_base64(cT) + "$" + this.sodium.to_base64(nonce);

    return encrypted;
  }

  /**
   * Converts bytes to their string representation of a number
   * @param {Uint8Array} bytes 
   * @returns {string}
   */
  private bytesToString(bytes: Uint8Array): string {
    let result: bigInt.BigInteger = bigInt(0);

    for (let i: number = bytes.length - 1; i >= 0; i--) {
      result = result.or(bigInt(bytes[i]).shiftLeft((i * 8)));
    }

    return result.toString();
  }
}




