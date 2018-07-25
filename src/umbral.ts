import bigInt = require('big-integer')
import * as encoding from 'text-encoding';

export interface IRecord {
  readonly perpId: string; 
  readonly userId: string;
}

export interface IEncryptedData {
  readonly matchingIndex: string; // pi
  readonly eOC: string; // c
  readonly eUser: string; // c'user
  eRecord: string;

}

interface IShare {
  readonly x: bigInt.BigInteger;
  readonly y: bigInt.BigInteger
  readonly eRecordKey: string;
}

interface IDerivedValues {
  readonly slope: bigInt.BigInteger;
  readonly k: Uint8Array;
  readonly matchingIndex: string
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

  private concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
    let concat: number[] = [];
    for (var i = 0; i < a.length; i++) {
      concat.push((a[i] + b[i]) % 255);
    }

    return new Uint8Array(concat);
  }

  private deriveValues(randId: Uint8Array): IDerivedValues {
    // TODO: derive slope from key??

    try {
      const a: Uint8Array = this.sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId);
      const k: Uint8Array = this.sodium.crypto_kdf_derive_from_key(32, 2, "derivation", randId);
      const matchingIndex: string = this.sodium.to_base64(this.sodium.crypto_kdf_derive_from_key(32, 3, "derivation", this.concatArrays(a, k)));
      
      const slope: bigInt.BigInteger = bigInt(this.bytesToString(a));
      return {
        slope, k, matchingIndex
      }  
    } catch(e) {
      throw e;
    }

  }

   /**
    * Encrypts a user's record
    * @param {Uint8Array} randId - random ID (pHat)
    * @param {IRecord} record - user record
    * @param {Uint8Array[]} pkOCs - options counselor public keys
    * @param {Uint8Array} skUser - user's secret key
    * @returns {IEncryptedData[]} an array of records encrypted under each public key
    */
  public encryptData(randId: Uint8Array, record: IRecord, pkOCs: Uint8Array[], skUser: Uint8Array, userPassPhrase: Uint8Array): IEncryptedData[] {
    if (pkOCs.length < 1) {
      throw new Error('No OC public key provided');
    }

    const derived: IDerivedValues = this.deriveValues(randId);

    // TODO: make sure U is 32 bytes (use different function?)
    const U: bigInt.BigInteger = bigInt(this.sodium.to_hex(this.sodium.crypto_hash(record.userId).slice(0, 32)), this.HEX);
    const kStr: string = this.bytesToString(derived.k);
    const s: bigInt.BigInteger = (derived.slope.times(U).plus(bigInt(kStr))).mod(this.PRIME);
    const recordKey: Uint8Array = this.sodium.crypto_secretbox_keygen();

    // TODO: should we authenticate data w/ eRecord?
    const eRecord: string = this.symmetricEncrypt(recordKey, JSON.stringify(record), null);
    const eRecordKey: string = this.symmetricEncrypt(derived.k, this.sodium.to_base64(recordKey), derived.matchingIndex);
    const eUser: string = this.symmetricEncrypt(userPassPhrase, this.sodium.to_base64(eRecordKey), derived.matchingIndex);
    
    const msg: IShare = { 
      x: U, 
      y: s, 
      eRecordKey };

    let encryptedData: IEncryptedData[] = [];

    for (const i in pkOCs) {
      let eOC = this.asymmetricEncrypt(JSON.stringify(msg), pkOCs[i], skUser);
      encryptedData.push({matchingIndex: derived.matchingIndex, eOC, eRecord, eUser});
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
    
    for (var i = 1; i < encryptedData.length; i++) {
      if (m != encryptedData[i].matchingIndex) {
        throw new Error('Incorrect match found');
      }
    }
  }

  /**
   * Decrypts a user's record for editing purposes 
   * @param {Uint8Array} userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @returns {IRecord[]} an array of decrypted records (should contain same content)
   */
  public decryptUserRecord(userPassPhrase: Uint8Array, userEncryptedData: IEncryptedData[]): IRecord[] {

    // NOTE: is it necessary to do this for ALL oc keys?
    const decryptedRecords: IRecord[] = [];

    for (let i in userEncryptedData) {
      const eUser = userEncryptedData[i].eUser;

      const recordKey: Uint8Array = this.symmetricDecrypt(userPassPhrase, eUser, null);
      decryptedRecords.push(this.decryptRecord(this.sodium.from_base64(recordKey), userEncryptedData[i].eRecord));
    }

    return decryptedRecords;
  }

  /**
   * 
   * @param {Uint8Array} userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @param {IRecord} updatedRecord - a user's updated record
   * @returns {IEncryptedData[]} an array of encrypted data containing the cipher text of the updated record
   */
  public updateUserRecord(userPassPhrase: Uint8Array, userEncryptedData: IEncryptedData[], updatedRecord: IRecord): IEncryptedData[] {

    for (let i in userEncryptedData) {

      const eUser = userEncryptedData[i].eUser;
      const recordKey: Uint8Array = this.symmetricDecrypt(userPassPhrase, eUser, userEncryptedData[i].matchingIndex);
      const eRecord: string = this.symmetricEncrypt(recordKey, JSON.stringify(updatedRecord), null);

      userEncryptedData[i].eRecord = eRecord;
    }
    return userEncryptedData;
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
   // TODO: test all pairs?
   // ignore ciphertexts that fail to decrypt 
   // check share[i] with every other index, decrypt record[i] with each key (once one succeeds, answer is correct, stop.) 
    const slope: bigInt.BigInteger = this.deriveSlope(shares[0], shares[1]);
    const intercept: bigInt.BigInteger = this.getIntercept(shares[0], slope);

    const k: Uint8Array = this.stringToBytes(intercept.toString());

    let decryptedRecords: IRecord[] = [];

    for (const i in encryptedData) {

      const recordKey: Uint8Array = this.symmetricDecrypt(k, shares[i].eRecordKey, encryptedData[i].matchingIndex);
      decryptedRecords.push(this.decryptRecord(this.sodium.from_base64(recordKey), encryptedData[i].eRecord));
    }

    return decryptedRecords;
    
  }


  /**
   * Symmetric decryption
   * @param {Uint8Array} key 
   * @param {string} cipherText - in base 64 encoding with a nonce split on ("$")
   * @return {Uint8Array} decrypted data
   */
  private symmetricDecrypt(key: Uint8Array, cipherText: string, ad: string): Uint8Array {
    try {
      const split: string[] = cipherText.split("$");

      if (key.length !== this.sodium.crypto_box_SECRETKEYBYTES) {
        throw new Error('Improper key length for symmetric decryption');
      }
  
      const cT: Uint8Array = this.sodium.from_base64(split[0]);
      const nonce: Uint8Array = this.sodium.from_base64(split[1]);

      const decrypted: Uint8Array = this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cT, ad, nonce, key);

      // const decrypted: Uint8Array = this.sodium.crypto_secretbox_open_easy(cT, nonce, key);
  
      return decrypted;
    } catch (e) {
      throw e;
    }
  }

  /**
   * Decrypts a single record
   * @param {Uint8Array} recordKey 
   * @param {string} eRecord 
   * @returns {IRecord} decrypted record
   */
  private decryptRecord(recordKey: Uint8Array, eRecord): IRecord {
    const decryptedRecord: Uint8Array = this.symmetricDecrypt(recordKey, eRecord, null);
    const dStr: string = new encoding.TextDecoder("utf-8").decode(decryptedRecord);
    return JSON.parse(dStr);
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

    try {
      const split: string[] = encryptedData.eOC.split("$");
      const c: Uint8Array = this.sodium.from_base64(split[0]);
      const nonce: Uint8Array = this.sodium.from_base64(split[1]);
      const msg: Uint8Array = this.sodium.crypto_box_open_easy(c, nonce, pkUser, skOC);
      const msgObj: IShare = JSON.parse(new encoding.TextDecoder("utf-8").decode(msg));  
      
      return {
        x: bigInt(msgObj.x),
        y: bigInt(msgObj.y),
        eRecordKey: msgObj.eRecordKey
      };
    } catch(e) {
      throw e;
    }
  }

  /**
   * Asymmetric encryption
   * @param {string} message - a plaintext string
   * @param {Uint8Array} pkOC - the public key of an options counselor
   * @param {Uint8Array} skUser - secret key of a user
   * @returns {string} encrypted string in base 64 encoding 
   */
  private asymmetricEncrypt(message: string, pkOC: Uint8Array, skUser: Uint8Array): string {

    try {
      const nonce: Uint8Array = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);
      const cY: Uint8Array = this.sodium.crypto_box_easy(
        message, nonce, pkOC, skUser);
      const encrypted: string = this.sodium.to_base64(cY) + "$" + this.sodium.to_base64(nonce);
      
      return encrypted;
    } catch(e) {
      throw(e);
    }
  }

  /**
   * Symmetric encryption
   * @param {Uint8Array} key  
   * @param {string} msg plaintext string
   * @returns {string} encrypted string in base 64 encoding
   */
  private symmetricEncrypt(key: Uint8Array, msg: string, ad: string): string {
    try {
      const nonce: Uint8Array = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);

      // TODO: double check that args are in correct order
      const cT: Uint8Array = this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, null, nonce, key);

 

      // const cT: Uint8Array = this.sodium.crypto_secretbox_easy(msg, nonce, key);


      const encrypted: string = this.sodium.to_base64(cT) + "$" + this.sodium.to_base64(nonce);

      return encrypted;
    } catch(e) {
      throw e;
    }
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




