import bigInt = require('big-integer');
import * as encoding from 'text-encoding';
import uuidv4 = require('uuid/v4');

/**
 * Encrypted data object
 */
export interface IEncryptedData {
  readonly eOC: string; // c
  eRecord: string;
  readonly eUser: string; // c'user
  readonly id: string; // id
  readonly matchingIndex: string; // pi
}

/**
 * Mapping of OC id to matching records
 */
export interface IOCDataMap {
  [OCid: string]: IEncryptedData[];
}

/**
 * Mapping of matching index to all matching records under a specific OC
 */
export interface IEncryptedMap {
  [matchingIndex: string]: IOCDataMap;
}

/**
 * Data object returned from encryption workflow
 */
export interface IEncrypted {
  readonly encryptedMap: IEncryptedMap;
  readonly malformed: IMalformed[];
}

/**
 * Object for storing errors
 */
export interface IMalformed {
  readonly id: string;
  readonly error: string;
}

/**
 * Data returned from decryption workflow
 */
export interface IDecrypted {
  readonly data: string[];
  readonly malformed: IMalformed[]; // ids
}

/**
 * Dictionary of {id, key}
 */
export interface IKey {
  [id: string]: Uint8Array;
}

/**
 * Share used for interpolation
 */
interface IShare {
  readonly x: bigInt.BigInteger;
  readonly y: bigInt.BigInteger;
  readonly eRecordKey: string;
}

/**
 * Values from key derivation
 */
interface IDerivedValues {
  readonly slope: bigInt.BigInteger;
  readonly k: Uint8Array;
  readonly matchingIndex: string;
}

export class Umbral {
  private sodium = null;

  private HEX: number = 16;
  private PRIME: bigInt.BigInteger = bigInt(
      '115792089237316195423570985008687907853269984665640564039457584007913129639936'
  ).plus(bigInt(297));

  private KEY_BYTES: number = 32;
  private RECORD_STRING: string = 'record';
  private RECORD_KEY_STRING: string = 'record key';
  private USER_EDIT_STRING: string = 'user edit';

  /**
   * Initializes sodium
   * @param sodium initialized sodium instance
   */
  constructor(sodium) {
      this.sodium = sodium;
  }

  /**
   * Encryption workflow
   * @param randIds - array of all randIds corresponding to each perpId submitted
   * @param data - record information
   * @param pkOCs - dictionary of all OC public keys
   * @param userPassPhrase - user's passphrase for use in encrypting for editing
   * @returns {IEncrypted} object containing encrypted data and errors
   */
  public encryptData(randIds: Uint8Array[], userId: string, data: string, pkOCs: IKey,
                     userPassPhrase?: Uint8Array): IEncrypted {

    const encrypted: IEncrypted = { encryptedMap: {}, malformed: [] };
    if (Object.keys(pkOCs).length < 1) {
      encrypted.malformed.push({
        error: 'No public OC keys provided',
        id: 'All'
      });
      return encrypted;
    }

    if (data === '' || data === null) {
      encrypted.malformed.push({
        error: 'No data provided',
        id: 'encryptData'
      });
      return encrypted;
    }

    for (const randId of randIds) {
      this.createEncryptedObject(encrypted, randId, userId, data, pkOCs, userPassPhrase);
    }
    return encrypted;
  }

  public tryAndDecrypt(k, shares, encryptedData, decryptedData) {
    const encrypted = [];
    for (const e of encryptedData) {
      if (!(this.decryptShare(k, shares[e.id], e, decryptedData))) {
        encrypted.push(shares[e.id]);
      }
    }
    return encrypted;
  }

  /**
   * Decrypts an array of encrypted data
   * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users
   * @param pkOC - public key of an options counselor
   * @param skOC - secret key of an options counselor
   * @returns {IDecrypted]} object containing decrypted records and errors
   */
  public decryptData(encryptedData: IEncryptedData[], pkOC: Uint8Array, skOC: Uint8Array): IDecrypted {

    const decryptedData: IDecrypted = {
      data: [],
      malformed: this.checkMatches(encryptedData),
    };

    if (decryptedData.malformed.length === encryptedData.length || encryptedData.length < 2) {
      return decryptedData;
    }

    const shares = this.OCDecrypt(pkOC, skOC, encryptedData, decryptedData);

    while (encryptedData.length > 0) {
      const encrypted = encryptedData.pop();

      const s = shares[encrypted.id];
      delete shares[encrypted.id];
      let decryptedFlag = false;

      for (const e of encryptedData) {
        try {
          const k: Uint8Array = this.interpolateShares(s, shares[e.id]);
          if (this.decryptShare(k, s, encrypted, decryptedData)) {
            decryptedFlag = true;
            encryptedData = this.tryAndDecrypt(k, shares, encryptedData, decryptedData);
            break;
          }
        } catch (e) {
          // do nothing
        }
      }
      if (decryptedFlag === false) {
        decryptedData.malformed.push({
          error: 'Share could not be decrypted',
          id: encrypted.id
        });
      }
    }
    return decryptedData;
  }

  /**
   * Decrypts a user's record for editing purposes
   * @param userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @returns {IDecrypted} object containing decrypted records and errors
   */
  public decryptUserRecord(userPassPhrase: Uint8Array, userEncryptedData: IEncryptedData[]): IDecrypted {

    // NOTE: is it necessary to do this for ALL oc keys?
    const data: string[] = [];
    const malformed: IMalformed[] = [];

    for (const eUserData of userEncryptedData) {
      const eUser = eUserData.eUser;

      try {
        const recordKey: Uint8Array = this.symmetricDecrypt(userPassPhrase, eUser,
            this.USER_EDIT_STRING + eUserData.matchingIndex);
        data.push(this.decryptRecord(this.sodium.from_base64(recordKey), eUserData.eRecord,
            this.RECORD_STRING + eUserData.matchingIndex));
      } catch (e) {
        malformed.push({
          error: e,
          id: eUserData.id,
        });
      }
    }
    return {data, malformed};
  }

  /**
   *
   * @param userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @param updatedRecord - a user's updated record
   * @returns {IEncryptedData[]} an array of encrypted data containing the cipher text of the updated record
   */
  public updateUserRecord(userPassPhrase: Uint8Array,
                          userEncryptedData: IEncryptedData[],
                          updatedRecord: string): IMalformed[] {
    const malformed: IMalformed[] = [];

    for (const eUserData of userEncryptedData) {
      const eUser = eUserData.eUser;
      try {
        const recordKey = this.symmetricDecrypt(
          userPassPhrase,
          eUser,
          this.USER_EDIT_STRING + eUserData.matchingIndex
        );

        eUserData.eRecord = this.symmetricEncrypt(
          this.sodium.from_base64(recordKey),
          updatedRecord,
          this.RECORD_STRING + eUserData.matchingIndex
        );
      } catch (e) {
        malformed.push({
          error: e,
          id: eUserData.id,
        });
      }
    }
    return malformed;
  }

  /**
   * Decrypts a single share using the derived key, k
   * @param k - key used to decrypt the record key
   * @param s - current share
   * @param encrypted - encrypted data object corresponding to current share
   * @param decryptedData - object containing decrypted records and errors
   */
  private decryptShare(k: Uint8Array, s, encrypted, decryptedData) {
    try {
      const recordKey: Uint8Array = this.symmetricDecrypt(k, s.eRecordKey,
        this.RECORD_KEY_STRING + encrypted.matchingIndex);
      const decrypted = this.decryptRecord(this.sodium.from_base64(recordKey), encrypted.eRecord,
              this.RECORD_STRING + encrypted.matchingIndex);
      decryptedData.data.push(decrypted);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Asymmetrically decrypts all shares using an OC's keys
   * @param pkOC - public key of an options counselor
   * @param skOC - secret key of an options counselor
   * @param encryptedData - an array of encrypted data of matched users
   * @param decryptedData - object containg decrypted records and errors
   */
  private OCDecrypt(pkOC, skOC, encryptedData, decryptedData) {
    const shares: object = {};
    // decrypt all pieces of data using OC's private key
    for (const eData of encryptedData) {
      try {
        const id = eData.id;
        shares[id] = this.asymmetricDecrypt(eData, skOC, pkOC);
      } catch (e) {
        decryptedData.malformed.push({
          error: e,
          id: eData.id,
        });
      }
    }
    return shares;
  }

  /**
   * Key derivation
   * @param randId - result of OPRF
   * @returns {IDerivedValues} object containing key, matching index, and slope
   */
  private deriveValues(randId: Uint8Array): IDerivedValues {

    try {
      const a: Uint8Array = this.sodium.crypto_kdf_derive_from_key(this.KEY_BYTES, 1, 'slope derivation', randId);
      const k: Uint8Array = this.sodium.crypto_kdf_derive_from_key(this.KEY_BYTES, 2, 'key derivation', randId);
      const ak: Uint8Array = this.sodium.crypto_generichash(
          this.KEY_BYTES,
          this.sodium.to_base64(a) + this.sodium.to_base64(k)
      );
      const matchingIndex: string = this.sodium.to_base64(
        this.sodium.crypto_kdf_derive_from_key(this.KEY_BYTES, 3, 'matching index derivation', ak)
      );

      const slope: bigInt.BigInteger = bigInt(this.bytesToString(a));
      return {
        k,
        matchingIndex,
        slope,
      };
    } catch (e) {
      throw new Error('Key derivation failure');
    }
  }

  /**
   * Encrypting under a single randId and then updating the encrypted data object
   * @param encrypted - encrypted data object
   * @param randId - result of OPRF
   * @param record - user record
   * @param pkOCs - dictionary of all OC public keys
   * @param userPassPhrase - user passphrase
   */
  private createEncryptedObject(encrypted: IEncrypted,
                                randId: Uint8Array, userId: string,
                                data: string, pkOCs: IKey,
                                userPassPhrase: Uint8Array): void {
    try {
      const derived: IDerivedValues = this.deriveValues(randId);
      const U: bigInt.BigInteger = bigInt(this.sodium.to_hex(
        this.sodium.crypto_generichash(this.KEY_BYTES, userId)), this.HEX);

      const kStr: string = this.bytesToString(derived.k);
      const s: bigInt.BigInteger = (derived.slope.times(U).plus(bigInt(kStr))).mod(this.PRIME);
      const recordKey: Uint8Array = this.sodium.crypto_secretbox_keygen();

      const eRecordKey: string = this.symmetricEncrypt(
        derived.k,
        this.sodium.to_base64(recordKey),
        this.RECORD_KEY_STRING + derived.matchingIndex
      );

      let eUser: string = null;
      if (userPassPhrase) {
        eUser = this.symmetricEncrypt(
          userPassPhrase,
          this.sodium.to_base64(recordKey),
          this.USER_EDIT_STRING + derived.matchingIndex
        );
      }

      const msg: IShare = {
        eRecordKey,
        x: U,
        y: s,
      };
      const eRecord: string = this.symmetricEncrypt(
        recordKey,
        data,
        this.RECORD_STRING + derived.matchingIndex
      );

      const recordId: string = uuidv4();
      for (const id of Object.keys(pkOCs)) {
        const eOC = this.asymmetricEncrypt(JSON.stringify(msg), pkOCs[id]);
        if (!encrypted.encryptedMap[derived.matchingIndex]) {
          encrypted.encryptedMap[derived.matchingIndex] = {};
        }
        encrypted.encryptedMap[derived.matchingIndex][id] = [{eOC,
                                                        eRecord,
                                                        eUser,
                                                        id: recordId,
                                                        matchingIndex: derived.matchingIndex,
                                                      }];
      }
    } catch (e) {
      encrypted.malformed.push({
        error: e,
        id: 'encryption'
      });
    }
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
  private checkMatches(encryptedData): IMalformed[] {
    const malformed: IMalformed[] = [];
    const matchingDict = {};

    if (encryptedData.length < 2) {
      return [{
        error: 'Decryption requires at least 2 matches',
        id: '',
      }];
    }

    // sort all shares under matching index
    for (const eData of encryptedData) {
      const index = eData.matchingIndex;

      if (index in matchingDict) {
        matchingDict[index].push(eData);
      } else {
        matchingDict[index] = [eData];
      }
    }

    for (const index in matchingDict) {
      if (matchingDict[index].length === 1) {
        malformed.push({
          error: 'Matching index does not match with other shares',
          id: matchingDict[index][0].id,
        });
        encryptedData.splice(encryptedData.indexOf(matchingDict[index][0]));
      }
    }
    return malformed;
  }

  private interpolateShares(s1: IShare, s2: IShare): Uint8Array {

    const slope: bigInt.BigInteger = this.deriveSlope(s1, s2);
    const intercept: bigInt.BigInteger = this.getIntercept(s1, slope);

    return this.stringToBytes(intercept.toString());

  }

  /**
   * Symmetric decryption
   * @param key
   * @param {string} cipherText - in base 64 encoding with a nonce split on ("$")
   * @param {string} ad - additional data associated with ciphertext
   * @return decrypted data
   */
  private symmetricDecrypt(key: Uint8Array, cipherText: string, ad: string): Uint8Array {
    try {
      const split: string[] = cipherText.split('$');

      if (key.length !== this.sodium.crypto_box_SECRETKEYBYTES) {
        throw new Error('Improper key length for symmetric decryption');
      }

      const cT: Uint8Array = this.sodium.from_base64(split[0]);
      const nonce: Uint8Array = this.sodium.from_base64(split[1]);

      return this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cT, ad, nonce, key);
    } catch (e) {
      throw e;
    }
  }

  /**
   * Decrypts a single record
   * @param recordKey
   * @param {string} eRecord
   * @param {string} ad - additional data associated with ciphertext
   * @returns decrypted record
   */
  private decryptRecord(recordKey: Uint8Array, eRecord, ad: string): string {
    const decryptedRecord: Uint8Array = this.symmetricDecrypt(recordKey, eRecord, ad);
    const dStr: string = new encoding.TextDecoder('utf-8').decode(decryptedRecord);

    return dStr;
    // return JSON.parse(dStr);
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
   * @param skOC - secret key of an options counselor
   * @param pkUser - public key of a user
   * @returns {IShare} a decrypted coordinate
   */
  private asymmetricDecrypt(encryptedData: IEncryptedData, skOC: Uint8Array, pkOC: Uint8Array): IShare {
    try {
      const c: Uint8Array = this.sodium.from_base64(encryptedData.eOC);
      const msg: Uint8Array = this.sodium.crypto_box_seal_open(c, pkOC, skOC);
      const msgObj: IShare = JSON.parse(new encoding.TextDecoder('utf-8').decode(msg));

      return {
        eRecordKey: msgObj.eRecordKey,
        x: bigInt(msgObj.x),
        y: bigInt(msgObj.y),
      };
    } catch (e) {
      throw new Error('Asymmetric decryption failure');
    }
  }

  /**
   * Asymmetric encryption
   * @param {string} message - a plaintext string
   * @param pkOC - the public key of an options counselor
   * @returns {string} encrypted string in base 64 encoding
   */
  private asymmetricEncrypt(message: string, pkOC: Uint8Array): string {
    try {
      const cT: Uint8Array = this.sodium.crypto_box_seal(message, pkOC);
      return this.sodium.to_base64(cT);
    } catch (e) {
      throw(e);
    }
  }

  /**
   * Symmetric encryption
   * @param key
   * @param {string} msg plaintext string
   * @param {string} ad - additional data associated with ciphertext
   * @returns {string} encrypted string in base 64 encoding
   */
  private symmetricEncrypt(key: Uint8Array, msg: string, ad: string): string {
    try {
      const nonce: Uint8Array = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);

      // TODO: double check that args are in correct order
      const cT: Uint8Array = this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, null, nonce, key);
      const encrypted: string = this.sodium.to_base64(cT) + '$' + this.sodium.to_base64(nonce);

      return encrypted;
    } catch (e) {
      throw e;
    }
  }

  /**
   * Converts bytes to their string representation of a number
   * @param bytes
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
