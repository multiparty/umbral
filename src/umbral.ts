import bigInt = require('big-integer');
import * as encoding from 'text-encoding';
import uuidv4 = require('uuid/v4');

export interface IRecord {
  readonly perpId: string;
  readonly userId: string;
}

/**
 * Mapping of OC id to matching records
 */
export interface IOCDataMap {
  [OCid: string]: IEncryptedData[];
}

/**
 * Data object returned from encryption workflow
 */
export interface IEncrypted {
  readonly encryptedMap: IEncryptedMap;
  readonly malformed: IMalformed[];
}

/**
 * Mapping of matching index to all matching records under a specific OC
 */
export interface IEncryptedMap {
  [matchingIndex: string]: IOCDataMap;
}

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

interface IShare {
  readonly x: bigInt.BigInteger;
  readonly y: bigInt.BigInteger;
  readonly eRecordKey: string;
}

interface IDerivedValues {
  readonly slope: bigInt.BigInteger;
  readonly k: Uint8Array;
  readonly matchingIndex: string;
}

export interface IMalformed {
  readonly id: string;
  readonly error: string;
}

export interface IDecrypted {
  readonly records: IRecord[];
  readonly malformed: IMalformed[]; // ids
}

export interface IKey {
  [id: string]: Uint8Array;
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
   * Encrypts a user's record
   * @param {Uint8Array} randId - random ID (pHat)
   * @param {IRecord} record - user record
   * @param {Uint8Array[]} pkOCs - options counselor public keys
   * @param {Uint8Array} skUser - user's secret key
   * @returns {IEncryptedData[]} an array of records encrypted under each public key
   */
  public encryptData(randIds: Uint8Array[], record: IRecord, pkOCs: IKey,
                     userPassPhrase: Uint8Array): IEncrypted {

    const encrypted: IEncrypted = { encryptedMap: {}, malformed: [] };
    if (Object.keys(pkOCs).length < 1) {
      encrypted.malformed.push({
        error: 'No public OC keys provided',
        id: 'All'
      });
      return encrypted;
    }

    if (record.perpId === null || record.perpId === '' || record.userId === null || record.userId === '') {
      encrypted.malformed.push({
        error: 'Record is missing information',
        id: 'All'
      });
      return encrypted;
    }

    for (const randId of randIds) {
      this.createEncryptedObject(encrypted, randId, record, pkOCs, userPassPhrase);
    }
    return encrypted;
  }

  /**
   * Decrypts a user's record for editing purposes
   * @param {Uint8Array} userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @returns {IRecord[]} an array of decrypted records (should contain same content)
   */
  public decryptUserRecord(userPassPhrase: Uint8Array, userEncryptedData: IEncryptedData[]): IDecrypted {

    // NOTE: is it necessary to do this for ALL oc keys?
    const records: IRecord[] = [];
    const malformed: IMalformed[] = [];

    for (const eUserData of userEncryptedData) {
      const eUser = eUserData.eUser;

      try {
        const recordKey: Uint8Array = this.symmetricDecrypt(userPassPhrase, eUser,
            this.USER_EDIT_STRING + eUserData.matchingIndex);
        records.push(this.decryptRecord(this.sodium.from_base64(recordKey), eUserData.eRecord,
            this.RECORD_STRING + eUserData.matchingIndex));
      } catch (e) {
        malformed.push({
          error: e,
          id: eUserData.id,
        });
      }
    }
    return {records, malformed};
  }

  /**
   *
   * @param {Uint8Array} userPassPhrase - original passphrase used to encrypt the record key
   * @param {IEncryptedData[]} userEncryptedData - a user's record encrypted under each OC public key
   * @param {IRecord} updatedRecord - a user's updated record
   * @returns {IEncryptedData[]} an array of encrypted data containing the cipher text of the updated record
   */
  public updateUserRecord(userPassPhrase: Uint8Array,
                          userEncryptedData: IEncryptedData[],
                          updatedRecord: IRecord): IMalformed[] {
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
          JSON.stringify(updatedRecord),
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
   * Decrypts an array of encrypted data
   * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users
   * @param {Uint8Array} skOC - secret key of an options counselor
   * @param {Uint8Array[]} pkUser - user's public key
   * @returns {IRecord[]} array of decrypted records from matched users
   */
  public decryptData(encryptedData: IEncryptedData[], pkOC: Uint8Array, skOC: Uint8Array): IDecrypted {

    const malformed: IMalformed[] = this.checkMatches(encryptedData);

    if (malformed.length === encryptedData.length) {
      return {
        malformed,
        records: [],
      };
    }

    const shares: object = {};
    const records: IRecord[] = [];

    for (const eData of encryptedData) {
      try {
        const id = eData.id;
        shares[id] = this.asymmetricDecrypt(eData, skOC, pkOC);
      } catch (e) {
        malformed.push({
          error: e,
          id: eData.id,
        });
      }
    }

    if (encryptedData.length < 2) {
      return {records, malformed};
    }

    const encryptedDict: object = {};
    for (const eData of encryptedData) {
      const id = eData.id;
      encryptedDict[id] = eData;
    }

    const decryptedMap = new Map();
    while (Object.keys(shares).length > 0) {

      const ids = Object.keys(shares);
      const shareId = ids[0];
      const share = shares[ids[0]];

      for (const [key, s2] of decryptedMap) {
        try {
          const k: Uint8Array = this.interpolateShares(share, s2);
          const recordKey: Uint8Array = this.symmetricDecrypt(k, share.eRecordKey,
              this.RECORD_KEY_STRING + encryptedDict[shareId].matchingIndex);
          records.push(this.decryptRecord(this.sodium.from_base64(recordKey), encryptedDict[shareId].eRecord,
              this.RECORD_STRING + encryptedDict[shareId].matchingIndex));

          decryptedMap.set(shareId, share);
          break;
        } catch (e) {
          // TODO Handle error
        }
      }

      for (let i = 1; i < ids.length; i++) {
        try {
          const s2: IShare = shares[ids[i]];
          const s2Id: string = ids[i];
          const k: Uint8Array = this.interpolateShares(share, s2);

          // decrypt share 1
          let recordKey: Uint8Array = this.symmetricDecrypt(k, share.eRecordKey,
            this.RECORD_KEY_STRING + encryptedDict[shareId].matchingIndex);

          records.push(this.decryptRecord(this.sodium.from_base64(recordKey), encryptedDict[shareId].eRecord,
            this.RECORD_STRING + encryptedDict[shareId].matchingIndex));

          decryptedMap.set(shareId, share);

          // decrypt share 2
          recordKey = this.symmetricDecrypt(k, s2.eRecordKey,
            this.RECORD_KEY_STRING + encryptedDict[s2Id].matchingIndex);
          records.push(this.decryptRecord(this.sodium.from_base64(recordKey), encryptedDict[s2Id].eRecord,
            this.RECORD_STRING + encryptedDict[s2Id].matchingIndex));
          decryptedMap.set(ids[i], s2);

          delete shares[s2Id];
          break;

        } catch (e) {
          malformed.push({
            error: e,
            id: shareId,
          });
        }
      }
      delete shares[ids[0]];
    }

    return {
      malformed,
      records,
    };
  }

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

  private createEncryptedObject(encrypted: IEncrypted,
                                randId: Uint8Array,
                                record: IRecord, pkOCs: IKey,
                                userPassPhrase: Uint8Array): void {
    try {
      const derived: IDerivedValues = this.deriveValues(randId);
      const U: bigInt.BigInteger = bigInt(this.sodium.to_hex(
        this.sodium.crypto_generichash(this.KEY_BYTES, record.userId)), this.HEX);

      const kStr: string = this.bytesToString(derived.k);
      const s: bigInt.BigInteger = (derived.slope.times(U).plus(bigInt(kStr))).mod(this.PRIME);
      const recordKey: Uint8Array = this.sodium.crypto_secretbox_keygen();

      const eRecordKey: string = this.symmetricEncrypt(
        derived.k,
        this.sodium.to_base64(recordKey),
        this.RECORD_KEY_STRING + derived.matchingIndex
      );
      const eUser: string = this.symmetricEncrypt(
        userPassPhrase,
        this.sodium.to_base64(recordKey),
        this.USER_EDIT_STRING + derived.matchingIndex
      );

      const msg: IShare = {
        eRecordKey,
        x: U,
        y: s,
      };

      const eRecord: string = this.symmetricEncrypt(
        recordKey,
        JSON.stringify(record),
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

    for (const eData of encryptedData) {
      const index = eData.matchingIndex;

      if (index in matchingDict) {
        matchingDict[index].push(eData.id);
      } else {
        matchingDict[index] = [eData.id];
      }
    }

    for (const index in matchingDict) {
      if (matchingDict[index].length === 1) {
        malformed.push({
          error: 'Matching index does not match with other shares',
          id: matchingDict[index][0],
        });
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
   * @param {Uint8Array} key
   * @param {string} cipherText - in base 64 encoding with a nonce split on ("$")
   * @return {Uint8Array} decrypted data
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
   * @param {Uint8Array} recordKey
   * @param {string} eRecord
   * @returns {IRecord} decrypted record
   */
  private decryptRecord(recordKey: Uint8Array, eRecord, ad: string): IRecord {
    const decryptedRecord: Uint8Array = this.symmetricDecrypt(recordKey, eRecord, ad);
    const dStr: string = new encoding.TextDecoder('utf-8').decode(decryptedRecord);

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
   * @param {Uint8Array} pkOC - the public key of an options counselor
   * @param {Uint8Array} skUser - secret key of a user
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
   * @param {Uint8Array} key
   * @param {string} msg plaintext string
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
