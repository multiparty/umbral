import bigInt = require('big-integer')
import * as $ from 'jquery';
import _sodium = require('libsodium-wrappers');

export interface IRecord {
  randId: Uint8Array;
  userId: string;
}

export interface IEncryptedData {
  readonly matchingIndex: string;
  readonly eOC: string;
  readonly eRecord: string;
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
  export function encryptData(randId: Uint8Array, userId: string, publicKeys: Array<Uint8Array>, skUser: Uint8Array): Array<IEncryptedData> {
    if (publicKeys.length < 1) {
      return undefined;
    }

    const record: IRecord = { randId, userId }

    const slope: bigInt.BigInteger = bigInt(bytesToString(sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId)));
    const k: Uint8Array = sodium.crypto_kdf_derive_from_key(32, 2, "derivation", randId);
    const matchingIndex: string = sodium.to_base64(sodium.crypto_kdf_derive_from_key(32, 3, "derivation", randId));

    const U: bigInt.BigInteger = bigInt(sodium.to_hex(sodium.crypto_hash(userId).slice(0, 32)), HEX);
    const kStr: string = bytesToString(k);
    const recordKey: Uint8Array = sodium.crypto_secretbox_keygen();

    const eRecord: string = symmetricEncrypt(recordKey, JSON.stringify(record));
    const eRecordKey: string = symmetricEncrypt(k, sodium.to_base64(recordKey));
  
    const msg = { U, slope, eRecordKey };

    let encryptedData: Array<IEncryptedData> = [];

    for (const i in publicKeys) {
      let eOC = asymmetricEncrypt(JSON.stringify(msg), publicKeys[i], skUser);
      encryptedData.push({matchingIndex, eOC, eRecord});
    }

    return encryptedData;
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




