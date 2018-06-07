import bigInt = require('big-integer')
import * as $ from 'jquery';
import _sodium = require('libsodium-wrappers');

export namespace CryptoService {
  let sodium = null;

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
  export function encryptData(randId: Uint8Array, userId: string, publicKeys: Array<Uint8Array>) :string {
    if (publicKeys.length < 1) {
      return undefined;
    }

    const slope: bigInt.BigInteger = bigInt(bytesToString(sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId)));
    const k: Uint8Array = sodium.crypto_kdf_derive_from_key(32, 2, "derivation", randId);
    const matchingIndex: string = sodium.to_base64(sodium.crypto_kdf_derive_from_key(32, 3, "derivation", randId));


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




