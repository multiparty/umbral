# Umbral
[![Build Status](https://travis-ci.org/multiparty/umbral.svg?branch=master)](https://travis-ci.org/multiparty/umbral)

### Installation
```npm install umbral```

### Initialization
The module must be initialized with a sodium instance.
```javascript
let _sodium = null;
await _sodium.ready;
umbral.init(_sodium);
```

### Encryption
```javascript


  /**
   * Encryption workflow
   * @param {Uint8Array} randId - randomized id resulting from OPRF
   * @param {IRecord} record - user's record
   * @param {Uint8Array[]} pkOCs - public keys for each OC
   * @param {Uint8Array} userPassPhrase - user passphrase used to encrypt a record key
   * @returns {IEncryptedData[]} ciphertext encrypted under each pkOC
   */
  public encryptData(randId: Uint8Array, record: IRecord, pkOCs: Uint8Array[], userPassPhrase: Uint8Array): IEncryptedData[]
```

### Decryption
The function should be provided with **matched** encrypted records
```javascript

  /**
   * Decryption workflow
   * @param encryptedData - an array of matched encrypted data objects corresponding to the OC 
   * @param pkOC - OC's public key
   * @param skOC - OC's private key
   * @returns {IDecryptedData} decrypted records and malformed shares
   */
  public decryptData(encryptedData: IEncryptedData[], pkOC: Uint8Array, skOC: Uint8Array): IDecryptedData {




```


### Basic End-to-End Example
```javascript

await _sodium.ready;
umbral.init(_sodium);

const ocKeyPair = _sodium.crypto_box_keypair();
const userKeyPairA = _sodium.crypto_box_keypair();
const userKeyPairB = _sodium.crypto_box_keypair();

const perpId = 'facebook.com/Mallory';
const randId: Uint8Array = hashId(perpId);

const encryptedDataA = umbral.encryptData(randId, { perpId, 'Alice' }, [ocKeyPair.publicKey], userKeyPairA.privateKey);
const encryptedDataB = umbral.encryptData(randId, { perpId, 'Bob' }, [ocKeyPair.publicKey], userKeyPairB.privateKey);
const decryptedRecords = umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], 
                                             ocKeyPair.privateKey, 
                                             [userKeyPairA.publicKey, userKeyPairB.publicKey]);
```

Additional examples can be found under ```test/tests.ts```

### Relevant Interfaces
A record is currently only a perpetrator ID and a user ID. This can be amended to include additional information.
```
export interface IRecord {
  readonly perpId: string;
  readonly userId: string;
}
```
