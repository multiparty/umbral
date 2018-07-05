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
  * Encrypts a user's record
  * @param {Uint8Array} randId - random ID
  * @param {IRecord} record - user record
  * @param {Uint8Array[]} publicKeys - options counselor public keys
  * @param {Uint8Array} skUser - user's secret key
  * @returns {IEncryptedData[]} an array of records encrypted under each public key
  */
function encryptData(randId: Uint8Array, record: IRecord, publicKeys: Uint8Array[], skUser: Uint8Array)
```

### Decryption
The function should be provided with **matched** encrypted records
```javascript
/**
 * Decrypts an array of encrypted data
 * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users
 * @param {Uint8Array} skOC - secret key of an options counselor
 * @param pkUser - user's private key
 * @returns {IRecord[]} array of decrypted records from matched users
 */
function decryptData(encryptedData: IEncryptedData[], skOC: Uint8Array, pkUser: Uint8Array)
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
