# crypto-service
### Installation


### Initialization
The module must be initialized with a sodium instance.
```javascript
let _sodium = null;
await _sodium.ready;
CryptoService.init(_sodium);
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
CryptoService.init(_sodium);

const ocKeyPair = _sodium.crypto_box_keypair();
const userKeyPair = _sodium.crypto_box_keypair();

const perpId = createName();
let userId = createName();
const randId: Uint8Array = hashId(perpId);

const encryptedDataA = CryptoService.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
userId = userId + userId;
const encryptedDataB = CryptoService.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
const decryptedRecords = CryptoService.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, userKeyPair.publicKey);
```

Additional examples can be found under ```test/tests.ts```

### Relevant Interfaces
A record is currently only a perpetrator ID and a user ID. This can be amended to include additional information.
```
export interface IRecord {
  perpId: string;
  userId: string;
}
```
