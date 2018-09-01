# Umbral
[![npm version](https://badge.fury.io/js/umbral.svg)](https://badge.fury.io/js/umbral)[![Build Status](https://travis-ci.org/multiparty/umbral.svg?branch=master)](https://travis-ci.org/multiparty/umbral)

### Installation
```npm install umbral```

### Initialization
The module must be initialized with a sodium instance.
```typescript
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
```


### Public Interfaces
##### ```IRecord``` #####
Object for a user-submitted record. It currently contains only a perpetrator ID and a user ID. This can be amended to include additional information.
```typescript
export interface IRecord {
  readonly perpId: string;
  readonly userId: string;
}
```
##### ```IKey``` #####
Dictionary of {id: key} key-value pairs, where the ```id``` identifies the options counselor the key belongs to. This assumes that each options counselor can be identified by an uuid.
```typescript
/**
 * Dictionary of {id: key}
 */
export interface IKey {
  [id: string]: Uint8Array;
}
```

##### ```IMalformed``` #####
Object for storing errors in either the encryption or decryption workflow. Within encryption, the ```id``` serves to notify the input that an error occurred on. For decryption, the ```id``` corresponds to a particular ```IEncryptedData```, described below. For both workflows the error field contains exact errors produced.
```typescript
/**
 * Object for storing errors
 */
export interface IMalformed {
  readonly id: string;
  readonly error: string;
}
```

##### ```IEncryptedData``` #####
Object containing the ciphertext resulting from encryption using a *single perpId* and a *single OC's public key*. The number of ```IEncryptedData``` objects at the end of the encryption worfklow should equal the number of perpetrator IDs submitted multiplied by the number of OCs.
```typescript
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
```

##### ```IOCDataMap``` #####
A dictionary mapping each options counselor, identified through an id, to an array of encrypted data objects that have all been encrypted under the OC's public key.
```typescript
/**
 * Mapping of OC id to matching records
 */
export interface IOCDataMap {
  [OCid: string]: IEncryptedData[];
}
```
##### ```IEncryptedMap``` #####
Dictionary represents the mapping of a matching index to all the records that have the same matching index encrypted under each options counselor's public key. 
```typescript
/**
 * Mapping of matching index to all matching records under a specific OC
 */
export interface IEncryptedMap {
  [matchingIndex: string]: IOCDataMap;
}
```
##### ```IEncrypted``` #####
At the end of the encryption workflow, a single object will be returned in the following form. The encryptedMap should contain as many matching indices as submitted perpIds. Corresponding to each matching index is the ```IOCDataMap``` for each options counselor, containing their corresponding ciphertexts. 
```typescript
/**
 * Data object returned from encryption workflow
 */
export interface IEncrypted {
  readonly encryptedMap: IEncryptedMap;
  readonly malformed: IMalformed[];
}
```
##### ```IDecrypted``` #####
Decryption returns the following object containing an array of user records and an array of malformed objects where decryption did not properly occur.
```typescript
/**
 * Data returned from decryption workflow
 */
export interface IDecrypted {
  readonly records: IRecord[];
  readonly malformed: IMalformed[]; // ids
}
```

### Encryption
This function must be provided with a dictionary of public keys in the form of ```IKey``` key-value pairs (pkOCs). It will return all of the encrypted data in ```IEncrypted``` form. 
```typescript

  /**
   * Encryption workflow
   * @param randIds - array of all randIds corresponding to each perpId submitted
   * @param record - user's record
   * @param pkOCs - dictionary of all OC public keys
   * @param userPassPhrase - user's passphrase for use in encrypting for editing
   * @returns {IEncrypted} object containing encrypted data and errors
   */
  public encryptData(randIds: Uint8Array[], record: IRecord, pkOCs: IKey,
                     userPassPhrase: Uint8Array): IEncrypted 
```

### Decryption
The function should be provided with **matched** encrypted records encrypted under a specific OC's public key.
```typescript

  /**
   * Decryption workflow
   * @param {IEncryptedData[]} encryptedData - an array of encrypted data of matched users, under a single OC's public key
   * @param pkOC - public key of an options counselor
   * @param skOC - secret key of an options counselor
   * @returns {IDecrypted]} object containing decrypted records and errors
   */
  public decryptData(encryptedData: IEncryptedData[], pkOC: Uint8Array, skOC: Uint8Array): IDecrypted 

```


### End-to-End Example
The following example involves two users and two options counselors.
```typescript
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(2);

    const perpId = 'facebook.com/Mallory';
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], { perpId, userId: 'Alice' }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], { perpId, userId: 'Bob' }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    for (let index in encryptedDict) {
      for (let oc in encryptedDict[index]) {
        const encrypted = encryptedDict[index][oc];
        const decrypted = _umbral.decryptData(encrypted, publicKeys[oc], privateKeys[oc]);
      }
    }
```

Additional examples can be found under ```test/tests.ts```

