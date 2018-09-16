import { Umbral, IEncryptedData, IEncrypted, IMalformed, IKey, IDecrypted, IEncryptedMap, IOCDataMap } from '../src/umbral';
import { expect } from 'chai';
import { OPRF, IMaskedData } from 'oprf';

var _sodium = require('libsodium-wrappers-sumo');


function getRandom(max: number): number {
    return Math.floor(Math.random() * Math.floor(max));
}

function createRandString(): string {

    const alphabet: string[] = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
    let name: string = "";
    for (let i: number = 0; i < getRandom(128); i++) {
        const index: number = getRandom(alphabet.length);
        name += alphabet[index];
    }

    if (name === "") {
        name = "XXXXXX";
    }
    return name;
}


function getRandIds(n: number): Uint8Array[] {
  const randIds: Uint8Array[] = [];

  for (var i = 0; i < n; i++) {
    const r = createRandString();
    randIds.push(performOPRF(r));
  }

  return randIds;
}


function addEntropy(input: string) {
  const rand1: Uint8Array = performOPRF(input);
  const rand2: Uint8Array = performOPRF(input);

  const c: Uint8Array = new Uint8Array(rand1.length + rand2.length);
  c.set(rand1);
  c.set(rand2, rand1.length);

  return c;
}

function performOPRF(input: string): Uint8Array {
    const oprf = new OPRF(_sodium);
    const sk = oprf.generateRandomScalar();
    const masked: IMaskedData = oprf.maskInput(input);
    const salted: number[] = oprf.scalarMult(masked.point, sk);
    const unmasked = oprf.unmaskInput(salted, masked.mask);

    return new Uint8Array(unmasked);
}

function decryptSuccess(encryptedDict: IEncryptedMap, publicKeys: IKey, privateKeys: IKey, perpId: string, userId: string, _umbral) {
  for (let index in encryptedDict) {
    for (let oc in encryptedDict[index]) {
      const encrypted = encryptedDict[index][oc];
      const decrypted = _umbral.decryptData(encrypted, publicKeys[oc], privateKeys[oc]);
      let user = userId;

      for (let data of decrypted.data) {
        let json = JSON.parse(data);

        expect(json.perpId).to.equal(perpId);
        expect(json.userId).to.equal(user);
        user += userId;
      }

      expect(decrypted.malformed.length).to.equal(0);
    }
  }
}

function updateDict(encryptedDict: IEncryptedMap, newDict: IEncryptedMap): void {
  for (let matchingIndex in newDict) {
    if (!(matchingIndex in encryptedDict)) {
      encryptedDict[matchingIndex] = newDict[matchingIndex];
    } else {
      const OCMap: IOCDataMap = encryptedDict[matchingIndex];

      for (let oc in OCMap) {
        encryptedDict[matchingIndex][oc].push(newDict[matchingIndex][oc][0]);
      }
    }
  }
}

function generateKeys(n: number) {
  const privateKeys: IKey = {};
  const publicKeys: IKey = {};
  for (let i = 0; i < n; i++) {
    const keyPair = _sodium.crypto_box_keypair();
    const id = createRandString();

    publicKeys[id] = keyPair.publicKey;
    privateKeys[id] = keyPair.privateKey;
  }

  return [publicKeys, privateKeys];
}

function retrieveEncrypted(encryptedDict: IEncryptedMap): IEncryptedData[] {
  let encrypted: IEncryptedData[] = [];

  for (let index in encryptedDict) {
    for (let oc in encryptedDict[index]) {
      for (let enc of encryptedDict[index][oc]) {
        const obj = {
          eOC: enc.eOC,
          eRecord: enc.eRecord,
          eUser: enc.eUser,
          id: enc.id,
          matchingIndex: 'matching'
        }
        encrypted.push(enc);
      }
    }
  }
  return encrypted;
}


describe('Basic end-to-end tests', () => {
  it('1 OCs, 2 matched users', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    expect(encryptedDataA.malformed.length).to.equal(0);
    expect(encryptedDataB.malformed.length).to.equal(0);
    
    decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
  });
});
  
//   it('2 OCs, 2 matched users', async function() {

//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(2);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataA.encryptedMap);

//     const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataB.encryptedMap);

//     expect(encryptedDataA.malformed.length).to.equal(0);
//     expect(encryptedDataB.malformed.length).to.equal(0);
//     decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
//   });

//   it('2 OCs, 3 matched users', async function() {

//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(2);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataA.encryptedMap);

//     const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataB.encryptedMap);

//     const encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataC.encryptedMap);

//     expect(encryptedDataA.malformed.length).to.equal(0);
//     expect(encryptedDataB.malformed.length).to.equal(0);
//     expect(encryptedDataC.malformed.length).to.equal(0);
//     decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
//   });

      
//   it('Stress test with rand number of OCs (up to 10)', async function() {

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();
//     const testNum = 50;

//     for (let i: number = 0; i < testNum; i++){
//       let encryptedDict: IEncryptedMap = {};
//       let [publicKeys, privateKeys] = generateKeys(getRandom(10));

//       let perpId = createRandString();
//       let userId = createRandString();
//       let randId: Uint8Array = performOPRF(perpId); 

//       let encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataA.encryptedMap);
  
//       let encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataB.encryptedMap);
  
//       let encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataC.encryptedMap);  
   
//       decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
//     }
//   });

//   it('Stress test with rand multiple perp ids (max 3), rand number of OCs (max 3)', async function() {

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();
//     const testNum = 1;

//     for (let i: number = 0; i < testNum; i++){
//       let encryptedDict: IEncryptedMap = {};
//       let [publicKeys, privateKeys] = generateKeys(getRandom(10));

//       let perpId = createRandString();
//       let userId = createRandString();

//       // perp ids
//       let randIds = getRandIds(4);

//       let encryptedDataA: IEncrypted = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataA.encryptedMap);
  
//       let encryptedDataB: IEncrypted = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataB.encryptedMap);
  
//       let encryptedDataC: IEncrypted = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
//       updateDict(encryptedDict, encryptedDataC.encryptedMap);  
   
//       decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
//     }
//   });
// });



// describe('Error cases', () => {

//   it('No public keys provided', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);
//     const encrypted: IEncrypted = _umbral.encryptData([randId], {perpId, userId}, {}, userKeyPair.privateKey);

//     expect(encrypted.malformed.length).to.equal(1);
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//   });


//   it('Record missing information', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     let [publicKeys, privateKeys] = generateKeys(1);
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);
//     let encrypted: IEncrypted = _umbral.encryptData([randId], {perpId: null, userId}, publicKeys, userKeyPair.privateKey);
//     expect(encrypted.malformed.length).to.equal(1);
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//     expect(encrypted.malformed[0].error).to.equal('Record is missing information');

//     encrypted = _umbral.encryptData([randId], {perpId: '', userId}, publicKeys, userKeyPair.privateKey);
//     expect(encrypted.malformed.length).to.equal(1);
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//     expect(encrypted.malformed[0].error).to.equal('Record is missing information');

//     encrypted = _umbral.encryptData([randId], {perpId, userId: null}, publicKeys, userKeyPair.privateKey);
//     expect(encrypted.malformed.length).to.equal(1);
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//     expect(encrypted.malformed[0].error).to.equal('Record is missing information');

//     encrypted = _umbral.encryptData([randId], {perpId, userId: ''}, publicKeys, userKeyPair.privateKey);
//     expect(encrypted.malformed.length).to.equal(1);
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//     expect(encrypted.malformed[0].error).to.equal('Record is missing information');

//   });
//   it('Asymmetric encryption failure', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const publicKey = new Uint8Array([10,10,10,10]);
    
//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);
//     const encrypted = _umbral.encryptData([randId], {perpId, userId}, {"oc": publicKey} , userKeyPair.privateKey);

//     expect(encrypted.malformed.length).to.equal(1);
//     expect(encrypted.malformed[0].error.toString()).to.contain('invalid publicKey length');
//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//   });

//   it('Asymmetric decryption failure', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     let encryptedDict: IEncryptedMap = {};

//     const [publicKeys, privateKeys] = generateKeys(1);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const ocId = Object.keys(publicKeys)[0];

//     updateDict(encryptedDict, _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randId], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey).encryptedMap);

//     for (let index in encryptedDict) {
//       for (let oc in encryptedDict[index]) {
//         const decrypted = _umbral.decryptData(encryptedDict[index][oc], userKeyPair.publicKey, userKeyPair.privateKey);
//         expect(decrypted.records.length).to.equal(0);
//         expect(decrypted.malformed.length).to.equal(2);
//         expect(decrypted.malformed[0].error.toString()).to.contain('Asymmetric decryption failure');
//         expect(decrypted.malformed[1].error.toString()).to.contain('Asymmetric decryption failure');
//       }
//     }
//   });


//   it('Key derivation failure', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     let encryptedDict: IEncryptedMap = {};

//     const [publicKeys, privateKeys] = generateKeys(1);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();

//     const rand = new Uint8Array([10,10,10]);

//     const encrypted = _umbral.encryptData([rand], { perpId, userId }, publicKeys, userKeyPair.privateKey);

//     expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
//     expect(encrypted.malformed.length).to.equal(1);
//     expect(encrypted.malformed[0].error.toString()).to.contain('Key derivation failure');
//   });

//   it('Only 1 match provided', async function() {
//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(1);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA: IEncrypted = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
//     updateDict(encryptedDict, encryptedDataA.encryptedMap);

//     const matchingIndex = Object.keys(encryptedDict)[0];
//     const ocId = Object.keys(publicKeys)[0];

//     const encrypted: IEncryptedData[] = encryptedDict[matchingIndex][ocId];
//     const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    
//     expect(decrypted.malformed.length).to.equal(1);
//     expect(decrypted.malformed[0].error).to.equal("Decryption requires at least 2 matches")
//   }); 


//   it('3 malformed shares', async function() {

//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(1);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randIdA: Uint8Array = performOPRF(perpId);
//     const randIdB: Uint8Array = performOPRF(perpId+perpId);
//     const randIdC: Uint8Array = performOPRF(perpId+perpId+perpId);

//     updateDict(encryptedDict, _umbral.encryptData([randIdA], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randIdB], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randIdC], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);

//     // shares all have points that cannot be interpolated, manually changing matchingIndex
//     const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);

//     const ocId = Object.keys(publicKeys)[0];
//     const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
//     expect(decrypted.records.length).to.equal(0);
//     expect(decrypted.malformed.length).to.equal(3);
//   });


//   it('2 of the same share', async function() {
//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(1);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     updateDict(encryptedDict, _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);

//     // shares all have points that cannot be interpolated, manually changing matchingIndex
//     const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);

//     const ocId = Object.keys(publicKeys)[0];
//     const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
//     expect(decrypted.records.length).to.equal(0);
//     expect(decrypted.malformed.length).to.equal(1);
//     expect(decrypted.malformed[0].error.toString()).to.contain('not co-prime')
//   });

//   it('2 decrypted shares, 1 malformed', async function() {

//     let encryptedDict: IEncryptedMap = {};

//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     var [publicKeys, privateKeys] = generateKeys(1);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randIdA: Uint8Array = performOPRF(perpId);
//     const randIdB: Uint8Array = performOPRF(perpId+perpId);

//     updateDict(encryptedDict, _umbral.encryptData([randIdA], { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randIdA], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey).encryptedMap);
//     updateDict(encryptedDict, _umbral.encryptData([randIdB], { perpId, userId: userId+userId+userId }, publicKeys, userKeyPair.privateKey).encryptedMap);

//     const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
//     const ocId = Object.keys(publicKeys)[0];
    
//     const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
//     expect(decrypted.records.length).to.equal(2);
//     expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId);
//     expect(decrypted.malformed.length).to.equal(1);
//     // TODO: write expect statement for specific error
//   });
// });

// describe('User editing', () => {
//   it('Decrypting eUser', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();

//     var [publicKeys, privateKeys] = generateKeys(4);

//     const randIds: Uint8Array[] = getRandIds(5);
//     const encryptedData: IEncryptedMap = _umbral.encryptData(randIds, { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap;

//     const encrypted: IEncryptedData[] = [];

//     for (let index in encryptedData) {
//       for (let oc in encryptedData[index]) {
//         const record = encryptedData[index][oc][0];
//         encrypted.push(record);
//       }
//     }

//     const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encrypted);

//     for (let record of decrypted.records) {
//       expect(record.perpId).to.equal(perpId);
//       expect(record.userId).to.equal(userId);
//     }
//     expect(decrypted.malformed.length).to.equal(0);
//   });

//   it('Updating user record', async function() {
//     await _sodium.ready;
//     const _umbral = new Umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();

//     var [publicKeys, privateKeys] = generateKeys(4);

//     const randIds: Uint8Array[] = getRandIds(5);
//     const encryptedData: IEncryptedMap = _umbral.encryptData(randIds, { perpId, userId }, publicKeys, userKeyPair.privateKey).encryptedMap;

//     const encrypted: IEncryptedData[] = [];

//     for (let index in encryptedData) {
//       for (let oc in encryptedData[index]) {
//         const record = encryptedData[index][oc][0];
//         encrypted.push(record);
//       }
//     }

//     const malformed: IMalformed[] = _umbral.updateUserRecord(userKeyPair.privateKey, encrypted, {
//       perpId: perpId+perpId,
//       userId
//     });

//     expect(malformed.length).to.equal(0);

//     const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encrypted);

//     for (let record of decrypted.records) {
//       expect(record.perpId).to.equal(perpId+perpId);
//       expect(record.userId).to.equal(userId);
//     }
//     expect(decrypted.malformed.length).to.equal(0);
//   });
// });