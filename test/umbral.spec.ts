import { Umbral, IEncryptedData, IMalformed, IKey, IDecryptedData, IRecord, IEncryptedMap, IOCDataMap } from '../src/umbral';
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

// TODO: perform 2 OPRF's and mimic 2 servers

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
      for (let record of decrypted.records) {
        expect(record.perpId).to.equal(perpId);
        expect(record.userId).to.equal(user);
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

    const encryptedDataA: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA);

    const encryptedDataB: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB);

    decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
  });
  
  it('2 OCs, 2 matched users', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(2);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA);

    const encryptedDataB: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB);

    decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
  });

  it('2 OCs, 3 matched users', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(2);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA);

    const encryptedDataB: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB);

    const encryptedDataC: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId+userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataC);

    decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
  });

      
  it('Stress test with rand number of OCs (up to 10)', async function() {

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();
    const testNum = 50;

    for (let i: number = 0; i < testNum; i++){
      let encryptedDict: IEncryptedMap = {};
      let [publicKeys, privateKeys] = generateKeys(getRandom(10));

      let perpId = createRandString();
      let userId = createRandString();
      let randId: Uint8Array = performOPRF(perpId); 

      let encryptedDataA: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataA);
  
      let encryptedDataB: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataB);
  
      let encryptedDataC: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId: userId+userId+userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataC);  
   
      decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
    }
  });

  it('Stress test with rand multiple perp ids (max 3), rand number of OCs (max 3)', async function() {

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();
    const testNum = 10;

    for (let i: number = 0; i < testNum; i++){
      let encryptedDict: IEncryptedMap = {};
      let [publicKeys, privateKeys] = generateKeys(getRandom(3));

      let perpId = createRandString();
      let userId = createRandString();

      let randIds = getRandIds(3);

      let encryptedDataA: IEncryptedMap = _umbral.encryptData(randIds, { perpId, userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataA);
  
      let encryptedDataB: IEncryptedMap = _umbral.encryptData(randIds, { perpId, userId: userId+userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataB);
  
      let encryptedDataC: IEncryptedMap = _umbral.encryptData(randIds, { perpId, userId: userId+userId+userId }, publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataC);  
   
      decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
    }
  });
});


function getRandIds(n: number): Uint8Array[] {
  const randIds: Uint8Array[] = [];

  for (var i = 0; i < n; i++) {
    const r = createRandString();
    randIds.push(performOPRF(r));
  }

  return randIds;
}


describe('Error cases', () => {
  // it('Did not provide OC public key', async function() {
  //   await _sodium.ready;
  //   const _umbral = new Umbral(_sodium);

  //   const userKeyPair = _sodium.crypto_box_keypair();

  //   const perpId = createRandString();
  //   let userId = createRandString();
  //   const randId: Uint8Array = performOPRF(perpId);
  //   expect(() => _umbral.encryptData([randId], {perpId, userId}, {"hello": []}, userKeyPair.privateKey))
  //                       .to.throw('No OC public key provided');

  // });
  it('Only 1 match provided', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncryptedMap = _umbral.encryptData([randId], { perpId, userId }, publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA);

    const matchingIndex = Object.keys(encryptedDict)[0];
    const ocId = Object.keys(publicKeys)[0];

    const encrypted: IEncryptedData[] = encryptedDict[matchingIndex][ocId];
    const decrypted: IDecryptedData = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    
    expect(decrypted.malformed.length).to.equal(1);
    expect(decrypted.malformed[0].error).to.equal("Decryption requires at least 2 matches")
  }); 
});


//   it('Incorrect match found', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randIdA: Uint8Array = performOPRF(perpId);
//     const randIdB: Uint8Array = performOPRF(perpId + perpId);

        // const ocKeyPair = _sodium.crypto_box_keypair();
        // const userKeyPair = _sodium.crypto_box_keypair();

//     const encryptedDataA = _umbral.encryptData(randIdA, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     userId = userId + userId;
//     const encryptedDataB = _umbral.encryptData(randIdB, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
  
//     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//     expect(decrypted.malformed.length).to.equal(2);
//     expect(decrypted.malformed[0].error).to.equal(decrypted.malformed[1].error).to.equal('Matching index does not match with other shares');

//   });

    // });

    // it('Incorrect match found', async function () {
    //     await _sodium.ready;
    //     const _umbral = new Umbral(_sodium);

//   it('Asymmetric encryption failure', async function() {

//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const key: Uint8Array = new Uint8Array([0]);

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);
//     const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [key], userKeyPair.privateKey);
//     const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
    
//     expect(encryptedDataA.length).to.equal(0);
//     expect(encryptedDataB.length).to.equal(1);    

//   });

//   it('Asymmetric decryption failure', async function() {

//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     userId = userId + userId;
//     const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.publicKey, ocKeyPair.publicKey);
    
//     expect(decrypted.malformed.length).to.equal(2);
//     expect(decrypted.malformed[0].error.toString()).to.contain('Asymmetric decryption failure');
//     expect(decrypted.malformed[1].error.toString()).to.contain('Asymmetric decryption failure');
//   });

//   it('2 shares can decrypt, 1 cannot', async function() {

//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPairA = _sodium.crypto_box_keypair();
//     const userKeyPairB = _sodium.crypto_box_keypair();
//     const userKeyPairC = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPairA.privateKey);    
//     userId = userId + userId;
//     const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPairB.privateKey);
//     userId = userId + userId;
//     const encryptedDataC = _umbral.encryptData(performOPRF(perpId + perpId), { perpId, userId }, [ocKeyPair.publicKey], userKeyPairC.privateKey);

//     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0], encryptedDataC[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//     expect(decrypted.records.length).to.equal(2);
//     expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId);
//     expect(decrypted.malformed.length).to.equal(1);    
//   });

        // const perpId = createRandString();
        // let userId = createRandString();
        // const randId: Uint8Array = performOPRF(perpId);



//   /**
//    * TODO:
//    * -Decryption succeeds but authentication of matching index fails
//    * -User edits record
//    * -Check algorithm for interpolation: 
//    *  -A can't decrypt, BC can
//    *  -No one can decrypt -> get back all shares in malformed array
//    *  -ABC can decrypt, CD can cdecrypt
//    * -New stress test with random number of entries per perp and randomly select malformed shares to include in data
//    * 
//    */
// });

    //     const encryptedDataA = _umbral.encryptData(performOPRF(perpId), {
    //         perpId,
    //         userId
    //     }, [ocKeyPair.publicKey], userKeyPair.privateKey);
    //     const encryptedDataB = _umbral.encryptData(performOPRF(perpId + perpId), {
    //         perpId,
    //         userId
    //     }, [ocKeyPair.publicKey], userKeyPair.privateKey);
    //     const encryptedDataC = _umbral.encryptData(performOPRF(perpId + perpId + perpId), {
    //         perpId,
    //         userId
    //     }, [ocKeyPair.publicKey], userKeyPair.privateKey);

    //     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0], encryptedDataC[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

    //     expect(decrypted.malformed.length).to.equal(3);
    //     expect(decrypted.records.length).to.equal(0);
    // });

    /**
     * TODO:
     * -Decryption succeeds but authentication of matching index fails
     * -User edits record
     * -Check algorithm for interpolation:
     *  -A can't decrypt, BC can
     *  -No one can decrypt -> get back all shares in malformed array
     *  -ABC can decrypt, CD can cdecrypt
     * -New stress test with random number of entries per perp and randomly select malformed shares to include in data
     *
     */
// });


// describe('User editing', () => {
//   it('Decrypting eUser', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     let userId = createRandString();

//     const randIdA: Uint8Array = performOPRF(perpId);
//     const encryptedDataA = _umbral.encryptData(randIdA, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

//     const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encryptedDataA);

//     expect(decrypted.malformed.length).to.equal(0);
//     expect(decrypted.records[0].perpId).to.equal(perpId);
//     expect(decrypted.records[0].userId).to.equal(userId);

//   });

//   it('Updating user record', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createRandString();
//     const userId = createRandString();

//     const randIdA: Uint8Array = performOPRF(perpId);
//     const encryptedDataA: IEncryptedData[] = _umbral.encryptData(randIdA, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

//     const newPerpId: string = createRandString();

//     const malformed: IMalformed[] = _umbral.updateUserRecord(userKeyPair.privateKey, encryptedDataA, {
//       perpId: newPerpId,
//       userId
//     });

//     expect(malformed.length).to.equal(0);
//     const decrypted: IDecryptedData = _umbral.decryptUserRecord(userKeyPair.privateKey, encryptedDataA);
  
//     expect(decrypted.records[0].perpId).to.equal(newPerpId);

        // expect(decrypted.records[0].perpId).to.equal(newPerpId);

//   });
// });