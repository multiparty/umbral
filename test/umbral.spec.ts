import { Umbral, IEncryptedData, IMalformed, IDecryptedData, IRecord } from '../src/umbral';
import { expect } from 'chai';
import { OPRF, IMaskedData } from 'oprf';

var _sodium = require('libsodium-wrappers-sumo');


function getRandom(max: number): number {
    return Math.floor(Math.random() * Math.floor(max));
}

function createName(): string {

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

function decryptSuccessTest(_umbral: Umbral, aDict: { [id: string] : IEncryptedData[]; }, bDict: { [id: string] : IEncryptedData[]; }, privKey, pubKey, perpId): void {
  
  // each perpId
  for (let key in aDict) {
    let a = aDict[key];
    let b = bDict[key];

    // encrypted data object for each OC
    for (let i = 0; i < a.length; i++) {
      const decrypted: IDecryptedData = _umbral.decryptData([a[i], b[i]], privKey, pubKey);
      const records: IRecord[] = decrypted.records;
  
      expect(decrypted.malformed.length).to.equal(0);
      for (let j = 0; j < records.length; j++) {
        // TODO: check correctness of userID
        expect(decrypted.records[0].perpId).to.equal(perpId);
      }
    }
  }
}

function updateDict(encryptedDict, newDict): void {
  for (let index in newDict) {
    if (!(index in encryptedDict)) {
      encryptedDict[index] = newDict[index];
    }
  }
}

describe('End-to-end tests', () => {
  
  it('Basic example with 1 OC, 2 matched users', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createName();
    let userId = createName();
    const randId: Uint8Array = performOPRF(perpId);

    let encryptedDict: { [id: string] : IEncryptedData[]; } = {};

    // updateDict(encryptedDict, _umbral.encryptData([randId], { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey));
    // const encryptedDataB = _umbral.encryptData([randId], { perpId, userId: userId+userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

    // console.log(encryptedDict);
    // decryptSuccessTest(_umbral, encryptedDataA, encryptedDataB, ocKeyPair.privateKey, ocKeyPair.publicKey, perpId);  
  });

  // it('Basic example with 3 matches', async function() {
  //   await _sodium.ready;
  //   const _umbral = new umbral(_sodium);

  //   const ocKeyPair = _sodium.crypto_box_keypair();
  //   const userKeyPairA = _sodium.crypto_box_keypair();
  //   const userKeyPairB = _sodium.crypto_box_keypair();
  //   const userKeyPairC = _sodium.crypto_box_keypair();

  //   const perpId = createName();
  //   let userId = createName();
  //   const randId: Uint8Array = performOPRF(perpId);

  //   const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPairA.privateKey);    
  //   userId = userId + userId;
  //   const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPairB.privateKey);
  //   userId = userId + userId;
  //   const encryptedDataC = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPairC.privateKey);

  //   const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0], encryptedDataC[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);
  //   expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
  //   expect(decrypted.records[2].userId).to.equal(userId);
  //   expect(decrypted.malformed.length).to.equal(0);
  // });
    
//   it('Stress test', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const testNum: number = 10;
//     for (let i: number = 0; i < testNum; i++) {
//       const perpId: string = createName();
//       const randId: Uint8Array = performOPRF(perpId);
//       let userId: string = createName();

//       const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

//       userId = userId + userId;
//       const encryptedDataB = _umbral.encryptData(randId, { perpId, userId}, [ocKeyPair.publicKey], userKeyPair.privateKey);
    
//       const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//       expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
//       expect(decrypted.records[1].userId).to.equal(userId);
//       expect(decrypted.malformed.length).to.equal(0);

//     }
//   });

//   it('Multiple OCs', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocNum = 5;
//     let ocPubKeys = [];
//     let ocPrivKeys = [];

//     for (var i = 0; i < ocNum; i++) {
//       let key = _sodium.crypto_box_keypair();

//       ocPubKeys.push(key.publicKey);
//       ocPrivKeys.push(key.privateKey);
//     }

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId: string = createName();
//     const randId: Uint8Array = performOPRF(perpId);
//     let userId: string = createName();

//     const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, ocPubKeys, userKeyPair.privateKey);
//     userId = userId + userId;
//     const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, ocPubKeys, userKeyPair.privateKey);

//     // note: highlight data structure necessary to make this work
//     // callisto database to send entire vector of encrypted data entries or just the entries for a particular OC?

//     // question: what is being fetched by an OC? 
//     for (var i = 0; i < ocNum; i++) {
//       const decrypted = _umbral.decryptData([encryptedDataA[i], encryptedDataB[i]], ocPrivKeys[i], ocPubKeys[i]);
//       expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
//       expect(decrypted.malformed.length).to.equal(0);
//     }
//   });

//             expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
//             expect(decrypted.records[1].userId).to.equal(userId);
//             expect(decrypted.malformed.length).to.equal(0);

// //   it('Multiple perpIds', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const perpIds: string[] = ['twitter', 'linkedin', 'facebook'];
//     let userId: string = createName();

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     for (var i = 0; i < perpIds.length; i++) {
//       let perpId = perpIds[i];
//       const randId: Uint8Array = performOPRF(perpId);
//       // TODO: make higher level function that handles calling encryptData for each perpID
//       const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//       userId = userId + userId;
//       const encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//       const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//       expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
//       expect(decrypted.malformed.length).to.equal(0);
//     }
//   });

//   it('Multiple perpIds and multiple OCs', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocNum = 5;
//     let ocPubKeys = [];
//     let ocPrivKeys = [];

//     for (var i = 0; i < ocNum; i++) {
//       let key = _sodium.crypto_box_keypair();

//       ocPubKeys.push(key.publicKey);
//       ocPrivKeys.push(key.privateKey);
//     }
    
//     const userKeyPair = _sodium.crypto_box_keypair();

//     for (var i = 0; i < ocNum; i++) {

//       let perpId: string = createName()
//       const randId: Uint8Array = performOPRF(perpId);
//       let userId: string = createName();

//       let encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, ocPubKeys, userKeyPair.privateKey);
//       userId = userId + userId;
//       let encryptedDataB = _umbral.encryptData(randId, { perpId, userId }, ocPubKeys, userKeyPair.privateKey);

    it('Multiple perpIds and multiple OCs', async function () {
        await _sodium.ready;
        const _umbral = new Umbral(_sodium);

//       for (var j = 0; j < ocNum; j++) {
//         let decrypted = _umbral.decryptData([encryptedDataA[i], encryptedDataB[i]], ocPrivKeys[i], ocPubKeys[i]);
//         expect(decrypted.records[0].perpId).to.equal(decrypted.records[1].perpId).to.equal(perpId);
//         expect(decrypted.malformed.length).to.equal(0);
//       }
//     }
//   });
// });

// describe('Error cases', () => {
//   it('Did not provide OC public key', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createName();
//     let userId = createName();
//     const randId: Uint8Array = performOPRF(perpId);
//     expect(() => _umbral.encryptData(randId, {perpId, userId}, [], userKeyPair.privateKey))
//                         .to.throw('No OC public key provided');

//   });

//   it('Only 1 match provided', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createName();
//     let userId = createName();
//     const randId: Uint8Array = performOPRF(perpId);

//     const encryptedDataA = _umbral.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     const decrypted = _umbral.decryptData([encryptedDataA[0]], ocKeyPair.privateKey, ocKeyPair.publicKey)

//     expect(decrypted.malformed.length).to.equal(1);
//     expect(decrypted.malformed[0].error).to.equal("Decryption requires at least 2 matches")

//   }); 

//   it('Incorrect match found', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createName();
//     let userId = createName();
//     const randIdA: Uint8Array = performOPRF(perpId);
//     const randIdB: Uint8Array = performOPRF(perpId + perpId);

        const ocKeyPair = _sodium.crypto_box_keypair();
        const userKeyPair = _sodium.crypto_box_keypair();

//     const encryptedDataA = _umbral.encryptData(randIdA, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     userId = userId + userId;
//     const encryptedDataB = _umbral.encryptData(randIdB, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
  
//     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//     expect(decrypted.malformed.length).to.equal(2);
//     expect(decrypted.malformed[0].error).to.equal(decrypted.malformed[1].error).to.equal('Matching index does not match with other shares');

//   });

    });

    it('Incorrect match found', async function () {
        await _sodium.ready;
        const _umbral = new Umbral(_sodium);

//   it('Asymmetric encryption failure', async function() {

//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const key: Uint8Array = new Uint8Array([0]);

//     const perpId = createName();
//     let userId = createName();
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

//     const perpId = createName();
//     let userId = createName();
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

//     const perpId = createName();
//     let userId = createName();
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

        // const perpId = createName();
        // let userId = createName();
        // const randId: Uint8Array = performOPRF(perpId);

//   it('3 malformed shares', async function() {

//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();
    
//     const perpId = createName();
//     let userId = createName();

//     const encryptedDataA = _umbral.encryptData(performOPRF(perpId), { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);    
//     const encryptedDataB = _umbral.encryptData(performOPRF(perpId + perpId), { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);
//     const encryptedDataC = _umbral.encryptData(performOPRF(perpId + perpId + perpId), { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

//     const decrypted = _umbral.decryptData([encryptedDataA[0], encryptedDataB[0], encryptedDataC[0]], ocKeyPair.privateKey, ocKeyPair.publicKey);

//     expect(decrypted.malformed.length).to.equal(3);
//     expect(decrypted.records.length).to.equal(0);
//   });

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
});


// describe('User editing', () => {
//   it('Decrypting eUser', async function() {
//     await _sodium.ready;
//     const _umbral = new umbral(_sodium);

//     const ocKeyPair = _sodium.crypto_box_keypair();
//     const userKeyPair = _sodium.crypto_box_keypair();

//     const perpId = createName();
//     let userId = createName();

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

//     const perpId = createName();
//     const userId = createName();

//     const randIdA: Uint8Array = performOPRF(perpId);
//     const encryptedDataA: IEncryptedData[] = _umbral.encryptData(randIdA, { perpId, userId }, [ocKeyPair.publicKey], userKeyPair.privateKey);

//     const newPerpId: string = createName();

//     const malformed: IMalformed[] = _umbral.updateUserRecord(userKeyPair.privateKey, encryptedDataA, {
//       perpId: newPerpId,
//       userId
//     });

//     expect(malformed.length).to.equal(0);
//     const decrypted: IDecryptedData = _umbral.decryptUserRecord(userKeyPair.privateKey, encryptedDataA);
  
//     expect(decrypted.records[0].perpId).to.equal(newPerpId);

        // expect(decrypted.records[0].perpId).to.equal(newPerpId);

//   });
});