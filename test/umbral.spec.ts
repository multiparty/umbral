import { Umbral, IEncryptedData, IEncrypted, IMalformed, IKey, IDecrypted, IEncryptedMap, IOCDataMap } from '../src/umbral';
import { expect } from 'chai';
import { OPRF, IMaskedData } from 'oprf';

var _sodium = require('libsodium-wrappers-sumo');

const SHARE_NO_DECRYPT = 'Share could not be decrypted';
const ASYMMETRIC_DEC_FAIL = 'Asymmetric decryption failure';

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

      const data = decrypted.data;
      for (let i = data - 1; i >= 0; i--) {
        let json = JSON.parse(data[i]);

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

// todo: maybe should be an array of MI's
function replaceMatchingIndex(matchingIndex: string, encrypted: IEncryptedMap) {
  for (let e in encrypted) {
    const ocKey = Object.keys(encrypted[e])[0];
    const obj = encrypted[e][ocKey][0];
    const newObj: IEncryptedData = {
      eOC: obj.eOC,
      eRecord: obj.eRecord,
      eUser: obj.eUser,
      id: obj.id,
      matchingIndex
    }
    encrypted[matchingIndex] = {};
    encrypted[matchingIndex][ocKey] = [];
    encrypted[matchingIndex][ocKey].push(newObj);
    delete encrypted[e];
  }
  return encrypted;
}


describe('Basic end-to-end tests', () => {
  it('Lisa Test', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    var a: IEncryptedData = {eOC: "ZD6wV1lA2JsUTZEZUhySnJrwFstrdlro3ROM-Ho-RglfQHxpp0oJzalsS7EBDj24pyzV5n_VXM1__utFf9Zdu6Gvn1fG3ZP2hnPp2ltZRXWR94SCpZnp_U4L4DRW0bC7kEqCSntVKHf1crLt0qO4BC8W5NCLdNKUrbQZHvr0xEpnUC13A8sqURSYBkAa8oJQzobv0E45Jx4c79DjUm13cJ-TPK\
    8zCRHn4eJ_QItOUCKyp2ZkHCsXt82MJnmLf-2e53A28qg6lx-6o0g7VBEfE2gvy13V6VS7KobEp1T1RLxF698rmU407viqVLt-UH-VHoZ-Ue5FsJzy4Erf6NWb4x6dCdowjj9-S0Cx1E9kD1VPDdh_3WgU0FJMhWLNLVwc9NCUgMYUGkgPSWu-2Rj-WO1V7ZM80mS2dnSJKeCISSRsTVEDmdYrLLYrhoYN\
    3RqJePhyzS0j1FoY",
    eRecord: "5yP9RKlv-XC-jxNWwb4b51DnERP7S-WtdfjeR79cfCjiplAzej2WVYTCXShDE1QSAtGxnJrswdO9qUgI3Y-kJZbSGhE927fAdlvrmoYyycCozlacImhjEYS5-4BS4NgrRUXBIVx0Esoa6ZsnItsuv9mTSH0BYDw91tNH8slCNrbbEyQNLf7sCs2nUUGu6Vy_862KirPrv0wwRYJ2lKyhU2L-\
    Gy33Bt9GG8Q_lWAV6Ioj1mwi6yNT8qZh0p5ugWXLEno_JNOJ6I1VNW2UBV1JdjzG1JesV49uafvT3fItG-nL9ktNPJGCohpWble5F4bgaT64PD304n_6Dq79YeuieEhujM0HNq_Ldwl5WPlaSCxUWm-wHump6zAuyspsBnfzulA$30JfSDL3xZx89g75UMOoH10Hz2F0_OO_",
    eUser: null,
    id: '6',
    matchingIndex: "lz0HhzwFayI2R5PhtviQCDZGcCX4eLfMb1V1YK14b-M"};

    var b: IEncryptedData = {
    eOC: "l4gKQ5MgtirXVL6rDU_OhOdsJOibSQpYd85MBXLraE9kh0lCGoXJocD6lOq90yIrkLyBCtlYSrTgd9jInQj6hqKQ3JfPbal9LHW_bVABXPK_tv7qpAiCrrvdINlJwY4LDxZLczxLTpOv9MXBtt-X-_TOVWH7lyAuEghEpNQuJqvu-4UqD9498Q7Y8aKfa2mwc2fl09tv6kfH4Mjc_gyu96bqoNy2\
    rr0HP7NF2jUnRtJrN92rVUSeUHmGj2cR813fTiWT8i-_i5ZNyPDTBfsNjKWXPU66Ix2IMX_XHqCp09hk-shrZxRhHmEwrTpzRli2bO8IHO_IYBuV25IOx0U7nBQFjgfoZKpU4e10_BaybM-7olIokv_8XWPWKfZ59vAt6WXGKhCXB2TWJOKibZqORT6QuWbznv8fxoChcmwgPJZJS6IDx0onbsNDgcT7qd\
    0NjOuIDgPUPfiEFA",
    eRecord: "KijyHhTZUXqSC4K4q4WKE62PPxbOmWt6tZowCQcsl0K-h8o3KrJHydXc4CTlkIDuqHff4Un2aqfBOSJl2qsvFq9gnyB5WaBv17zT7VLzlG7n4p_t3Lv7_xzfhaVYTo9wlRsguRujTzaJShgb2Ueh871ee2TT_R1Jtw_LVBi4bvWWD_gKInlzP_FwgZNcNzXfA4Rcn9Rtpi-Lqb7XtJa2-YZY\
    -qWuNOIngaHXU05xtkaELlXtzPc9lXwDkDn07jizGtE2FQDRCncWpqL4yn346LmBxtv67_MkLHxNxlGzUV-BoVMTaQ-Hi1Rje5fzO9rhmq7mi-3jNFyaW0YtJfTSOdHpuP_CxftgMT93cWbksrNoVVHgzZBP8aOjSFXLFLVwCIEVVAXo$Zx7sJoSF9whk8D0_jqT3Za-eaFq7jg-i",
    eUser: null,
    id: '4',
    matchingIndex: "lz0HhzwFayI2R5PhtviQCDZGcCX4eLfMb1V1YK14b-M"
    }
    
    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    _umbral.decryptData([a,b], userKeyPair.publicKey, userKeyPair.privateKey);


  });

  it('1 OC, 2 matched users', async function() {

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

  it('1 OC, 5 matched users', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = 'hello';
    const userId = 'world';
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId}), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    const encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataC.encryptedMap);

    const encryptedDataD: IEncrypted = _umbral.encryptData([randId], userId+userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataD.encryptedMap);

    const encryptedDataE: IEncrypted = _umbral.encryptData([randId], userId+userId+userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId+userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataE.encryptedMap);


    expect(encryptedDataA.malformed.length).to.equal(0);
    expect(encryptedDataB.malformed.length).to.equal(0);
    expect(encryptedDataC.malformed.length).to.equal(0);
    expect(encryptedDataD.malformed.length).to.equal(0);
    expect(encryptedDataE.malformed.length).to.equal(0);

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

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId + userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    expect(encryptedDataA.malformed.length).to.equal(0);
    expect(encryptedDataB.malformed.length).to.equal(0);
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

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    const encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
    updateDict(encryptedDict, encryptedDataC.encryptedMap);

    expect(encryptedDataA.malformed.length).to.equal(0);
    expect(encryptedDataB.malformed.length).to.equal(0);
    expect(encryptedDataC.malformed.length).to.equal(0);
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

      let encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataA.encryptedMap);
  
      let encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataB.encryptedMap);
  
      let encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataC.encryptedMap);  
   
      decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
    }
  });

  it('Stress test with rand multiple perp ids (max 3), rand number of OCs (max 3)', async function() {

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();
    const testNum = 1;

    for (let i: number = 0; i < testNum; i++){
      let encryptedDict: IEncryptedMap = {};
      let [publicKeys, privateKeys] = generateKeys(getRandom(10));

      let perpId = createRandString();
      let userId = createRandString();

      // perp ids
      let randIds = getRandIds(4);

      let encryptedDataA: IEncrypted = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataA.encryptedMap);
  
      let encryptedDataB: IEncrypted = _umbral.encryptData(randIds, userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataB.encryptedMap);
  
      let encryptedDataC: IEncrypted = _umbral.encryptData(randIds, userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey);
      updateDict(encryptedDict, encryptedDataC.encryptedMap);  
   
      decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
    }
  });

  it('2 OCs, 3 matched users, no userPassPhrase', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(2);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    const encryptedDataA: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys);
    updateDict(encryptedDict, encryptedDataA.encryptedMap);

    const encryptedDataB: IEncrypted = _umbral.encryptData([randId], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys);
    updateDict(encryptedDict, encryptedDataB.encryptedMap);

    const encryptedDataC: IEncrypted = _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys);
    updateDict(encryptedDict, encryptedDataC.encryptedMap);

    expect(encryptedDataA.malformed.length).to.equal(0);
    expect(encryptedDataB.malformed.length).to.equal(0);
    expect(encryptedDataC.malformed.length).to.equal(0);

    decryptSuccess(encryptedDict, publicKeys, privateKeys, perpId, userId, _umbral);
  });
});

describe('Error cases', () => {

  it('No public keys provided', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);
    const encrypted: IEncrypted = _umbral.encryptData([randId], userId, JSON.stringify({perpId, userId}), {}, userKeyPair.privateKey);

    expect(encrypted.malformed.length).to.equal(1);
    expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
  });

  it('Missing data', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    let [publicKeys, privateKeys] = generateKeys(1);
    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);
    let encrypted: IEncrypted = _umbral.encryptData([randId], userId, '', publicKeys, userKeyPair.privateKey);
    expect(encrypted.malformed.length).to.equal(1);
    expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
    expect(encrypted.malformed[0].error).to.equal('No data provided');

    encrypted = _umbral.encryptData([randId], userId, null, publicKeys, userKeyPair.privateKey);
    expect(encrypted.malformed.length).to.equal(1);
    expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
    expect(encrypted.malformed[0].error).to.equal('No data provided');
  });

  it('Asymmetric encryption failure', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    const publicKey = new Uint8Array([10,10,10,10]);
    
    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);
    const encrypted = _umbral.encryptData([randId], userId, JSON.stringify({perpId, userId}), {"oc": publicKey} , userKeyPair.privateKey);

    expect(encrypted.malformed.length).to.equal(1);
    expect(encrypted.malformed[0].error.toString()).to.contain('invalid publicKey length');
    expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
  });

  it('Asymmetric decryption failure', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    let encryptedDict: IEncryptedMap = {};

    const [publicKeys, privateKeys] = generateKeys(1);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    for (let index in encryptedDict) {
      for (let oc in encryptedDict[index]) {
        const decrypted = _umbral.decryptData(encryptedDict[index][oc], userKeyPair.publicKey, userKeyPair.privateKey);
        expect(decrypted.data.length).to.equal(0);
        expect(decrypted.malformed.length).to.equal(4);
        expect(decrypted.malformed[0].error.toString()).to.contain(ASYMMETRIC_DEC_FAIL);
        expect(decrypted.malformed[1].error.toString()).to.contain(ASYMMETRIC_DEC_FAIL);
        expect(decrypted.malformed[2].error.toString()).to.contain(SHARE_NO_DECRYPT);
        expect(decrypted.malformed[3].error.toString()).to.contain(SHARE_NO_DECRYPT);
      }
    }
  });

  it('Key derivation failure', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
    
    const [publicKeys, privateKeys] = generateKeys(1);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();

    const rand = new Uint8Array([10,10,10]);

    const encrypted = _umbral.encryptData([rand], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey);

    expect(Object.keys(encrypted.encryptedMap).length).to.equal(0);
    expect(encrypted.malformed.length).to.equal(1);
    expect(encrypted.malformed[0].error.toString()).to.contain('Key derivation failure');
  });

  it('Only 1 match provided', async function() {
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

    const matchingIndex = Object.keys(encryptedDict)[0];
    const ocId = Object.keys(publicKeys)[0];

    const encrypted: IEncryptedData[] = encryptedDict[matchingIndex][ocId];
    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    
    expect(decrypted.malformed.length).to.equal(1);
    expect(decrypted.malformed[0].error).to.equal("Decryption requires at least 2 matches")
  }); 


  it('3 malformed shares', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = createRandString();
    let userId = createRandString();
    const randIdA: Uint8Array = performOPRF(perpId);
    const randIdB: Uint8Array = performOPRF(perpId+perpId);
    const randIdC: Uint8Array = performOPRF(perpId+perpId+perpId);

    updateDict(encryptedDict, _umbral.encryptData([randIdA], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdB], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdC], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    // shares all have points that cannot be interpolated, manually changing matchingIndex
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);

    const ocId = Object.keys(publicKeys)[0];
    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(0);
    expect(decrypted.malformed.length).to.equal(3);
  });


  it('2 of the same share', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = createRandString();
    let userId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);

    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    // shares all have points that cannot be interpolated, manually changing matchingIndex
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);

    const ocId = Object.keys(publicKeys)[0];
    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(0);
    expect(decrypted.malformed.length).to.equal(2);
    expect(decrypted.malformed[0].error.toString()).to.contain(SHARE_NO_DECRYPT);
    expect(decrypted.malformed[1].error.toString()).to.contain(SHARE_NO_DECRYPT);
  });

  it('2 decrypted shares, 1 malformed with different matching index', async function() {

    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    var [publicKeys, privateKeys] = generateKeys(1);

    const perpId = createRandString();
    let userId = createRandString();
    const randIdA: Uint8Array = performOPRF(perpId);
    const randIdB: Uint8Array = performOPRF(perpId+perpId);

    updateDict(encryptedDict, _umbral.encryptData([randIdA], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdA], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdB], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];
    
    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(2);
    expect(JSON.parse(decrypted.data[0]).perpId).to.equal(JSON.parse(decrypted.data[1]).perpId);
    expect(decrypted.malformed.length).to.equal(1);
  });

  it('No userPassPhrase used in encryption, should not be able to edit', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();

    var [publicKeys, privateKeys] = generateKeys(4);

    const randIds: Uint8Array[] = getRandIds(5);
    const encryptedData: IEncryptedMap = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId }), publicKeys).encryptedMap;

    const encrypted: IEncryptedData[] = [];

    for (let index in encryptedData) {
      for (let oc in encryptedData[index]) {
        const record = encryptedData[index][oc][0];
        encrypted.push(record);
      }
    }

    const malformed: IMalformed[] = _umbral.updateUserRecord(userKeyPair.privateKey, encrypted, JSON.stringify({
      perpId: perpId+perpId,
      userId
    }));

    expect(malformed.length).to.equal(20);
    // TODO: this should fail
    const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encrypted);

    for (let data of decrypted.data) {
      let json = JSON.parse(data);
      expect(json.perpId).to.equal(perpId);
      expect(json.userId).to.equal(userId);
    }
  });
});

describe('Interpolation cases', () => {
  it('A: 1 valid, 1 invalid', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
    const randIdMalicious: Uint8Array = performOPRF(perpId+perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
  
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(2);
    expect(decrypted.malformed[0].error.toString()).to.equal(decrypted.malformed[1].error.toString()).to.contain(SHARE_NO_DECRYPT);
  });

  it('A+: 1 valid, 3 invalid separate points', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([performOPRF('a')], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([performOPRF('b')], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([performOPRF('c')], userId+userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(0);

    for (var m of decrypted.malformed) {
      expect(m.error).to.equal(SHARE_NO_DECRYPT);
    }
    expect(decrypted.malformed.length).to.equal(4);
  });

  it('B-1: 1 valid, 2 invalid', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
    const randIdMalicious: Uint8Array = performOPRF(perpId+perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
  
    let encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    let decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(3);
    expect(decrypted.malformed[0].error.toString()).to.equal(decrypted.malformed[1].error.toString()).to.equal(decrypted.malformed[2].error.toString()).to.contain(SHARE_NO_DECRYPT);

    // check that the malicious shares would decrypt with one another
    encryptedDict = {};
    updateDict(encryptedDict, _umbral.encryptData([randIdMalicious], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdMalicious], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    encrypted = retrieveEncrypted(encryptedDict);

    decrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(0);
    expect(decrypted.data.length).to.equal(2);
  });

  it('B-2: 1 valid, 2 invalid', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
    const malicious1: Uint8Array = performOPRF(perpId+perpId);
    const malicious2: Uint8Array = performOPRF(perpId+perpId+perpId);

    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([malicious1], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([malicious2], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
  
    let encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    let decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(3);
    expect(decrypted.malformed[0].error.toString()).to.equal(decrypted.malformed[1].error.toString()).to.equal(decrypted.malformed[2].error.toString()).to.contain(SHARE_NO_DECRYPT);

    // check that the malicious shares would decrypt with one another
    encryptedDict = {};
    updateDict(encryptedDict, _umbral.encryptData([malicious1], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([malicious2], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);

    encrypted = retrieveEncrypted(encryptedDict);

    decrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(2);
  });


  it('C: 2 valid, 1 invalid', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
    const randIdMalicious: Uint8Array = performOPRF(perpId+perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
  
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(2);
    expect(JSON.parse(decrypted.data[0]).perpId).to.equal(JSON.parse(decrypted.data[1]).perpId);
    expect(decrypted.malformed.length).to.equal(1);
    expect(decrypted.malformed[0].error.toString()).to.contain(SHARE_NO_DECRYPT);
  });

  it('C+: 3 on line, 1 point', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    let userId = createRandString();

    const randId: Uint8Array = performOPRF(perpId);
    const randIdMalicious: Uint8Array = performOPRF(perpId+perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], userId+userId, JSON.stringify({ perpId, userId: userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, _umbral.encryptData([randId], userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randId], userId+userId+userId+userId, JSON.stringify({ perpId, userId: userId+userId+userId+userId }), publicKeys, userKeyPair.privateKey).encryptedMap);
  
    const encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    const decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.data.length).to.equal(3);
    expect(JSON.parse(decrypted.data[0]).perpId).to.equal(JSON.parse(decrypted.data[1]).perpId).to.equal(JSON.parse(decrypted.data[2]).perpId);
    expect(decrypted.malformed.length).to.equal(1);
    expect(decrypted.malformed[0].error.toString()).to.contain(SHARE_NO_DECRYPT);
  });
  
  it('D-1: 2 valid, 2 invalid', async function() {
    let encryptedDict: IEncryptedMap = {};

    await _sodium.ready;
    const _umbral = new Umbral(_sodium);
  
    const userKeyPair = _sodium.crypto_box_keypair();
  
    var [publicKeys, privateKeys] = generateKeys(1);
  
    const perpId = createRandString();
    const randId: Uint8Array = performOPRF(perpId);
    const randIdMalicious: Uint8Array = performOPRF(perpId+perpId);
  
    updateDict(encryptedDict, _umbral.encryptData([randId], 'A', JSON.stringify({ perpId, userId: 'A' }), publicKeys, userKeyPair.privateKey).encryptedMap);
    const matchingIndex = Object.keys(encryptedDict)[0];
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], 'C', JSON.stringify({ perpId, userId: 'C' }), publicKeys, userKeyPair.privateKey).encryptedMap));
    updateDict(encryptedDict, _umbral.encryptData([randId], 'B', JSON.stringify({ perpId, userId: 'B' }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, replaceMatchingIndex(matchingIndex, _umbral.encryptData([randIdMalicious], 'D', JSON.stringify({ perpId, userId: 'D' }), publicKeys, userKeyPair.privateKey).encryptedMap));
  
    let encrypted: IEncryptedData[] = retrieveEncrypted(encryptedDict);
    const ocId = Object.keys(publicKeys)[0];

    let decrypted: IDecrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(2);
    expect(decrypted.malformed[0].error.toString()).to.equal(decrypted.malformed[1].error.toString()).to.contain(SHARE_NO_DECRYPT);
    expect(JSON.parse(decrypted.data[0]).perpId).to.equal(JSON.parse(decrypted.data[1]).perpId);

    // check that the malicious shares would decrypt with one another
    encryptedDict = {};
    updateDict(encryptedDict, _umbral.encryptData([randIdMalicious], 'C', JSON.stringify({ perpId, userId: 'C' }), publicKeys, userKeyPair.privateKey).encryptedMap);
    updateDict(encryptedDict, _umbral.encryptData([randIdMalicious], 'D', JSON.stringify({ perpId, userId: 'D' }), publicKeys, userKeyPair.privateKey).encryptedMap);

    encrypted = retrieveEncrypted(encryptedDict);

    decrypted = _umbral.decryptData(encrypted, publicKeys[ocId], privateKeys[ocId]);
    expect(decrypted.malformed.length).to.equal(0);
    expect(decrypted.data.length).to.equal(2);
  });

});

describe('User editing', () => {
  it('Decrypting eUser', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();

    var [publicKeys, privateKeys] = generateKeys(4);

    const randIds: Uint8Array[] = getRandIds(5);
    const encryptedData: IEncryptedMap = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap;

    const encrypted: IEncryptedData[] = [];

    for (let index in encryptedData) {
      for (let oc in encryptedData[index]) {
        const record = encryptedData[index][oc][0];
        encrypted.push(record);
      }
    }

    const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encrypted);

    for (let data of decrypted.data) {
      let json = JSON.parse(data);
      expect(json.perpId).to.equal(perpId);
      expect(json.userId).to.equal(userId);
    }
    expect(decrypted.malformed.length).to.equal(0);
  });

  it('Updating user record', async function() {
    await _sodium.ready;
    const _umbral = new Umbral(_sodium);

    const userKeyPair = _sodium.crypto_box_keypair();

    const perpId = createRandString();
    let userId = createRandString();

    var [publicKeys, privateKeys] = generateKeys(4);

    const randIds: Uint8Array[] = getRandIds(5);
    const encryptedData: IEncryptedMap = _umbral.encryptData(randIds, userId, JSON.stringify({ perpId, userId }), publicKeys, userKeyPair.privateKey).encryptedMap;

    const encrypted: IEncryptedData[] = [];

    for (let index in encryptedData) {
      for (let oc in encryptedData[index]) {
        const record = encryptedData[index][oc][0];
        encrypted.push(record);
      }
    }

    const malformed: IMalformed[] = _umbral.updateUserRecord(userKeyPair.privateKey, encrypted, JSON.stringify({
      perpId: perpId+perpId,
      userId
    }));

    expect(malformed.length).to.equal(0);

    const decrypted = _umbral.decryptUserRecord(userKeyPair.privateKey, encrypted);

    for (let data of decrypted.data) {
      let json = JSON.parse(data);
      expect(json.perpId).to.equal(perpId+perpId);
      expect(json.userId).to.equal(userId);
    }
    expect(decrypted.malformed.length).to.equal(0);
  });
});