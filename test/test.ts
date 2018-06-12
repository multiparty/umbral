import { CryptoService } from '../src/index';
import { expect } from 'chai';
import { IRecord } from '../src/service';
var _sodium = require('libsodium-wrappers');

function hashId(id: string): Uint8Array {
  return (_sodium.crypto_hash(id)).slice(0, 32);
}

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

describe('hello test', () => {
  
  
  it('basic example', async function() {
    await _sodium.ready;
    CryptoService.init(_sodium);
  
    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeys = _sodium.crypto_box_keypair();

    const randId: Uint8Array = hashId('harvey weinstein');

    const record: IRecord = {
      perpId: 'harvey weinstein',
      userId: 'meow'
    }

    const encryptedDataA = CryptoService.encryptData(randId, record, [ocKeyPair.publicKey], userKeys.privateKey);
    record.userId = 'meowmeow';
    const encryptedDataB = CryptoService.encryptData(randId, record, [ocKeyPair.publicKey], userKeys.privateKey);

    const decryptedRecords = CryptoService.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, userKeys.publicKey);

    expect(decryptedRecords[0].perpId).to.equal(decryptedRecords[1].perpId);
  });

  it('stress test', async function() {
    await _sodium.ready;
    CryptoService.init(_sodium);

    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeys = _sodium.crypto_box_keypair();

    const testNum: number = 100;
    for (let i: number = 0; i < testNum; i++) {
      const perpId: string = createName();
      const randId: Uint8Array = hashId(perpId);
      let userId: string = createName();

      const encryptedDataA = CryptoService.encryptData(randId, { perpId, userId }, [ocKeyPair.publicKey], userKeys.privateKey);

      userId = userId + userId;
      const encryptedDataB = CryptoService.encryptData(randId, { perpId, userId}, [ocKeyPair.publicKey], userKeys.privateKey);
      
      const decryptedRecords = CryptoService.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, userKeys.publicKey);

    }
  });
});

