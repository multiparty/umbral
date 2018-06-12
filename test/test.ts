import { CryptoService } from '../src/index';
import { expect } from 'chai';
import { IRecord } from '../src/service';
var _sodium = require('libsodium-wrappers');



describe('hello test', () => {
  it('basic example', async function() {
    await _sodium.ready;
    
    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeys = _sodium.crypto_box_keypair();

    const randId: Uint8Array = (_sodium.crypto_hash('helloWorld')).slice(0, 32);;

    CryptoService.init(_sodium)

    var record: IRecord = {
      perpId: 'harvey weinstein',
      userId: 'meow'
    }

    var encryptedDataA = CryptoService.encryptData(randId, record, [ocKeyPair.publicKey], userKeys.privateKey);
    record.userId = 'meowmeow';
    var encryptedDataB = CryptoService.encryptData(randId, record, [ocKeyPair.publicKey], userKeys.privateKey);

    var decryptedRecords = CryptoService.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, userKeys.publicKey);

    expect(decryptedRecords[0].perpId).to.equal(decryptedRecords[1].perpId);
  });
});

