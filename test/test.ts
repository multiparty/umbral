import { CryptoService } from '../src/index';
import { expect } from 'chai';
var _sodium = require('libsodium-wrappers');



describe('hello test', () => {
  it('initialization', async function() {
    await _sodium.ready;
    
    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeys = _sodium.crypto_box_keypair();

    const randId: Uint8Array = (_sodium.crypto_hash('helloWorld')).slice(0, 32);;

    CryptoService.init(_sodium)
    var encryptedDataA = CryptoService.encryptData(randId, 'meow', [ocKeyPair.publicKey], userKeys.privateKey);
    var encryptedDataB = CryptoService.encryptData(randId, 'meowmeow', [ocKeyPair.publicKey], userKeys.privateKey);

    CryptoService.decryptData([encryptedDataA[0], encryptedDataB[0]], ocKeyPair.privateKey, userKeys.publicKey);

  });
});

