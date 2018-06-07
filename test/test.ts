import { CryptoService } from '../src/index';
import { expect } from 'chai';
var _sodium = require('libsodium-wrappers');



describe('hello test', () => {
  it('initialization', async function() {
    await _sodium.ready;
    
    const ocKeyPair = _sodium.crypto_box_keypair();
    const userKeys = _sodium.crypto_box_keypair();

    const randId: Uint8Array = (_sodium.crypto_hash('helloWorld')).slice(0, 32);;

    // _sodium.crypto_kdf_derive_from_key(32, 1, "derivation", randId);
    CryptoService.init(_sodium)
    CryptoService.encryptData(randId, 'meow', [ocKeyPair.publicKey])
  });
});

