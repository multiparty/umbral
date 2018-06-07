import { CryptoService } from '../src/index';
import { expect } from 'chai';

describe('hello test', () => {
  it('hello!', () => {
    const result = CryptoService.hello();
    expect(result).to.equal('hello');
  });
});

