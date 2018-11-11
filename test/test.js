const bip39 = require('bip39')
const fetch = require('node-fetch')
const TronWallet = require('../')
const mnemonic = 'cobo wallet is awesome'
const assert = require('assert')
const seed = bip39.mnemonicToSeedHex(mnemonic)
const pk = '43B75088348B0E2F0B5FABC6F43CF5C084B0010FBFA2D86160A70E5AF7E17E56'
const pk1 = '2193A720B5811BE5E48D8D25CF7473D47E3556A017922ED36CC3A3A137437751'

describe('Tron Wallet', function () {
  it('Can get tron account from HD wallet structure', () => {
    const node = TronWallet.fromMasterSeed(seed, true)
    const node1 = TronWallet.fromTronPrivateKey(pk, true)
    const nodeMainnet = TronWallet.fromTronPrivateKey(pk)

    assert.equal(node.getAddress(), '27QXjqR1iz6DhRNPj9PXx7W6h6NwM3r4gT2')
    assert.equal(node.getTronPrivateKey(), '2EBF15FCEF9CEF30CA13731FD08CEB6F4F7C5E1C2A5794977068FD9BAC2E2DAC')
    assert.equal(node1.getAddress(), '27UozX7c7y8iXJRQ9La9kwGozokGnBURhfV')
    assert.equal(nodeMainnet.getAddress(), 'TFhgyoHkWzhHcF9v1iWUsMxG1poAg8xxXb')
  })

  it('Can generate new mnemonic and import', () => {
    const myMnemonic = TronWallet.generateMnemonic()
    const node = TronWallet.fromMnemonic(myMnemonic)
    assert(node.getAddress())
  })

  it('Can import from private extended key', () => {
    const node = TronWallet.fromExtendedKey('xprv9s21ZrQH143K27GwrJ5SPAZc9KPn8i8gkjeXcQe5vPtRPgUDyoq8qrh4qCRPwZAxzP8abdc9nZduW7UDYN1B5V6rjhc3YPMXzr9ArHaM4M6')
    assert(node.getAddress())
  })

  it('Can import from public extended key', () => {
    const node = TronWallet.fromExtendedKey('xpub661MyMwAqRbcEbMQxKcSkJWLhMEGYArY7xa8Qo3hUjRQGUoNXM9PPf1YgT9CCwi8MNvRLW91thbtChgu6eP5qcUeg3x2QLQGfFfC5LqM5dt')
    assert(node.getAddress())
  })

  it('Can derive to child nodes and get address', () => {
    const parentNode = TronWallet.fromMasterSeed(seed, true)
    const childNode1 = parentNode.derivePath("m/44'/194'/0'/0/0")
    assert.equal(childNode1.getAddress(), '27Vsbb84NX6hNgR7kAGwi74BAXV7TdCcHTp')
    const childNode2 = parentNode.deriveChild(0)
    assert.equal(childNode2.getAddress(), '27Qy2jqg5KLzwKxz4HYxabqqiEkAkBWb4aN')
  })

  it('Can generate from tron private key', async () => {
    // 43B75088348B0E2F0B5FABC6F43CF5C084B0010FBFA2D86160A70E5AF7E17E56
    const node = TronWallet.fromTronPrivateKey(pk, false)
    const res = await fetch('https://api.tronscan.org/api/block?sort=-timestamp&limit=1')
    const { data } = await res.json()
    const tx = node.generateTransaction('TFhgyoHkWzhHcF9v1iWUsMxG1poAg8xxXb', 1000000, 'TRX', data[0])
    return tx
  })

  it('Cen generate transaction offline', () => {
    const node = TronWallet.fromTronPrivateKey(pk, false)
    const latestBlock = {
      hash: '315f1ee0e082a1dae1b9de559665c6714f3b8667f69cd5e44466ba6e34d37aef',
      number: 1936,
      timestamp: 1527682440000
    }
    const tx = node.generateTransaction('27Vsbb84NX6hNgR7kAGwi74BAXV7TdCcHTp', 100000000, 'TRX', latestBlock)
    return tx
  })

  it('Can sign the message and verify it', () => {
    const node = TronWallet.fromTronPrivateKey(pk, false)
    const tx = node.signMessage('helloTron')
    const address = node.getAddress()
    assert(node.verfiyMessage(address, tx, 'helloTron'))
  })

  it('Will return false if sign the messaged is not matched', () => {
    const node = TronWallet.fromTronPrivateKey(pk, false)
    const tx = node.signMessage('helloTron')
    const address = node.getAddress()
    assert.equal(node.verfiyMessage(address, tx, 'helloTron2'), false)
  })

  it('Can freeze some TRX', async () => {
    const node = TronWallet.fromTronPrivateKey(pk1, false)
    const res = await fetch('https://api.tronscan.org/api/block?sort=-timestamp&limit=1')
    const { data } = await res.json()
    const tx = node.freeze(10000000, 3, data[0])
    return tx
  })

  it('Can unfreeze TRX', async () => {
    const node = TronWallet.fromTronPrivateKey(pk, false)
    const res = await fetch('https://api.tronscan.org/api/block?sort=-timestamp&limit=1')
    const { data } = await res.json()
    const tx = node.unfreeze(data[0])
    return tx
  })

  it('Verify Tronbet TriggerSmartContract', () => {
    const tx = {
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data:
                  'a3082be900000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000001',
                owner_address: '41f927c5f87d9070cad933af1bbe9ac81d8fa7b9c9',
                contract_address: '412ec5f63da00583085d4c2c5e8ec3c8d17bde5e28',
                call_value: 10000000
              },
              type_url: 'protocol.TriggerSmartContract'
            },
            type: 'TriggerSmartContract'
          }
        ],
        ref_block_bytes: '6aea',
        ref_block_hash: '8a701d5b40f79e8f',
        expiration: 1541634210000,
        fee_limit: 6000000,
        timestamp: 1541634152623
      }
    }
    assert.equal('5625749ba36702ddb3bf158b4ce20ba4e8f552ac8639b6c5ecc88101aa5326b2', TronWallet.getTxID(tx).toString())
  })

  it('Verify Trondice TriggerSmartContract', () => {
    const tx = {
      // txID: '3191743bb7b3b0f9318d4c534fb7966b13888bdac409d2f6f2a7201698e3748a',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data: '7365870b0000000000000000000000000000000000000000000000000000000000000032',
                owner_address: '41f927c5f87d9070cad933af1bbe9ac81d8fa7b9c9',
                contract_address: '41e19c9914380de8eb9df99b9e6965bd5bf75f2c66',
                call_value: 10000000
              },
              type_url: 'type.googleapis.com/protocol.TriggerSmartContract'
            },
            type: 'TriggerSmartContract'
          }
        ],
        ref_block_bytes: '3059',
        ref_block_hash: 'b4d0180f66dc5d5b',
        expiration: 1541785920000,
        fee_limit: 1000000000,
        timestamp: 1541785861024
      }
    }
    assert.equal('3191743bb7b3b0f9318d4c534fb7966b13888bdac409d2f6f2a7201698e3748a', TronWallet.getTxID(tx).toString())
  })

  it('Verify TronFOMO TriggerSmartContract', () => {
    const tx = {
      // txID: 'c8bfe791e44a0866396774c093d2e545ef32ed41d05159c076540ff2ed906cac',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data: 'b32820e9000000000000000000000000000000000000000000000000000000000000000a',
                owner_address: '41f927c5f87d9070cad933af1bbe9ac81d8fa7b9c9',
                contract_address: '416be6e1772a94567134116b8e069595dce3f67276',
                call_value: 16000000
              },
              type_url: 'type.googleapis.com/protocol.TriggerSmartContract'
            },
            type: 'TriggerSmartContract'
          }
        ],
        ref_block_bytes: '3123',
        ref_block_hash: '0a326df637e5ac33',
        expiration: 1541786532000,
        fee_limit: 1000000000,
        timestamp: 1541786474648
      }
    }
    assert.equal('c8bfe791e44a0866396774c093d2e545ef32ed41d05159c076540ff2ed906cac', TronWallet.getTxID(tx).toString())
  })

  it('Verify TronBaccarat TriggerSmartContract', () => {
    const tx = {
      // txID: 'f10f5ce33e74eef37b053eae019ee1142898fb82e915c8b4bd950e7591495faa',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data:
                  'ab2e5a1f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009896800000000000000000000000000000000000000000000000000000000000000000',
                owner_address: '41f927c5f87d9070cad933af1bbe9ac81d8fa7b9c9',
                contract_address: '41f567f77c5db3cf0a7666976c35ccf9ea492570f0',
                call_value: 10000000
              },
              type_url: 'type.googleapis.com/protocol.TriggerSmartContract'
            },
            type: 'TriggerSmartContract'
          }
        ],
        ref_block_bytes: '32ee1',
        ref_block_hash: 'fe25ae1f3babbdda',
        expiration: 1541787909000,
        fee_limit: 1000000000,
        timestamp: 1541787852531
      }
    }
    assert.equal('f10f5ce33e74eef37b053eae019ee1142898fb82e915c8b4bd950e7591495faa', TronWallet.getTxID(tx).toString())
  })
})
