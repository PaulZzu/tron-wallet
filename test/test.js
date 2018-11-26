const bip39 = require('bip39')
const hdkey = require('hdkey')
const TronWallet = require('../')
const assert = require('assert')

const mnemonic = 'cobo wallet is awesome'
const seed =
  '621aec8c28bf4689bdc19558fe3d7881b354a0586be1090e6dc308fddf161af46df067ee458fbafe160a29ea64d21a402dfa8c4f14f41cde84142eee8be69aa2' // mnemonicToSeedHex

const xprv =
  'xprv9yQPCnKHN6U5BLPJN5b6AL7KvQQtADWThKbpVeSGFuvenZFgXzKGpEcKpvHcSJT6sTSsDP8gLQETecqnHDQuEajtCa27dqdBjxc8fgusWU1' // path: m/44'/195'/0'

const pk = '986e593a779463e5d15fba95939f22d48736ccac90d4d451942cdc1047757f06' // path: m/44'/195'/0'/0/0
const addressMainNet = 'TUAhxw3MgMyR9rhyrMDnVJbo3bky1GSUrH' // path: m/44'/195'/0'/0/0

const refBlock = {
  hash: '315f1ee0e082a1dae1b9de559665c6714f3b8667f69cd5e44466ba6e34d37aef',
  number: 1936,
  timestamp: 1527682440000
}

describe('Tron Wallet', function () {
  it('Can import wallet from multiple way', () => {
    assert.strictEqual(
      TronWallet.fromMnemonic(mnemonic)
        .derivePath("m/44'/195'/0'/0/0")
        .getAddress(),
      addressMainNet
    )

    assert.strictEqual(
      TronWallet.fromMasterSeed(seed)
        .derivePath("m/44'/195'/0'/0/0")
        .getAddress(),
      addressMainNet
    )

    assert.strictEqual(
      TronWallet.fromExtendedKey(xprv)
        .derivePath('m/0/0')
        .getAddress(),
      addressMainNet
    )

    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk).getAddress(),
      addressMainNet
    )

    assert.strictEqual(
      TronWallet.fromPrivateKey(Buffer.from(pk, 'hex')).getAddress(),
      addressMainNet
    )
  })

  it('Can generate test net address', () => {
    const addressTestNet = '27hH1WFMj8Vzer2xDBCs4ZDTXqXEachaTGt' // path: m/44'/195'/0'/0/0, the same path like main net, but different prefix

    assert.strictEqual(
      TronWallet.fromMnemonic(mnemonic, true)
        .derivePath("m/44'/195'/0'/0/0")
        .getAddress(),
      addressTestNet
    )

    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk, true).getAddress(),
      addressTestNet
    )
  })

  it('Can generate new mnemonic and import', () => {
    const newMnemonic = TronWallet.generateMnemonic()
    assert.strictEqual(
      TronWallet.fromMnemonic(newMnemonic)
        .getPrivateKey()
        .toString(),
      hdkey
        .fromMasterSeed(bip39.mnemonicToSeed(newMnemonic))
        .privateKey.toString()
    )
  })

  it('Can derive to child nodes', () => {
    const accountNode = TronWallet.fromExtendedKey(xprv)

    assert.notStrictEqual(
      accountNode.getPrivateKey().toString('hex'),
      accountNode
        .derivePath('m/0/0')
        .getPrivateKey()
        .toString('hex')
    )

    assert.strictEqual(
      accountNode.derivePath('m/0/0').getAddress(),
      addressMainNet
    )

    assert.strictEqual(
      accountNode
        .derivePath('m/0')
        .deriveChild(0)
        .getAddress(),
      addressMainNet
    )
  })

  it('Can generate transaction', async () => {
    const tx = TronWallet.fromTronPrivateKey(pk).generateTransaction(
      'TLNUxjgFxy8YhuhsrynLYsMNx93B4a5NvF',
      1000000,
      'TRX',
      refBlock
    )
    assert.strictEqual(
      tx.hex,
      '0A7E0A0207902208E1B9DE559665C67140A0DEF287BB2C5A67080112630A2D747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E5472616E73666572436F6E747261637412320A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD121541721825CD2A4A8AE79EFE16A42A986916CE7FCA8618C0843D12411219AEEF07CB7228FDFEF2E6861E06D2B0C56929359DAE97C557088002169A146B36B98BB609ADD75F1B56E8D67BE11C162C6645C28E8087015A78FF27B331A301'
    )
  })

  it('Can sign the message', () => {
    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk).signMessage('helloTron'),
      '0C3009511DF885C7F22FF20D94A720A40A1834F3CE7062E334E52646EB9D6CA9EC2D8EAB3F6D7462624593BABBFE46D02C12BDFB842416872F3CE75558FA17C100'
    )
  })

  it('Can verify the message', () => {
    assert(
      TronWallet.fromTronPrivateKey(pk).verfiyMessage(
        addressMainNet,
        '0C3009511DF885C7F22FF20D94A720A40A1834F3CE7062E334E52646EB9D6CA9EC2D8EAB3F6D7462624593BABBFE46D02C12BDFB842416872F3CE75558FA17C100',
        'helloTron'
      )
    )
  })

  it('Can freeze BANDWIDTH', async () => {
    const node = TronWallet.fromTronPrivateKey(pk)
    const freezeBandWidthHex =
      '0A6F0A0207902208E1B9DE559665C67140A0DEF287BB2C5A58080B12540A32747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E467265657A6542616C616E6365436F6E7472616374121E0A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD1080ADE20418031241E1D2A94BAD231B9E189A478E11B5635B0C4EF29EBA004F0BB712996667C7EB42850856893990CFAB9A63B27FB333B6E2993DE9A45572DCCB4501539FC41EDACA00'

    assert.strictEqual(
      node.freeze(10000000, 3, refBlock).hex, // freeze BANDWIDTH default
      freezeBandWidthHex
    )

    assert.strictEqual(
      node.freeze(10000000, 3, refBlock, 'BANDWIDTH').hex,
      freezeBandWidthHex
    )
  })

  it('Can freeze ENERGY', async () => {
    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk).freeze(10000000, 3, refBlock, 'ENERGY')
        .hex,
      '0A710A0207902208E1B9DE559665C67140A0DEF287BB2C5A5A080B12560A32747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E467265657A6542616C616E6365436F6E747261637412200A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD1080ADE204180350011241003854497A4A49704A586D6C1D8B08DCD84C16468F716A14E0D3F8DFADB99AF7CA21083CCBD466FF8413ED5F5BBE53DC8226D945AAB3006FFCF9E41242729E5201'
    )
  })

  it('Can unfreeze', async () => {
    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk).unfreeze(refBlock).hex,
      '0A6A0A0207902208E1B9DE559665C67140A0DEF287BB2C5A53080C124F0A34747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E556E667265657A6542616C616E6365436F6E747261637412170A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD1241EB49F0D9A315EEF9E8FA11234645CDCC70C00618E69D29247BB98DDD01DA9E3AF58D3E46FBD445D7C7945F486B7CC2E2535CF97BAAD2282A1C6A5A7B3B22BB0E00'
    )
  })

  it('Can vote', async () => {
    assert.strictEqual(
      TronWallet.fromTronPrivateKey(pk).vote(
        { TLNUxjgFxy8YhuhsrynLYsMNx93B4a5NvF: 100 },
        refBlock
      ).hex,
      '0A81010A0207902208E1B9DE559665C67140A0DEF287BB2C5A6A080412660A30747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E566F74655769746E657373436F6E747261637412320A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD12190A1541721825CD2A4A8AE79EFE16A42A986916CE7FCA8610641241266A006E65B6EFEECB4FABA70A5BF7352884A4D12F18E5352654B009107163A40F6984CE11D9C532C097B1FC93B88BB47FE3A0F656DDBDC9AEC92509D238859900'
    )
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
    assert.strictEqual(
      '5625749ba36702ddb3bf158b4ce20ba4e8f552ac8639b6c5ecc88101aa5326b2',
      TronWallet.getTxID(tx).toString()
    )
  })

  it('Verify Trondice TriggerSmartContract', () => {
    const tx = {
      // txID: '3191743bb7b3b0f9318d4c534fb7966b13888bdac409d2f6f2a7201698e3748a',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data:
                  '7365870b0000000000000000000000000000000000000000000000000000000000000032',
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
    assert.strictEqual(
      '3191743bb7b3b0f9318d4c534fb7966b13888bdac409d2f6f2a7201698e3748a',
      TronWallet.getTxID(tx).toString()
    )
  })

  it('Verify TronFOMO TriggerSmartContract', () => {
    const tx = {
      // txID: 'c8bfe791e44a0866396774c093d2e545ef32ed41d05159c076540ff2ed906cac',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                data:
                  'b32820e9000000000000000000000000000000000000000000000000000000000000000a',
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
    assert.strictEqual(
      'c8bfe791e44a0866396774c093d2e545ef32ed41d05159c076540ff2ed906cac',
      TronWallet.getTxID(tx).toString()
    )
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
    assert.strictEqual(
      'f10f5ce33e74eef37b053eae019ee1142898fb82e915c8b4bd950e7591495faa',
      TronWallet.getTxID(tx).toString()
    )
  })

  it('triggerContract to transfer token', () => {
    const contractAddress = 'TBAo7PNyKo94YWUq1Cs2LBFxkhTphnAE4T'
    const to = 'TQAg2T2vJcHAX9sbKTEoaoWzt512yUjiFD'
    const amout = 1000000
    assert.equal(TronWallet.fromTronPrivateKey(pk).transferTRC20Token(contractAddress, to, amout, refBlock).hex, '0AD4010A0207902208E1B9DE559665C67140A0DEF287BB2C5AAE01081F12A9010A31747970652E676F6F676C65617069732E636F6D2F70726F746F636F6C2E54726967676572536D617274436F6E747261637412740A1541C79F045E4D48AD8DAE00E6A6714DAE1E000ADFCD1215410D292C98A5ECA06C2085FFF993996423CF66C93B2244A9059CBB0000000000000000000000009BBCE520D984C3B95AD10CB4E32A9294E6338DA300000000000000000000000000000000000000000000000000000000000F424070C0B6E087BB2C90018094EBDC031241DF0F08440F3CA758D432E5566CC1A6F0260BBFBBD1F5BDEB583A4ACDF8E10906125FA005DBE025D508CF2A2F946DA177E63FAF5253C0E3B097449F9F4259DFAB00')
  })
})
