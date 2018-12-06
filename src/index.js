import bip39 from 'bip39'
import assert from 'assert'
import hdkey from 'hdkey'
import secp256k1 from 'secp256k1'
import elliptic from 'elliptic'
import { Buffer } from 'safe-buffer'
import {
  buildTransferTransaction,
  buildAccountUpdate,
  buildVote,
  buildFreezeBalance,
  buildUnfreezeBalance,
  buildAssetIssue,
  buildAssetParticipate,
  buildTriggerSmartContract
} from '@tronscan/client/src/utils/transactionBuilder'
import { signTransaction, signBytes } from '@tronscan/client/src/utils/crypto'
import JSSHA from 'jssha'
import { addRef } from './transactionBuilder'
import {
  computeAddress,
  getBase58CheckAddress,
  byteArray2hexStr,
  hexStr2byteArray,
  getTronPubKey,
  pubKeyPointToBytes,
  SHA256,
  SHA256Str
} from './address'
import {
  toHexAddress,
  composeTRC20data
} from './utils'

class TronWallet {
  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static fromMnemonic (mnemonic, isTestNet = false) {
    const seed = bip39.mnemonicToSeed(mnemonic)
    return new this({ seed, isTestNet })
  }

  static fromMasterSeed (seed, isTestNet = false) {
    return new this({ seed, isTestNet })
  }

  static fromExtendedKey (extendedKey, isTestNet = false) {
    return new this({ extendedKey, isTestNet })
  }

  static fromPrivateKey (privateKey, isTestNet = false) {
    return new this({ privateKey, isTestNet })
  }

  static fromTronPrivateKey (pk, isTestNet = false) {
    return new this({ privateKey: Buffer.from(pk, 'hex'), isTestNet })
  }

  static getTxID (transaction) {
    const raw = transaction.raw_data
    if (raw && raw.contract && raw.contract.length > 0) {
      const contract = raw.contract[0]
      if (contract.type === 'TriggerSmartContract') {
        const value = contract.parameter.value
        const txMessage = buildTriggerSmartContract(
          value.owner_address,
          value.contract_address,
          value.call_value,
          value.data
        )
        const rawData = txMessage.getRawData()
        rawData.setRefBlockHash(
          Uint8Array.from(hexStr2byteArray(raw.ref_block_hash))
        )
        rawData.setRefBlockBytes(
          Uint8Array.from(hexStr2byteArray(raw.ref_block_bytes))
        )
        rawData.setExpiration(raw.expiration)
        rawData.setFeeLimit(raw.fee_limit)
        rawData.setTimestamp(raw.timestamp)
        txMessage.setRawData(rawData)
        const digest = txMessage.getRawData().serializeBinary()
        return SHA256Str(digest)
      }
    }
    // TODO: support other transaction types
    return ''
  }

  constructor ({ seed, extendedKey, privateKey, isTestNet }) {
    if (seed) {
      if (Buffer.isBuffer(seed)) {
        this._node = hdkey.fromMasterSeed(seed)
      } else if (typeof seed === 'string') {
        this._node = hdkey.fromMasterSeed(Buffer.from(seed, 'hex'))
      } else {
        throw new Error('seed should be buffer or hex string')
      }
    } else if (extendedKey) {
      this._node = hdkey.fromExtendedKey(extendedKey)
      assert(this._node.privateExtendedKey, 'Please use extend private key')
    } else {
      assert.strictEqual(
        privateKey.length,
        32,
        'Private key must be 32 bytes.'
      )
      assert(secp256k1.privateKeyVerify(privateKey), 'Invalid private key')
      this._node = {
        publicKey: secp256k1.publicKeyCreate(privateKey, true),
        privateKey: privateKey
      }
    }
    this._isTestNet = isTestNet || false
  }

  derivePath (path) {
    assert(
      this._node.derive,
      'can not derive when generate from private / public key'
    )
    return new TronWallet({
      extendedKey: this._node.derive(path).privateExtendedKey,
      isTestNet: this._isTestNet
    })
  }

  deriveChild (index) {
    assert(
      this._node.deriveChild,
      'can not derive when generate from private / public key'
    )
    return new TronWallet({
      extendedKey: this._node.deriveChild(index).privateExtendedKey,
      isTestNet: this._isTestNet
    })
  }

  getPrivateExtendedKey () {
    assert(
      this._node.privateExtendedKey,
      'can not get xpriv when generate from private / public key'
    )
    return this._node.privateExtendedKey
  }

  getPublicExtendedKey () {
    assert(
      this._node.publicExtendedKey,
      'can not get xpub when generate from private / public key'
    )
    return this._node.publicExtendedKey
  }

  getPrivateKey () {
    assert(
      this._node.privateKey,
      'can not get private when generate from public key'
    )
    return this._node.privateKey
  }

  getTronPrivateKey () {
    const priKey = this.getPrivateKey()
    let priKeyHex = priKey.toString('hex')
    while (priKeyHex.length < 64) {
      priKeyHex = '0' + priKeyHex
    }
    this._priKeyBytes = hexStr2byteArray(priKeyHex)

    return byteArray2hexStr(this._priKeyBytes)
  }

  getAddress () {
    const addressBytes = computeAddress(getTronPubKey(this._node.publicKey), this._isTestNet)
    return getBase58CheckAddress(addressBytes)
  }

  updateTransaction (tx, latestBlock, isTRC20 = false) {
    const transactionWithRefs = addRef(tx, latestBlock, isTRC20)
    const signed = signTransaction(
      this.getTronPrivateKey(),
      transactionWithRefs
    )
    const shaObj = new JSSHA('SHA-256', 'HEX')
    shaObj.update(signed.hex)
    const txid = shaObj.getHash('HEX')
    return { txid, ...signed }
  }

  generateTransaction (to, amount, token = 'TRX', latestBlock) {
    const transaction = buildTransferTransaction(
      token,
      this.getAddress(),
      to,
      amount
    )
    return this.updateTransaction(transaction, latestBlock)
  }

  signMessage (message) {
    return byteArray2hexStr(
      signBytes(this.getTronPrivateKey(), Buffer.from(message))
    )
  }

  verfiyMessage (address, signature, message) {
    const EC = elliptic.ec
    const messageBytes = Buffer.from(message)
    const signedMessage = SHA256(messageBytes)

    const signObj = {
      r: signature.slice(0, 64),
      s: signature.slice(64, 128)
    }
    const signatureBytes = hexStr2byteArray(signature)
    const recoverId = signatureBytes[signatureBytes.length - 1]
    const ec = new EC('secp256k1')
    const pub = ec.recoverPubKey(signedMessage, signObj, recoverId)
    const pubBytes = pubKeyPointToBytes(pub)
    const computedAddress = getBase58CheckAddress(computeAddress(pubBytes))
    return computedAddress === address
  }

  updateAccount (name, latestBlock) {
    const transaction = buildAccountUpdate(this.getAddress(), name)
    return this.updateTransaction(transaction, latestBlock)
  }

  freeze (amount, duration = 3, latestBlock, resource = 'BANDWIDTH') {
    assert(
      ['BANDWIDTH', 'ENERGY'].includes(resource),
      'resource should be one of [BANDWIDTH, ENERGY]'
    )
    const transaction = buildFreezeBalance(
      this.getAddress(),
      amount,
      duration,
      resource
    )
    return this.updateTransaction(transaction, latestBlock)
  }

  unfreeze (latestBlock, resource = 'BANDWIDTH') {
    assert(
      ['BANDWIDTH', 'ENERGY'].includes(resource),
      'resource should be one of [BANDWIDTH, ENERGY]'
    )
    const transaction = buildUnfreezeBalance(this.getAddress(), resource)
    return this.updateTransaction(transaction, latestBlock)
  }

  transferTRC20Token (contractAddress, to, amount, latestBlock) {
    const ownerAddress = toHexAddress(this.getAddress())
    const hexContractAddress = toHexAddress(contractAddress)
    const data = composeTRC20data(to, amount)
    const transaction = buildTriggerSmartContract(ownerAddress, hexContractAddress, 0, data)
    return this.updateTransaction(transaction, latestBlock, true)
  }

  vote (votes, latestBlock) {
    const transaction = buildVote(this.getAddress(), votes)
    return this.updateTransaction(transaction, latestBlock)
  }

  issueAssets (options, latestBlock) {
    const transaction = buildAssetIssue(options, latestBlock)
    return this.updateTransaction(transaction, latestBlock)
  }

  buyAssets (issuer, token, amount, latestBlock) {
    const transaction = buildAssetParticipate(
      this.getAddress(),
      issuer,
      token,
      amount
    )
    return this.updateTransaction(transaction, latestBlock)
  }
}

export default TronWallet
