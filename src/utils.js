import { byteArray2hexStr, SHA256 } from './address'
import { Buffer } from 'safe-buffer'
import sha3 from 'js-sha3'

import * as Ethers from 'ethers'

function isHex (string) {
  return typeof string === 'string' && !isNaN(parseInt(string, 16))
}

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const ALPHABET_MAP = {}

for (let i = 0; i < ALPHABET.length; i++) { ALPHABET_MAP[ALPHABET.charAt(i)] = i }

const BASE = 58

export function encode58 (buffer) {
  if (buffer.length === 0) { return '' }

  let i
  let j

  const digits = [0]

  for (i = 0; i < buffer.length; i++) {
    for (j = 0; j < digits.length; j++) { digits[j] <<= 8 }

    digits[0] += buffer[i]
    let carry = 0

    for (j = 0; j < digits.length; ++j) {
      digits[j] += carry
      carry = (digits[j] / BASE) | 0
      digits[j] %= BASE
    }

    while (carry) {
      digits.push(carry % BASE)
      carry = (carry / BASE) | 0
    }
  }

  for (i = 0; buffer[i] === 0 && i < buffer.length - 1; i++) { digits.push(0) }

  return digits.reverse().map(digit => ALPHABET[digit]).join('')
}

export function decode58 (string) {
  if (string.length === 0) { return [] }

  let i
  let j

  const bytes = [0]

  for (i = 0; i < string.length; i++) {
    const c = string[i]

    if (!(c in ALPHABET_MAP)) { throw new Error('Non-base58 character') }

    for (j = 0; j < bytes.length; j++) { bytes[j] *= BASE }

    bytes[0] += ALPHABET_MAP[c]
    let carry = 0

    for (j = 0; j < bytes.length; ++j) {
      bytes[j] += carry
      carry = bytes[j] >> 8
      bytes[j] &= 0xff
    }

    while (carry) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }

  for (i = 0; string[i] === '1' && i < string.length - 1; i++) { bytes.push(0) }

  return bytes.reverse()
}

export function decodeBase58Address (base58Sting) {
  if (typeof (base58Sting) !== 'string') { return false }

  if (base58Sting.length <= 4) { return false }

  let address = decode58(base58Sting)

  if (base58Sting.length <= 4) { return false }

  const len = address.length
  const offset = len - 4
  const checkSum = address.slice(offset)

  address = address.slice(0, offset)

  const hash0 = SHA256(address)
  const hash1 = SHA256(hash0)
  const checkSum1 = hash1.slice(0, 4)

  if (checkSum[0] === checkSum1[0] && checkSum[1] === checkSum1[1] && checkSum[2] ===
        checkSum1[2] && checkSum[3] === checkSum1[3]
  ) {
    return address
  }

  throw new Error('Invalid address provided')
}

export function toHexAddress (address) {
  if (isHex(address)) { return address.toLowerCase().replace(/^0x/, '41') }

  return byteArray2hexStr(
    decodeBase58Address(address)
  ).toLowerCase()
}

export function composeTRC20data (to, amount = 0) {
  const functionSelector = 'transfer(address,uint256)'
  const types = ['address', 'uint256']
  const toAddress = toHexAddress(to).replace(/^(41)/, '0x')
  const values = [toAddress, amount]

  const abiCoder = new Ethers.utils.AbiCoder()
  const parameters = abiCoder.encode(types, values).replace(/^(0x)/, '')
  const selectorByteArray = sha3.keccak256.array(Buffer.from(functionSelector)).slice(0, 4)

  return byteArray2hexStr(selectorByteArray).toLowerCase() + parameters
}
