// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "CryptoNoteConfig.h"
#include "../../include/CryptoTypes.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include <random>

using namespace CryptoNote;

bool blocksEqual(Block, Block);
Block getBasicBlock();
Crypto::Hash getBasicHash();
Crypto::KeyImage getBasicKeyImage();
Crypto::PublicKey getBasicPublicKey();
Crypto::Signature getBasicSignature();
Transaction getBasicTransaction();
Transaction getRandCoinbaseTransaction();
Transaction getRandBaseTransaction(uint32_t);
Block getRandBlock();
Block getRandBlockAtHeight(uint32_t);
Crypto::Hash getRandHash();
std::string getRandHashStr();
Crypto::KeyImage getRandKeyImage();
Crypto::PublicKey getRandPublicKey();
Crypto::Signature getRandSignature();
Transaction getRandTransaction();
Transaction getRandTransactionAtHeight(uint32_t);
Transaction getRandTransactionNoBaseInput();
uint8_t getRandUint8_t();
uint32_t getRandUint32_t();
uint64_t getRandUint64_t();
bool hashesEqual(Crypto::Hash, Crypto::Hash);
bool hashVectorsEqual(std::vector<Crypto::Hash>, std::vector<Crypto::Hash>);
bool publicKeysEqual(Crypto::PublicKey, Crypto::PublicKey);
bool secretKeysEqual(Crypto::SecretKey, Crypto::SecretKey);


bool blocksEqual(Block a, Block b)
{
  if (a.nonce != b.nonce)
  {
    return false;
  }

  if (a.timestamp != b.timestamp)
  {
    return false;
  }

  if (!hashesEqual(a.previousBlockHash, b.previousBlockHash))
  {
    return false;
  }

  if (!std::equal(a.transactionHashes.begin(), a.transactionHashes.end(), b.transactionHashes.begin()))
  {
    return false;
  }

  Crypto::Hash aBaseTransactionHash = getObjectHash(a.baseTransaction);
  Crypto::Hash bBaseTransactionHash = getObjectHash(b.baseTransaction);

  if (!hashesEqual(aBaseTransactionHash, bBaseTransactionHash))
  {
    return false;
  }

  Crypto::Hash aBlockHash = getObjectHash(a);
  Crypto::Hash bBlockHash = getObjectHash(b);

  if (!hashesEqual(aBlockHash, bBlockHash))
  {
    return false;
  }

  return true;
}

Block getBasicBlock()
{
  Block block;

  // nonce
  block.nonce = 2;

  // timestamp
  block.timestamp = 5;

  // previous block hash
  block.previousBlockHash = getBasicHash();

  // base transaction
  block.baseTransaction = getBasicTransaction();

  // transaction hashes
  uint8_t randNumTransactions = getRandUint8_t();
  for (uint8_t i = 0; i < randNumTransactions; ++i)
  {
    block.transactionHashes.push_back(getBasicHash());
  }

  return block;
}

Crypto::Hash getBasicHash()
{
  Crypto::Hash hash;
  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = 1;
  }

  return hash;
}

Crypto::KeyImage getBasicKeyImage()
{
  Crypto::KeyImage keyImage;
  size_t keyImageSize = sizeof(keyImage.data) / sizeof(keyImage.data[0]);

  for (int i = 0; i < keyImageSize; ++i)
  {
    keyImage.data[i] = 1;
  }

  return keyImage;
}

Crypto::PublicKey getBasicPublicKey()
{
  Crypto::PublicKey publicKey;

  size_t publicKeySize = sizeof(publicKey.data) / sizeof(publicKey.data[0]);

  for (int i = 0; i < publicKeySize; ++i)
  {
    publicKey.data[i] = 1;
  }

  return publicKey;
}

Crypto::Signature getBasicSignature()
{
  Crypto::Signature signature;
  size_t signatureSize = sizeof(signature.data) / sizeof(signature.data[0]);

  for (size_t i = 0; i < signatureSize; ++i)
  {
    signature.data[i] = 1;
  }

  return signature;
}

Transaction getBasicTransaction()
{
  Transaction transaction;
  
  // version
  transaction.version = 1;

  // unlock time
  transaction.unlockTime = 1;

  // inputs
  BaseInput baseInput;
  baseInput.blockIndex = 1;

  // add BaseInput transaction
  transaction.inputs.push_back(baseInput);

  uint8_t numKeyInputs = 2;

  for (uint8_t i = 0; i < numKeyInputs; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = 10;
    
    std::vector<uint32_t> outputIndexes;
    outputIndexes.push_back(i);
    keyInput.outputIndexes = outputIndexes;

    keyInput.keyImage = getBasicKeyImage();

    // add KeyInput transaction
    transaction.inputs.push_back(keyInput);
  }

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;

  KeyOutput keyOutput;
  keyOutput.key = getBasicPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);
  // create basic payment id
  for (int i = 0; i < 32; ++i)
  {
    transaction.extra.push_back(1);
  }

  // signatures
  std::vector<Crypto::Signature> temp;
  // signature for coinbase transaction is empty
  transaction.signatures.push_back(temp);

  for (uint8_t i = 0; i < numKeyInputs; ++i)
  {
    std::vector<Crypto::Signature> temp;

    temp.push_back(getBasicSignature());

    transaction.signatures.push_back(temp);
  }

  return transaction;
}

Transaction getRandCoinbaseTransaction()
{
  Transaction transaction;
  
  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = getRandUint64_t();

  // inputs
  BaseInput baseInput;
  baseInput.blockIndex = getRandUint32_t();

  // add BaseInput transaction
  transaction.inputs.push_back(baseInput);

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);
  // create random payment id
  for (int i = 0; i < 32; ++i)
  {
    transaction.extra.push_back(getRandUint32_t());
  }

  // signatures
  std::vector<Crypto::Signature> temp;

  // signature for coinbase transaction is empty
  transaction.signatures.push_back(temp);

  return transaction;
}

Transaction getRandBaseTransaction(uint32_t blockHeight)
{
  Transaction transaction;
  
  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = getRandUint64_t();

  // inputs
  BaseInput baseInput;
  baseInput.blockIndex = blockHeight;

  // add BaseInput transaction
  transaction.inputs.push_back(baseInput);

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  return transaction;
}

Block getRandBlock()
{
  Block block;

  // nonce
  block.nonce = getRandUint32_t();

  // timestamp
  block.timestamp = getRandUint64_t();

  // previous block hash
  block.previousBlockHash = getRandHash();

  // base transaction
  block.baseTransaction = getRandTransaction();

  // transaction hashes
  uint8_t randNumTransactions = getRandUint8_t();
  for (uint8_t i = 0; i < randNumTransactions; ++i)
  {
    block.transactionHashes.push_back(getRandHash());
  }

  return block;
}

Block getRandBlockAtHeight(uint32_t blockHeight)
{
  Block block;

  // nonce
  block.nonce = getRandUint32_t();

  // timestamp
  block.timestamp = getRandUint64_t();

  // previous block hash
  block.previousBlockHash = getRandHash();

  // base transaction
  block.baseTransaction = getRandBaseTransaction(blockHeight);

  // transaction hashes
  uint8_t randNumTransactions = getRandUint8_t();
  for (uint8_t i = 0; i < randNumTransactions; ++i)
  {
    block.transactionHashes.push_back(getRandHash());
  }

  return block;
}

Crypto::Hash getRandHash()
{
  Crypto::Hash hash;
  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = getRandUint8_t();
  }

  return hash;
}

std::string getRandHashStr()
{
  char hexArr[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  std::string hashStr;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // podFromHex in StringTools.h requires that the size of the hash string be twice the size of Crypto::Hash (32 bytes) because 2 characters converts to one hex value
  for (int i = 0; i < hashSize * 2; ++i)
  {
    hashStr.push_back(hexArr[rand() % 16]);
  }

  return hashStr;
}

Crypto::KeyImage getRandKeyImage()
{
  Crypto::KeyImage keyImage;
  size_t keyImageSize = sizeof(keyImage.data) / sizeof(keyImage.data[0]);

  for (int i = 0; i < keyImageSize; ++i)
  {
    keyImage.data[i] = getRandUint8_t();
  }

  return keyImage;
}

Crypto::PublicKey getRandPublicKey()
{
  KeyPair keyPair = generateKeyPair();

  return keyPair.publicKey;
}

Crypto::Signature getRandSignature()
{
  Crypto::Signature signature;
  size_t signatureSize = sizeof(signature.data) / sizeof(signature.data[0]);

  for (size_t i = 0; i < signatureSize; ++i)
  {
    signature.data[i] = getRandUint8_t();
  }

  return signature;
}

Transaction getRandTransaction()
{
  Transaction transaction;
  
  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = getRandUint64_t();

  // inputs
  BaseInput baseInput;
  baseInput.blockIndex = getRandUint32_t();

  // add BaseInput transaction
  transaction.inputs.push_back(baseInput);

  uint8_t randKeyInputs = getRandUint8_t();

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = getRandUint8_t();
    
    std::vector<uint32_t> outputIndexes;
    outputIndexes.push_back(getRandUint32_t());
    keyInput.outputIndexes = outputIndexes;

    keyInput.keyImage = getRandKeyImage();

    // add KeyInput transaction
    transaction.inputs.push_back(keyInput);
  }

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint32_t();

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);
  // create random payment id
  for (int i = 0; i < 32; ++i)
  {
    transaction.extra.push_back(getRandUint32_t());
  }

  // signatures
  std::vector<Crypto::Signature> temp;
  // signature for coinbase transaction is empty
  transaction.signatures.push_back(temp);

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    std::vector<Crypto::Signature> temp;

    temp.push_back(getRandSignature());

    transaction.signatures.push_back(temp);
  }

  return transaction;
}

Transaction getRandTransactionAtHeight(uint32_t blockHeight)
{
  Transaction transaction;
  
  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = getRandUint64_t();

  // inputs
  BaseInput baseInput;
  baseInput.blockIndex = blockHeight;

  // add BaseInput transaction
  transaction.inputs.push_back(baseInput);

  uint8_t randKeyInputs = getRandUint8_t();

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = getRandUint64_t();
    
    std::vector<uint32_t> outputIndexes;
    outputIndexes.push_back(getRandUint32_t());
    keyInput.outputIndexes = outputIndexes;

    keyInput.keyImage = getRandKeyImage();

    // add KeyInput transaction
    transaction.inputs.push_back(keyInput);
  }

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);
  // create random payment id
  for (int i = 0; i < 32; ++i)
  {
    transaction.extra.push_back(getRandUint32_t());
  }

  // signatures
  std::vector<Crypto::Signature> temp;
  // signature for coinbase transaction is empty
  transaction.signatures.push_back(temp);

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    std::vector<Crypto::Signature> temp;

    temp.push_back(getRandSignature());

    transaction.signatures.push_back(temp);
  }

  return transaction;
}

// no coinbase input in inputs
Transaction getRandTransaction2()
{
  Transaction transaction;
  
  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = getRandUint64_t();

  // inputs
  uint8_t randKeyInputs = getRandUint8_t();

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = getRandUint8_t();
    
    std::vector<uint32_t> outputIndexes;
    outputIndexes.push_back(getRandUint32_t());
    keyInput.outputIndexes = outputIndexes;

    keyInput.keyImage = getRandKeyImage();

    // add KeyInput transaction
    transaction.inputs.push_back(keyInput);
  }

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint32_t();

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);
  // create random payment id
  for (int i = 0; i < 32; ++i)
  {
    transaction.extra.push_back(getRandUint32_t());
  }

  // signatures
  std::vector<Crypto::Signature> temp;

  for (uint8_t i = 0; i < randKeyInputs; ++i)
  {
    std::vector<Crypto::Signature> temp;

    temp.push_back(getRandSignature());

    transaction.signatures.push_back(temp);
  }

  return transaction;
}

uint8_t getRandUint8_t()
{
  // initialize the seed engine
  std::random_device rd;
  // use Mersenne-Twister random-number engine
  std::mt19937 rng(rd());
  std::uniform_int_distribution<int> uni(0, 255);

  return uni(rng);
}

uint32_t getRandUint32_t()
{
  // obtain a random number from hardware
  std::random_device rd;

  // 32 bit seed for the generator
  std::mt19937 gen(rd());

  return gen();
}

uint64_t getRandUint64_t()
{
  // obtain a random number from hardware
  std::random_device rd;

  // 64 bit seed for the generator
  std::mt19937_64 gen(rd());

  return gen();
}

bool hashesEqual(Crypto::Hash a, Crypto::Hash b)
{
  size_t aSize = sizeof(a.data) / sizeof(a.data[0]);
  size_t bSize = sizeof(b.data) / sizeof(b.data[0]);

  if (aSize != bSize)
  {
    return false;
  }

  for (size_t i = 0; i < aSize; i++)
  {
    if (a.data[i] != b.data[i])
    {
      return false;
    }
  }

  return true;
}

bool hashVectorsEqual(std::vector<Crypto::Hash> a, std::vector<Crypto::Hash> b)
{
  if (a.size() != b.size())
  {
    return false;
  }

  for (size_t i = 0; i < a.size(); ++i)
  {
    size_t sizeA = sizeof(a[i].data) / sizeof(a[i].data[0]);
    size_t sizeB = sizeof(b[i].data) / sizeof(b[i].data[0]);

    if (sizeA != sizeB)
    {
      return false;
    }

    for (size_t j = 0; j < sizeA; ++j)
    {
      if (a[i].data[j] != b[i].data[j])
      {
        return false;
      }
    }
  }

  return true;
}

bool publicKeysEqual(Crypto::PublicKey a, Crypto::PublicKey b)
{
  size_t aSize = sizeof(a.data) / sizeof(a.data[0]);
  size_t bSize = sizeof(b.data) / sizeof(b.data[0]);

  if (aSize != bSize)
  {
    return false;
  }

  for (size_t i = 0; i < aSize; i++)
  {
    if (a.data[i] != b.data[i])
    {
      return false;
    }
  }

  return true;
}

bool secretKeysEqual(Crypto::SecretKey a, Crypto::SecretKey b)
{
  size_t aSize = sizeof(a.data) / sizeof(a.data[0]);
  size_t bSize = sizeof(b.data) / sizeof(b.data[0]);

  if (aSize != bSize)
  {
    return false;
  }

  for (size_t i = 0; i < aSize; i++)
  {
    if (a.data[i] != b.data[i])
    {
      return false;
    }
  }

  return true;
}
