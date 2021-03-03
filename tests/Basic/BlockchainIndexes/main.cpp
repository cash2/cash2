// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/BlockchainIndexes.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include <iostream>
#include <stdlib.h>
#include <random>

using namespace CryptoNote;

/*
  My Notes:

  struct TransactionPrefix {
   uint8_t version;
   uint64_t unlockTime;
   std::vector<TransactionInput> inputs;
   std::vector<TransactionOutput> outputs;
   std::vector<uint8_t> extra;
  };

  struct Transaction : public TransactionPrefix {
   std::vector<std::vector<Crypto::Signature>> signatures;
  };

  struct TransactionOutput {
   uint64_t amount;
   TransactionOutputTarget target;
  };

  typedef boost::variant<BaseInput, KeyInput, MultisignatureInput> TransactionInput;

  struct BaseInput {
   uint32_t blockIndex;
  };

  struct KeyInput {
   uint64_t amount;
   std::vector<uint32_t> outputIndexes;
   Crypto::KeyImage keyImage;
  };

  struct MultisignatureInput {
   uint64_t amount;
   uint8_t signatureCount;
   uint32_t outputIndex;
  };

  typedef boost::variant<KeyOutput, MultisignatureOutput> TransactionOutputTarget;

  struct KeyOutput {
   Crypto::PublicKey key;
  };

  struct MultisignatureOutput {
   std::vector<Crypto::PublicKey> keys;
   uint8_t requiredSignatureCount;
  };

  struct Hash {
   uint8_t data[32];
  };

  struct Signature {
    uint8_t data[64];
  };

  struct BlockHeader {
    uint32_t nonce;
    uint64_t timestamp;
    Crypto::Hash previousBlockHash;
  };

  struct Block : public BlockHeader {
    Transaction baseTransaction;
    std::vector<Crypto::Hash> transactionHashes;
  };
*/

uint32_t loopCount = 100;

// PaymentIdIndex
// add()
TEST(blockchainIndexes_PaymentIdIndex, 1)
{
  PaymentIdIndex paymentIdIndex;

  for (int i = 0; i < loopCount; ++i)
  {
    Transaction transaction = getRandTransaction();
    ASSERT_TRUE(paymentIdIndex.add(transaction));
  }
}

// PaymentIdIndex
// find()
TEST(blockchainIndexes_PaymentIdIndex, 2)
{
  PaymentIdIndex paymentIdIndex;

  Transaction transaction = getRandTransaction();

  // add
  ASSERT_TRUE(paymentIdIndex.add(transaction));
  
  std::vector<uint8_t> transactionExtra = transaction.extra;

  // paymentId contains the last 32 values of transaction.extra
  Crypto::Hash paymentId;
  
  for (int i = 3; i < transactionExtra.size(); ++i)
  {
    paymentId.data[i - 3] = transactionExtra[i];
  }
  
  std::vector<Crypto::Hash> transactionHashes;

  // find
  ASSERT_TRUE(paymentIdIndex.find(paymentId, transactionHashes));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_EQ(transactionHashes[0], transactionHash);
}

// PaymentIdIndex
// remove()
TEST(blockchainIndexes_PaymentIdIndex, 3)
{
  PaymentIdIndex paymentIdIndex;

  Transaction transaction = getRandTransaction();

  // add
  ASSERT_TRUE(paymentIdIndex.add(transaction));
  
  std::vector<uint8_t> transactionExtra = transaction.extra;

  // paymentId contains the last 32 values of transaction.extra
  Crypto::Hash paymentId;
  
  for (int i = 3; i < transactionExtra.size(); ++i)
  {
    paymentId.data[i - 3] = transactionExtra[i];
  }
  
  std::vector<Crypto::Hash> transactionHashes;

  // find
  ASSERT_TRUE(paymentIdIndex.find(paymentId, transactionHashes));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_EQ(transactionHashes[0], transactionHash);

  // remove
  ASSERT_TRUE(paymentIdIndex.remove(transaction));

  // find
  ASSERT_FALSE(paymentIdIndex.find(paymentId, transactionHashes));
}

// PaymentIdIndex
// clear()
TEST(blockchainIndexes_PaymentIdIndex, 4)
{
  PaymentIdIndex paymentIdIndex;

  Transaction transaction = getRandTransaction();

  // add
  ASSERT_TRUE(paymentIdIndex.add(transaction));
  
  std::vector<uint8_t> transactionExtra = transaction.extra;

  // paymentId contains the last 32 values of transaction.extra
  Crypto::Hash paymentId;
  
  for (int i = 3; i < transactionExtra.size(); ++i)
  {
    paymentId.data[i - 3] = transactionExtra[i];
  }
  
  std::vector<Crypto::Hash> transactionHashes;

  // find
  ASSERT_TRUE(paymentIdIndex.find(paymentId, transactionHashes));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_EQ(transactionHashes[0], transactionHash);

  // clear
  paymentIdIndex.clear();

  // find
  ASSERT_FALSE(paymentIdIndex.find(paymentId, transactionHashes));
}

// TimestampBlocksIndex
// add()
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 1)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampBlocksIndex
// add()
// max timestamp
// hash of all zeros
TEST(blockchainIndexes_TimestampBlocksIndex, 2)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampBlocksIndex
// add()
// max timestamp
// hash of all 255
TEST(blockchainIndexes_TimestampBlocksIndex, 3)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampBlocksIndex
// add()
// timestamp equals 0
// hash of all zeros
TEST(blockchainIndexes_TimestampBlocksIndex, 4)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampBlocksIndex
// add()
// timestamp equals 0
// hash of all 255
TEST(blockchainIndexes_TimestampBlocksIndex, 5)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampBlocksIndex
// add()
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 6)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    // add loop is between 1 and loopCount - 1
    size_t addLoop = rand() % loopCount;

    if (addLoop == 0)
    {
      addLoop = 1;
    }

    for (int j = 0; j < addLoop; ++j)
    {
      ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addLoop;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addLoop);
    ASSERT_EQ(hashes.size(), addLoop);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampBlocksIndex
// add()
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 7)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    for (int j = 0; j <= i; ++j)
    {
      ASSERT_EQ(hashesOutput[j], hashesInput[j]);
    }
  }
}

// TimestampBlocksIndex
// add()
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 8)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashes.size(), i + 1);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampBlocksIndex
// add()
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 9)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }
}

// TimestampBlocksIndex
// add()
// timestamp collision
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 10)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  uint64_t timestamp = 100;

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = timestamp;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);
  ASSERT_EQ(hashes.size(), loopCount);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampBlocksIndex
// add()
// timestamp collision
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 11)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);
  ASSERT_EQ(hashes.size(), loopCount);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampBlocksIndex
// add()
// timestamp collision
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 12)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  size_t addCounter = 0;

  // random timestamp
  uint64_t timestamp = rand();
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // add
    for (int j = 0; j < rand() % 100; ++j)
    {
      ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashesOutput.size(), addCounter);
    
    for (int j = 0; j < addCounter; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }
}

// TimestampBlocksIndex
// add()
// timestamp collision
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 13)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  size_t addCounter = 0;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 1000; ++j)
    {
      ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashes.size(), addCounter);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampBlocksIndex
// add()
// timestamp collision
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 14)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  size_t addCounter = 0;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 100; ++j)
    {
      ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashesOutput.size(), addCounter);
    
    for (int j = 0; j < addCounter; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }
}

// TimestampBlocksIndex
// add()
// hash collision
// single constant timestamp
// single constant hash

TEST(blockchainIndexes_TimestampBlocksIndex, 15)
{
  // same test for timestamp collision
}

// TimestampBlocksIndex
// add()
// hash collision
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 16)
{
  // same test for timestamp collision
}

// TimestampBlocksIndex
// add()
// hash collision
// single random timestamp
// multiple random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 17)
{
  // same as for timestamp collision
}

// TimestampBlocksIndex
// add()
// hash collision
// multiple random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 18)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  size_t addCounter = 0;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 1000; ++j)
    {
      ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashes.size(), addCounter);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampBlocksIndex
// add()
// hash collision
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 19)
{
  // same test for timestamp collision
}

// TimestampBlocksIndex
// find()
// timestamp out of range
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 20)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 100;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  // timestamp is below range
  uint64_t timestampBegin = 200;
  uint64_t timestampEnd = 300;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);

  // timestamp is above range
  timestampBegin = 0;
  timestampEnd = 99;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);
}

// TimestampBlocksIndex
// find()
// timestamp out of range
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 21)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  // timestamp is between 1 and RAND_MAX - 1
  uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  // timestamp is below range
  uint64_t timestampBegin = timestamp + 1;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);

  // timestamp is above range
  timestampBegin = 0;
  timestampEnd = timestamp - 1;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);
}

// TimestampBlocksIndex
// find()
// timestamp out of range
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 22)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random timestamp
  // timestamp is between 1 and RAND_MAX - 1
  uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampBlocksIndex
// find()
// timestamp out of range
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 23)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    // random timestamp
    // timestamp is between 1 and RAND_MAX - 1
    uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampBlocksIndex
// find()
// timestamp out of range
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 24)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    // timestamp is between 1 and RAND_MAX - 1
    uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampBlocksIndex
// find()
// timestampEnd < timestampBegin
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 25)
{
  TimestampBlocksIndex timestampBlocksIndex;

  std::vector<Crypto::Hash> hashesInput;
  
  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  uint64_t timestamp = 100;

  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  // timestampBegin is greater than zero
  uint64_t timestampBegin = timestamp;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

}

// TimestampBlocksIndex
// find()
// timestampEnd < timestampBegin
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 26)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  // timestampBegin is between 1 and RAND_MAX
  uint64_t timestampBegin = rand() % RAND_MAX + 1;
  // timestampEnd is less than timestampBegin
  uint64_t timestampEnd = rand() % timestampBegin;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// find()
// timestampEnd < timestampBegin
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 27)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random timestamp
  uint64_t timestamp = rand();
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// timestampEnd < timestampBegin
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 28)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// timestampEnd < timestampBegin
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 29)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 30)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash1));

  // timestamp lies within timestamp begin and timestamp end
  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  // hashesNumberLimit is set below the number of matches to be found
  uint32_t hashesNumberLimit = 0;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 31)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 32)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 33)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 34)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit equals 0
// random timestamp random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 35)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 36)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  // hashesNumberLimit is between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % (loopCount - 1) + 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (auto h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 37)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // get a random hash
  for (int j = 0; j < hashSize; ++j)
  {
    hash.data[j] = rand() % 256;
  }

  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  // hashesNumberLimit is between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % (loopCount - 1) + 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 38)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);
    
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;

  // set hashesNumberLimit to be between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % loopCount;
  if (hashesNumberLimit == 0)
  {
    hashesNumberLimit = 1;
  }

  std::vector<Crypto::Hash> hashesOutput;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashesOutput.size(), hashesNumberLimit);

  for (int j = 0; j < hashesOutput.size(); ++j)
  {
    ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// multiple random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 39)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // get a random hash
  for (int j = 0; j < hashSize; ++j)
  {
    hash.data[j] = rand() % 256;
  }

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    uint64_t timestamp = rand();
    
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;

  // set hashesNumberLimit to be between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % loopCount;
  if (hashesNumberLimit == 0)
  {
    hashesNumberLimit = 1;
  }

  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (int j = 0; j < hashes.size(); ++j)
  {
    ASSERT_EQ(hashes[j], hash);
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 40)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;

    // hashesNumberLimit is between 1 and i - 1
    if (i > 0)
    {
      // get a number less than i
      int32_t temp = i - ((rand() % i) + 1);

      if (temp > 1)
      {
        hashesNumberLimit = temp;
      }
    }

    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), hashesNumberLimit);
  }
}

// TimestampBlocksIndex
// find()
// hashesNumberLimit > hashesNumberWithinTimestamps
TEST(blockchainIndexes_TimestampBlocksIndex, 41)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // i is the index inside the hashesInput vector
  // (i + 1) is the number of entries in the hashesInput vector
  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    // timestamp lies within timestamp begin and timestamp end
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = RAND_MAX / 2;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }
}

// TimestampBlocksIndex
// remove()
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampBlocksIndex, 42)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// remove()
// max timestamp
// hash of all zeros
TEST(blockchainIndexes_TimestampBlocksIndex, 43)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// remove()
// max timestamp
// hash of all 255
TEST(blockchainIndexes_TimestampBlocksIndex, 44)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// remove()
// timestamp equals zero
// hash of all zeros
TEST(blockchainIndexes_TimestampBlocksIndex, 45)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// remove()
// timestamp equals zero
// hash of all 255
TEST(blockchainIndexes_TimestampBlocksIndex, 46)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// remove()
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 47)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  // add loop is between 1 and loopCount - 1
  size_t addLoop = rand() % loopCount;

  if (addLoop == 0)
  {
    addLoop = 1;
  }

  for (int i = 0; i < addLoop; ++i)
  {
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = addLoop;
  std::vector<Crypto::Hash> hashes1;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes1, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, addLoop);

  ASSERT_EQ(hashes1.size(), addLoop);

  for (Crypto::Hash h : hashes1)
  {
    ASSERT_EQ(h, hash);
  }

  for (int i = 0; i < addLoop; ++i)
  {
    // remove
    // removes only 1 entry if there are duplicate entries
    ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hash));

    std::vector<Crypto::Hash> hashes2;

    // find
    if (i < addLoop - 1)
    {
      // duplicate entries still remain
      ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes2, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashes2.size(), addLoop - (i + 1));
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes2, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampBlocksIndex
// remove()
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 48)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    for (int j = 0; j <= i; ++j)
    {
      ASSERT_EQ(hashesOutput[j], hashesInput[j]);
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampBlocksIndex.remove(timestamp, hashesInput[i]));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashesOutput.size(), loopCount - (i + 1));

      ASSERT_EQ(std::find(hashesOutput.begin(), hashesOutput.end(), hashesInput[i]), hashesOutput.end());
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampBlocksIndex
// remove()
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampBlocksIndex, 49)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<uint64_t> timestamps;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    timestamps.push_back(timestamp);

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashes.size(), i + 1);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampBlocksIndex.remove(timestamps[i], hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashes.size(), loopCount - (i + 1));

      for (Crypto::Hash h : hashes)
      {
        ASSERT_EQ(h, hash);
      }
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampBlocksIndex
// remove()
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampBlocksIndex, 50)
{
  TimestampBlocksIndex timestampBlocksIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  std::vector<uint64_t> timestamps;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    timestamps.push_back(timestamp);

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashesOutput.size(), i + 1);
    
    for (int j = 0; j <= i; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampBlocksIndex.remove(timestamps[i], hashesInput[i]));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashesOutput.size(), loopCount - (i + 1));

      for (int j = 0; j < hashesOutput.size(); ++j)
      {
        ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
      }
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampBlocksIndex
// remove() fail
// no entries added
TEST(blockchainIndexes_TimestampBlocksIndex, 51)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_FALSE(timestampBlocksIndex.remove(timestamp, hash));
  }
}

// TimestampBlocksIndex
// remove() fail
// timestamp mismatch
TEST(blockchainIndexes_TimestampBlocksIndex, 52)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove
    uint64_t timestampRemove = rand();

    while (timestampRemove == timestamp)
    {
      timestampRemove = rand();
    }

    ASSERT_FALSE(timestampBlocksIndex.remove(timestampRemove, hash));
  }
}

// TimestampBlocksIndex
// remove() fail
// hash mismatch
TEST(blockchainIndexes_TimestampBlocksIndex, 53)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove
    Crypto::Hash hashRemove;

    for (int j = 0; j < hashSize; ++j)
    {
      hashRemove.data[j] = rand() % 256;
    }

    while (hashRemove.data == hash.data)
    {
      for (int j = 0; j < hashSize; ++j)
      {
        hashRemove.data[j] = rand() % 256;
      }
    }

    ASSERT_FALSE(timestampBlocksIndex.remove(timestamp, hashRemove));
  }
}

// TimestampBlocksIndex
// remove() fail
// timestamp mismatch and hash mismatch
TEST(blockchainIndexes_TimestampBlocksIndex, 54)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove

    // timestampRemove
    uint64_t timestampRemove = rand();

    while (timestampRemove == timestamp)
    {
      timestampRemove = rand();
    }

    // hashRemove
    Crypto::Hash hashRemove;

    for (int j = 0; j < hashSize; ++j)
    {
      hashRemove.data[j] = rand() % 256;
    }

    while (hashRemove.data == hash.data)
    {
      for (int j = 0; j < hashSize; ++j)
      {
        hashRemove.data[j] = rand() % 256;
      }
    }

    ASSERT_FALSE(timestampBlocksIndex.remove(timestampRemove, hashRemove));
  }
}

// TimestampBlocksIndex
// clear()
TEST(blockchainIndexes_TimestampBlocksIndex, 55)
{
  TimestampBlocksIndex timestampBlocksIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampBlocksIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }

  timestampBlocksIndex.clear();

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashesOutput;
  uint32_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
}

// TimestampBlocksIndex
// clear()
// no entries previously added
TEST(blockchainIndexes_TimestampBlocksIndex, 56)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampBlocksIndex timestampBlocksIndex;
    
    timestampBlocksIndex.clear();

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint32_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampBlocksIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// add()
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 1)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampTransactionsIndex
// add()
// max timestamp
// hash of all zeros
TEST(blockchainIndexes_TimestampTransactionsIndex, 2)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampTransactionsIndex
// add()
// max timestamp
// hash of all 255
TEST(blockchainIndexes_TimestampTransactionsIndex, 3)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampTransactionsIndex
// add()
// timestamp equals 0
// hash of all zeros
TEST(blockchainIndexes_TimestampTransactionsIndex, 4)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampTransactionsIndex
// add()
// timestamp equals 0
// hash of all 255
TEST(blockchainIndexes_TimestampTransactionsIndex, 5)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);
}

// TimestampTransactionsIndex
// add()
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 6)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    // add loop is between 1 and loopCount - 1
    size_t addLoop = rand() % loopCount;

    if (addLoop == 0)
    {
      addLoop = 1;
    }

    for (int j = 0; j < addLoop; ++j)
    {
      ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addLoop;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addLoop);
    ASSERT_EQ(hashes.size(), addLoop);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampTransactionsIndex
// add()
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 7)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    for (int j = 0; j <= i; ++j)
    {
      ASSERT_EQ(hashesOutput[j], hashesInput[j]);
    }
  }
}

// TimestampTransactionsIndex
// add()
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 8)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashes.size(), i + 1);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampTransactionsIndex
// add()
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 9)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }
}

// TimestampTransactionsIndex
// add()
// timestamp collision
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 10)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  uint64_t timestamp = 100;

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = timestamp;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);
  ASSERT_EQ(hashes.size(), loopCount);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampTransactionsIndex
// add()
// timestamp collision
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 11)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);
  ASSERT_EQ(hashes.size(), loopCount);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampTransactionsIndex
// add()
// timestamp collision
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 12)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  size_t addCounter = 0;

  // random timestamp
  uint64_t timestamp = rand();
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // add
    for (int j = 0; j < rand() % 100; ++j)
    {
      ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashesOutput.size(), addCounter);
    
    for (int j = 0; j < addCounter; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }
}

// TimestampTransactionsIndex
// add()
// timestamp collision
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 13)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  size_t addCounter = 0;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 1000; ++j)
    {
      ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashes.size(), addCounter);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampTransactionsIndex
// add()
// timestamp collision
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 14)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  size_t addCounter = 0;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 100; ++j)
    {
      ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashesOutput.size(), addCounter);
    
    for (int j = 0; j < addCounter; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }
}

// TimestampTransactionsIndex
// add()
// hash collision
// single constant timestamp
// single constant hash

TEST(blockchainIndexes_TimestampTransactionsIndex, 15)
{
  // same test for timestamp collision
}

// TimestampTransactionsIndex
// add()
// hash collision
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 16)
{
  // same test for timestamp collision
}

// TimestampTransactionsIndex
// add()
// hash collision
// single random timestamp
// multiple random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 17)
{
  // same as for timestamp collision
}

// TimestampTransactionsIndex
// add()
// hash collision
// multiple random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 18)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  size_t addCounter = 0;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    for (int j = 0; j < rand() % 1000; ++j)
    {
      ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

      ++addCounter;
    }

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = addCounter;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, addCounter);
    ASSERT_EQ(hashes.size(), addCounter);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }
}

// TimestampTransactionsIndex
// add()
// hash collision
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 19)
{
  // same test for timestamp collision
}

// TimestampTransactionsIndex
// find()
// timestamp out of range
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 20)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 100;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  // timestamp is below range
  uint64_t timestampBegin = 200;
  uint64_t timestampEnd = 300;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);

  // timestamp is above range
  timestampBegin = 0;
  timestampEnd = 99;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);
}

// TimestampTransactionsIndex
// find()
// timestamp out of range
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 21)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  // timestamp is between 1 and RAND_MAX - 1
  uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  // timestamp is below range
  uint64_t timestampBegin = timestamp + 1;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);

  // timestamp is above range
  timestampBegin = 0;
  timestampEnd = timestamp - 1;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 0);
  ASSERT_EQ(hashes.size(), 0);
}

// TimestampTransactionsIndex
// find()
// timestamp out of range
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 22)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random timestamp
  // timestamp is between 1 and RAND_MAX - 1
  uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampTransactionsIndex
// find()
// timestamp out of range
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 23)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    // random timestamp
    // timestamp is between 1 and RAND_MAX - 1
    uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampTransactionsIndex
// find()
// timestamp out of range
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 24)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    // timestamp is between 1 and RAND_MAX - 1
    uint64_t timestamp = rand() % (RAND_MAX - 1) + 1;

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestamp is below range
    uint64_t timestampBegin = timestamp + 1;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);

    // timestamp is above range
    timestampBegin = 0;
    timestampEnd = timestamp - 1;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 0);
    ASSERT_EQ(hashes.size(), 0);
  }
}

// TimestampTransactionsIndex
// find()
// timestampEnd < timestampBegin
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 25)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  std::vector<Crypto::Hash> hashesInput;
  
  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  uint64_t timestamp = 100;

  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  // timestampBegin is greater than zero
  uint64_t timestampBegin = timestamp;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

}

// TimestampTransactionsIndex
// find()
// timestampEnd < timestampBegin
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 26)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  // timestampBegin is between 1 and RAND_MAX
  uint64_t timestampBegin = rand() % RAND_MAX + 1;
  // timestampEnd is less than timestampBegin
  uint64_t timestampEnd = rand() % timestampBegin;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// find()
// timestampEnd < timestampBegin
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 27)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random timestamp
  uint64_t timestamp = rand();
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// timestampEnd < timestampBegin
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 28)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// timestampEnd < timestampBegin
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 29)
{
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    // timestampBegin is between 1 and RAND_MAX
    uint64_t timestampBegin = rand() % RAND_MAX + 1;
    // timestampEnd is less than timestampBegin
    uint64_t timestampEnd = rand() % timestampBegin;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 30)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash1));

  // timestamp lies within timestamp begin and timestamp end
  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  // hashesNumberLimit is set below the number of matches to be found
  uint32_t hashesNumberLimit = 0;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 31)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 32)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 33)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 34)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit equals 0
// random timestamp random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 35)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 0;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 36)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  // hashesNumberLimit is between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % (loopCount - 1) + 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (auto h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 37)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // get a random hash
  for (int j = 0; j < hashSize; ++j)
  {
    hash.data[j] = rand() % 256;
  }

  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  // hashesNumberLimit is between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % (loopCount - 1) + 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (Crypto::Hash h : hashes)
  {
    ASSERT_EQ(h, hash);
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 38)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  uint64_t timestamp = rand();

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);
    
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;

  // set hashesNumberLimit to be between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % loopCount;
  if (hashesNumberLimit == 0)
  {
    hashesNumberLimit = 1;
  }

  std::vector<Crypto::Hash> hashesOutput;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashesOutput.size(), hashesNumberLimit);

  for (int j = 0; j < hashesOutput.size(); ++j)
  {
    ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// multiple random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 39)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // get a random hash
  for (int j = 0; j < hashSize; ++j)
  {
    hash.data[j] = rand() % 256;
  }

  // add
  for (int i = 0; i < loopCount; ++i)
  {
    uint64_t timestamp = rand();
    
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;

  // set hashesNumberLimit to be between 1 and loopCount - 1
  uint32_t hashesNumberLimit = rand() % loopCount;
  if (hashesNumberLimit == 0)
  {
    hashesNumberLimit = 1;
  }

  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, loopCount);

  ASSERT_EQ(hashes.size(), hashesNumberLimit);

  for (int j = 0; j < hashes.size(); ++j)
  {
    ASSERT_EQ(hashes[j], hash);
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit < hashesNumberWithinTimestamps
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 40)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;

    // hashesNumberLimit is between 1 and i - 1
    if (i > 0)
    {
      // get a number less than i
      int32_t temp = i - ((rand() % i) + 1);

      if (temp > 1)
      {
        hashesNumberLimit = temp;
      }
    }

    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), hashesNumberLimit);
  }
}

// TimestampTransactionsIndex
// find()
// hashesNumberLimit > hashesNumberWithinTimestamps
TEST(blockchainIndexes_TimestampTransactionsIndex, 41)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // i is the index inside the hashesInput vector
  // (i + 1) is the number of entries in the hashesInput vector
  for (int i = 0; i < loopCount; ++i)
  {
    // get a random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    // timestamp lies within timestamp begin and timestamp end
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = RAND_MAX / 2;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }
}

// TimestampTransactionsIndex
// remove()
// single constant timestamp
// single constant hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 42)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint64_t timestamp = 1;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 2;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// remove()
// max timestamp
// hash of all zeros
TEST(blockchainIndexes_TimestampTransactionsIndex, 43)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// remove()
// max timestamp
// hash of all 255
TEST(blockchainIndexes_TimestampTransactionsIndex, 44)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = INTMAX_MAX;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = INTMAX_MAX;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// remove()
// timestamp equals zero
// hash of all zeros
TEST(blockchainIndexes_TimestampTransactionsIndex, 45)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// remove()
// timestamp equals zero
// hash of all 255
TEST(blockchainIndexes_TimestampTransactionsIndex, 46)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
  uint64_t timestamp = 0;

  // add
  ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = 0;
  uint32_t hashesNumberLimit = 1;
  std::vector<Crypto::Hash> hashes;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, 1);

  ASSERT_EQ(hashes.size(), 1);

  ASSERT_EQ(hashes[0], hash);

  // remove
  ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// remove()
// single random timestamp
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 47)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }

  // random timestamp
  uint64_t timestamp = rand();

  // add
  // add loop is between 1 and loopCount - 1
  size_t addLoop = rand() % loopCount;

  if (addLoop == 0)
  {
    addLoop = 1;
  }

  for (int i = 0; i < addLoop; ++i)
  {
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  }

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = addLoop;
  std::vector<Crypto::Hash> hashes1;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes1, hashesNumberWithinTimestamps));

  ASSERT_EQ(hashesNumberWithinTimestamps, addLoop);

  ASSERT_EQ(hashes1.size(), addLoop);

  for (Crypto::Hash h : hashes1)
  {
    ASSERT_EQ(h, hash);
  }

  for (int i = 0; i < addLoop; ++i)
  {
    // remove
    // removes only 1 entry if there are duplicate entries
    ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hash));

    std::vector<Crypto::Hash> hashes2;

    // find
    if (i < addLoop - 1)
    {
      // duplicate entries still remain
      ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes2, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashes2.size(), addLoop - (i + 1));
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes2, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampTransactionsIndex
// remove()
// single random timestamp
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 48)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  // random timestamp
  uint64_t timestamp = rand();

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    for (int j = 0; j <= i; ++j)
    {
      ASSERT_EQ(hashesOutput[j], hashesInput[j]);
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampTransactionsIndex.remove(timestamp, hashesInput[i]));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = timestamp;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashesOutput.size(), loopCount - (i + 1));

      ASSERT_EQ(std::find(hashesOutput.begin(), hashesOutput.end(), hashesInput[i]), hashesOutput.end());
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampTransactionsIndex
// remove()
// multiple random timestamps
// single random hash
TEST(blockchainIndexes_TimestampTransactionsIndex, 49)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<uint64_t> timestamps;

  // random hash
  for (int i = 0; i < hashSize; ++i)
  {
    hash.data[i] = rand() % 256;
  }
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random timestamp
    uint64_t timestamp = rand();

    timestamps.push_back(timestamp);

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashes.size(), i + 1);
    
    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampTransactionsIndex.remove(timestamps[i], hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashes.size(), loopCount - (i + 1));

      for (Crypto::Hash h : hashes)
      {
        ASSERT_EQ(h, hash);
      }
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampTransactionsIndex
// remove()
// multiple random timestamps
// multiple random hashes
TEST(blockchainIndexes_TimestampTransactionsIndex, 50)
{
  TimestampTransactionsIndex timestampTransactionsIndex;

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  std::vector<uint64_t> timestamps;
  
  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    timestamps.push_back(timestamp);

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = i + 1;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);
    ASSERT_EQ(hashesOutput.size(), i + 1);
    
    for (int j = 0; j <= i; ++j)
    {
      ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
    }
  }

  for (int i = 0; i < loopCount; ++i)
  {
    // remove
    ASSERT_TRUE(timestampTransactionsIndex.remove(timestamps[i], hashesInput[i]));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    if (i < loopCount - 1)
    {
      ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

      ASSERT_EQ(hashesNumberWithinTimestamps, loopCount - (i + 1));

      ASSERT_EQ(hashesOutput.size(), loopCount - (i + 1));

      for (int j = 0; j < hashesOutput.size(); ++j)
      {
        ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[j]), hashesInput.end());
      }
    }
    else
    {
      // all entries have been removed
      ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
    }
  }
}

// TimestampTransactionsIndex
// remove() fail
// no entries added
TEST(blockchainIndexes_TimestampTransactionsIndex, 51)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_FALSE(timestampTransactionsIndex.remove(timestamp, hash));
  }
}

// TimestampTransactionsIndex
// remove() fail
// timestamp mismatch
TEST(blockchainIndexes_TimestampTransactionsIndex, 52)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int i = 0; i < hashSize; ++i)
    {
      hash.data[i] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove
    uint64_t timestampRemove = rand();

    while (timestampRemove == timestamp)
    {
      timestampRemove = rand();
    }

    ASSERT_FALSE(timestampTransactionsIndex.remove(timestampRemove, hash));
  }
}

// TimestampTransactionsIndex
// remove() fail
// hash mismatch
TEST(blockchainIndexes_TimestampTransactionsIndex, 53)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove
    Crypto::Hash hashRemove;

    for (int j = 0; j < hashSize; ++j)
    {
      hashRemove.data[j] = rand() % 256;
    }

    while (hashRemove.data == hash.data)
    {
      for (int j = 0; j < hashSize; ++j)
      {
        hashRemove.data[j] = rand() % 256;
      }
    }

    ASSERT_FALSE(timestampTransactionsIndex.remove(timestamp, hashRemove));
  }
}

// TimestampTransactionsIndex
// remove() fail
// timestamp mismatch and hash mismatch
TEST(blockchainIndexes_TimestampTransactionsIndex, 54)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;

    Crypto::Hash hash;

    size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    // random timestamp
    uint64_t timestamp = rand();

    // add
    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hash));

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = 1;
    std::vector<Crypto::Hash> hashes;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashes, hashesNumberWithinTimestamps));

    ASSERT_EQ(hashesNumberWithinTimestamps, 1);

    ASSERT_EQ(hashes.size(), 1);

    for (Crypto::Hash h : hashes)
    {
      ASSERT_EQ(h, hash);
    }

    // remove

    // timestampRemove
    uint64_t timestampRemove = rand();

    while (timestampRemove == timestamp)
    {
      timestampRemove = rand();
    }

    // hashRemove
    Crypto::Hash hashRemove;

    for (int j = 0; j < hashSize; ++j)
    {
      hashRemove.data[j] = rand() % 256;
    }

    while (hashRemove.data == hash.data)
    {
      for (int j = 0; j < hashSize; ++j)
      {
        hashRemove.data[j] = rand() % 256;
      }
    }

    ASSERT_FALSE(timestampTransactionsIndex.remove(timestampRemove, hashRemove));
  }
}

// TimestampTransactionsIndex
// clear()
TEST(blockchainIndexes_TimestampTransactionsIndex, 55)
{
  TimestampTransactionsIndex timestampTransactionsIndex;
  
  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    // random hash
    for (int j = 0; j < hashSize; ++j)
    {
      hash.data[j] = rand() % 256;
    }

    hashesInput.push_back(hash);

    // random timestamp
    uint64_t timestamp = rand();

    ASSERT_TRUE(timestampTransactionsIndex.add(timestamp, hashesInput[i]));
  
    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_TRUE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));

    // (i + 1) is the number of entries in the hashesInput vector
    ASSERT_EQ(hashesNumberWithinTimestamps, i + 1);

    ASSERT_EQ(hashesOutput.size(), i + 1);

    // check that hashesInput and hashesOutput contain the same elements, order does not matter
    ASSERT_TRUE(std::is_permutation(hashesOutput.begin(), hashesOutput.end(), hashesInput.begin()));
  }

  timestampTransactionsIndex.clear();

  uint64_t timestampBegin = 0;
  uint64_t timestampEnd = RAND_MAX;
  uint32_t hashesNumberLimit = loopCount;
  std::vector<Crypto::Hash> hashesOutput;
  uint64_t hashesNumberWithinTimestamps;

  // find
  ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
}

// TimestampTransactionsIndex
// clear()
// no entries previously added
TEST(blockchainIndexes_TimestampTransactionsIndex, 56)
{
  for (int i = 0; i < loopCount; ++i)
  {
    TimestampTransactionsIndex timestampTransactionsIndex;
    
    timestampTransactionsIndex.clear();

    uint64_t timestampBegin = 0;
    uint64_t timestampEnd = RAND_MAX;
    uint32_t hashesNumberLimit = loopCount;
    std::vector<Crypto::Hash> hashesOutput;
    uint64_t hashesNumberWithinTimestamps;

    // find
    ASSERT_FALSE(timestampTransactionsIndex.find(timestampBegin, timestampEnd, hashesNumberLimit, hashesOutput, hashesNumberWithinTimestamps));
  }
}

// GeneratedTransactionsIndex
// add() success
TEST(blockchainIndexes_GeneratedTransactionsIndex, 1)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  ASSERT_TRUE(generatedTransactionsIndex.add(block));
}

// GeneratedTransactionsIndex
// add() multiple blocks success
TEST(blockchainIndexes_GeneratedTransactionsIndex, 2)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    ASSERT_TRUE(generatedTransactionsIndex.add(block));
  }
}

// GeneratedTransactionsIndex
// add()fail
// add empty block
TEST(blockchainIndexes_GeneratedTransactionsIndex, 3)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  Block block;

  ASSERT_ANY_THROW(generatedTransactionsIndex.add(block));
}

// GeneratedTransactionsIndex
// add() fail
// incorrect block height 1
TEST(blockchainIndexes_GeneratedTransactionsIndex, 4)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint32_t randNonZeroBlockHeight = getRandUint32_t();

  for (int i = 0; i < loopCount; ++i)
  {
    while (randNonZeroBlockHeight == 0)
    {
      randNonZeroBlockHeight = getRandUint32_t();
    }

    Block block = getRandBlockAtHeight(randNonZeroBlockHeight);

    ASSERT_FALSE(generatedTransactionsIndex.add(block));
  }
}

// GeneratedTransactionsIndex
// add() fail
// incorrect block height 2
TEST(blockchainIndexes_GeneratedTransactionsIndex, 5)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  // uint32_t randBlockHeight1 = getRandUint32_t(); // this takes too long
  uint32_t randBlockHeight1 = rand() % 100;

  for (uint32_t blockHeight = 0; blockHeight < randBlockHeight1; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    ASSERT_TRUE(generatedTransactionsIndex.add(block));
  }

  uint32_t randBlockHeight2 = getRandUint32_t();

  for (int i = 0; i < loopCount; ++i)
  {
    while (randBlockHeight2 == randBlockHeight1)
    {
      randBlockHeight2 = getRandUint32_t();
    }

    Block block = getRandBlockAtHeight(randBlockHeight2);

    ASSERT_FALSE(generatedTransactionsIndex.add(block));
  }
}

// GeneratedTransactionsIndex
// find() success 1
TEST(blockchainIndexes_GeneratedTransactionsIndex, 6)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  uint64_t generatedTransactionsIn = block.transactionHashes.size(); 

  ASSERT_TRUE(generatedTransactionsIndex.add(block));

  uint64_t generatedTransactionsOut;

  ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactionsOut));

  // add 1 for miner's coinbase transaction
  ASSERT_EQ(generatedTransactionsOut, generatedTransactionsIn + 1);
}

// GeneratedTransactionsIndex
// find() success 2
TEST(blockchainIndexes_GeneratedTransactionsIndex, 7)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint64_t generatedTransactionsIn = 0;

  uint32_t minersTransactionCount = 0;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    generatedTransactionsIn += block.transactionHashes.size(); 

    ASSERT_TRUE(generatedTransactionsIndex.add(block));

    ++minersTransactionCount;

    uint64_t generatedTransactionsOut;

    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactionsOut));

    ASSERT_EQ(generatedTransactionsOut, generatedTransactionsIn + minersTransactionCount);
  }
}

// GeneratedTransactionsIndex
// find() fail
// block height mismatch 1
TEST(blockchainIndexes_GeneratedTransactionsIndex, 8)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  ASSERT_TRUE(generatedTransactionsIndex.add(block));

  uint32_t randBlockHeight = getRandUint32_t();

  while (randBlockHeight == blockHeight)
  {
    randBlockHeight = getRandUint32_t();
  }

  uint64_t generatedTransactions;

  ASSERT_FALSE(generatedTransactionsIndex.find(randBlockHeight, generatedTransactions));
}

// GeneratedTransactionsIndex
// find() fail
// block height mismatch 2
TEST(blockchainIndexes_GeneratedTransactionsIndex, 9)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    ASSERT_TRUE(generatedTransactionsIndex.add(block));
  }

  uint32_t randBlockHeight = getRandUint32_t();
  
  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    while (randBlockHeight < loopCount)
    {
      randBlockHeight = getRandUint32_t();
    }

    uint64_t generatedTransactionsOut;

    ASSERT_FALSE(generatedTransactionsIndex.find(randBlockHeight, generatedTransactionsOut));
  }
}

// GeneratedTransactionsIndex
// remove() success
TEST(blockchainIndexes_GeneratedTransactionsIndex, 10)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;
  
  for(int i = 0; i < loopCount; ++i)
  {
    uint32_t blockHeight = 0;

    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(generatedTransactionsIndex.add(block));

    uint64_t generatedTransactions;

    // find
    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));

    // remove
    generatedTransactionsIndex.remove(block);

    // find
    ASSERT_FALSE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));
  }
}

// GeneratedTransactionsIndex
// remove() success
TEST(blockchainIndexes_GeneratedTransactionsIndex, 11)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  std::vector<Block> blocks;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    blocks.push_back(block);

    // add
    ASSERT_TRUE(generatedTransactionsIndex.add(block));

    uint64_t generatedTransactionsOut;

    // find
    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactionsOut));
  }

  uint64_t generatedTransactions;

  for (int32_t blockHeight = loopCount - 1; blockHeight >= 0; --blockHeight)
  {
    // remove
    ASSERT_TRUE(generatedTransactionsIndex.remove(blocks[blockHeight]));

    // find
    ASSERT_FALSE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));
  }
}

// GeneratedTransactionsIndex
// remove() fail
// remove empty block
TEST(blockchainIndexes_GeneratedTransactionsIndex, 12)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(generatedTransactionsIndex.add(block));

    uint64_t generatedTransactionsOut;

    // find
    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactionsOut));
  }

  uint64_t generatedTransactions;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block;

    // remove
    ASSERT_ANY_THROW(generatedTransactionsIndex.remove(block));

    // find
    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));
  }
}

// GeneratedTransactionsIndex
// clear()
TEST(blockchainIndexes_GeneratedTransactionsIndex, 13)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  // add
  ASSERT_TRUE(generatedTransactionsIndex.add(block));

  uint64_t generatedTransactions;

  // find
  ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));

  // clear
  generatedTransactionsIndex.clear();

  // find
  ASSERT_FALSE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));
}

// GeneratedTransactionsIndex
// clear()
TEST(blockchainIndexes_GeneratedTransactionsIndex, 14)
{
  GeneratedTransactionsIndex generatedTransactionsIndex;

  uint64_t generatedTransactionsIn = 0;

  uint32_t minersTransactionCount = 0;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    generatedTransactionsIn += block.transactionHashes.size(); 

    // add
    ASSERT_TRUE(generatedTransactionsIndex.add(block));

    ++minersTransactionCount;

    uint64_t generatedTransactionsOut;

    // find
    ASSERT_TRUE(generatedTransactionsIndex.find(blockHeight, generatedTransactionsOut));
  }

  generatedTransactionsIndex.clear();

  uint64_t generatedTransactions;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    // find
    ASSERT_FALSE(generatedTransactionsIndex.find(blockHeight, generatedTransactions));
  }
}

// OrphanBlocksIndex
// add() success
TEST(blockchainIndexes_OrphanBlocksIndex, 1)
{
  OrphanBlocksIndex orphanBlocksIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  // add
  ASSERT_TRUE(orphanBlocksIndex.add(block));

  // check that block hash is not all zeros (error with get_block_hash())
  Crypto::Hash blockHash = get_block_hash(block);
  uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
  ASSERT_NE(blockHash.data, zeroBlockHash);
}

// OrphanBlocksIndex
// add() multiple blocks in succession success
TEST(blockchainIndexes_OrphanBlocksIndex, 2)
{
  OrphanBlocksIndex orphanBlocksIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(orphanBlocksIndex.add(block));

    // check that block hash is not all zeros (error with get_block_hash())
    Crypto::Hash blockHash = get_block_hash(block);
    uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ASSERT_NE(blockHash.data, zeroBlockHash);
  }
}

// OrphanBlocksIndex
// add() same block multiple times success
TEST(blockchainIndexes_OrphanBlocksIndex, 3)
{
  OrphanBlocksIndex orphanBlocksIndex;

  uint32_t blockHeight = getRandUint32_t();

  for (int i = 0; i < loopCount; ++i)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    ASSERT_TRUE(orphanBlocksIndex.add(block));

    // check that block hash is not all zeros (error with get_block_hash())
    Crypto::Hash blockHash = get_block_hash(block);
    uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ASSERT_NE(blockHash.data, zeroBlockHash);
  }
}

// OrphanBlocksIndex
// find() success
TEST(blockchainIndexes_OrphanBlocksIndex, 4)
{
  OrphanBlocksIndex orphanBlocksIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  // add
  ASSERT_TRUE(orphanBlocksIndex.add(block));

  std::vector<Crypto::Hash> blockHashes;

  // find
  ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

  Crypto::Hash blockHash = get_block_hash(block);

  ASSERT_EQ(blockHashes[0], blockHash);

  // check that block hash is not all zeros (error with get_block_hash())
  uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
  ASSERT_NE(blockHash.data, zeroBlockHash);
}

// OrphanBlocksIndex
// find() multiple blocks success
TEST(blockchainIndexes_OrphanBlocksIndex, 5)
{
  OrphanBlocksIndex orphanBlocksIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(orphanBlocksIndex.add(block));

    std::vector<Crypto::Hash> blockHashes;

    // find
    ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

    Crypto::Hash blockHash = get_block_hash(block);

    ASSERT_EQ(blockHashes[0], blockHash);

    // check that block hash is not all zeros (error with get_block_hash())
    uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ASSERT_NE(blockHash.data, zeroBlockHash);
  }
}

// OrphanBlocksIndex
// remove() success
TEST(blockchainIndexes_OrphanBlocksIndex, 6)
{
  OrphanBlocksIndex orphanBlocksIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  // add
  ASSERT_TRUE(orphanBlocksIndex.add(block));

  // find
  std::vector<Crypto::Hash> blockHashes;
  ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

  Crypto::Hash blockHash = get_block_hash(block);
  ASSERT_EQ(blockHashes[0], blockHash);

  // check that block hash is not all zeros (error with get_block_hash())
  uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
  ASSERT_NE(blockHash.data, zeroBlockHash);

  // remove
  ASSERT_TRUE(orphanBlocksIndex.remove(block));

  // find
  blockHashes.clear();
  ASSERT_FALSE(orphanBlocksIndex.find(blockHeight, blockHashes));
}

// OrphanBlocksIndex
// remove() multiple blocks success
TEST(blockchainIndexes_OrphanBlocksIndex, 7)
{
  OrphanBlocksIndex orphanBlocksIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(orphanBlocksIndex.add(block));

    // find
    std::vector<Crypto::Hash> blockHashes;
    ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

    Crypto::Hash blockHash = get_block_hash(block);
    ASSERT_EQ(blockHashes[0], blockHash);

    // check that block hash is not all zeros (error with get_block_hash())
    uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ASSERT_NE(blockHash.data, zeroBlockHash);

    // remove
    ASSERT_TRUE(orphanBlocksIndex.remove(block));

    // find
    blockHashes.clear();
    ASSERT_FALSE(orphanBlocksIndex.find(blockHeight, blockHashes));
  }
}

// OrphanBlocksIndex
// clear() success
TEST(blockchainIndexes_OrphanBlocksIndex, 8)
{
  OrphanBlocksIndex orphanBlocksIndex;

  uint32_t blockHeight = 0;

  Block block = getRandBlockAtHeight(blockHeight);

  // add
  ASSERT_TRUE(orphanBlocksIndex.add(block));

  // find
  std::vector<Crypto::Hash> blockHashes;
  ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

  Crypto::Hash blockHash = get_block_hash(block);
  ASSERT_EQ(blockHashes[0], blockHash);

  // check that block hash is not all zeros (error with get_block_hash())
  uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
  ASSERT_NE(blockHash.data, zeroBlockHash);

  // clear
  orphanBlocksIndex.clear();

  // find
  blockHashes.clear();
  ASSERT_FALSE(orphanBlocksIndex.find(blockHeight, blockHashes));
}

// OrphanBlocksIndex
// clear() multiple blocks success
TEST(blockchainIndexes_OrphanBlocksIndex, 9)
{
  OrphanBlocksIndex orphanBlocksIndex;

  for (uint32_t blockHeight = 0; blockHeight < loopCount; ++blockHeight)
  {
    Block block = getRandBlockAtHeight(blockHeight);

    // add
    ASSERT_TRUE(orphanBlocksIndex.add(block));

    // find
    std::vector<Crypto::Hash> blockHashes;
    ASSERT_TRUE(orphanBlocksIndex.find(blockHeight, blockHashes));

    Crypto::Hash blockHash = get_block_hash(block);
    ASSERT_EQ(blockHashes[0], blockHash);

    // check that block hash is not all zeros (error with get_block_hash())
    uint8_t zeroBlockHash[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ASSERT_NE(blockHash.data, zeroBlockHash);

    // clear
    orphanBlocksIndex.clear();

    // find
    blockHashes.clear();
    ASSERT_FALSE(orphanBlocksIndex.find(blockHeight, blockHashes));
  }
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}