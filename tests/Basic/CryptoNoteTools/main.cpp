// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

getBinaryArrayHash()
getBinaryArrayHash()
toBinaryArray()
toBinaryArray()
toBinaryArray()
fromBinaryArray()
getObjectBinarySize()
getObjectBinarySize()
getObjectHash()
getObjectHash()
getObjectHash()
getInputAmount()
getInputsAmounts()
getOutputAmount()
decomposeAmount()

using BinaryArray = std::vector<uint8_t>;

struct MultisignatureInput {
  uint64_t amount;
  uint8_t signatureCount;
  uint32_t outputIndex;
};

typedef boost::variant<KeyOutput, MultisignatureOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  TransactionOutputTarget target;
};

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

// toBinaryArray(const T& object, BinaryArray& binaryArray)
TEST(CryptoNoteTools, 1)
{
  Block block = getRandBlock();

  BinaryArray binaryArray;

//  binaryArray = vector of length 10713 capacity 19506
//    {
//      0x1, 0x2, 0xde, 0xac, 0xe3, 0xc4, 0xfc, 0xb9, 0x87, 0xe4, 
//      0x55, 0x13, 0xd5, 0xaa, 0x0, 0xd0, 0x3d, 0x84, 0x41, 0x40,
//      0xc, 0xac, 0x3e, 0xd4, 0x8d, 0xcd, 0xef, 0x63, 0x3a, 0x51,
//      0xf7, 0xa5, 0xc0, 0xb5, 0xe6, 0x67, 0x87, 0x85, 0x35, 0xbd,
//      0x8c, 0x1e, 0xfd, 0x14, 0xc7, 0xd8, 0x32, 0x1, 0xa7, 0xc5,
//      0xbe, 0x93, 0x97, 0xbf, 0xc9, 0xd1, 0x30, 0x42, 0xff, 0xfc,
//      0x8c, 0xfa, 0x94, 0x1, 0x2, 0x90, 0xd7, 0xb8, 0xa0, 0x94,
//      0x94, 0xf8, 0xd4, 0xe8, 0x1, 0x1, 0xef, 0xd5, 0xef, 0xa9,
//      0xd, 0xcf, 0x1e, 0x95, 0xc, 0x34, 0x5e, 0xc5, 0xca, 0xf7,
//      0x3b, 0x3d, 0x74, 0x9, 0xdf, 0xa5, 0x6b, 0x84, 0x28, 0xa7, 
//      0xeb, 0xec, 0xb2, 0xf6, 0x8e, 0x97, 0xd9, 0xaf, 0xf, 0xf1,
//      0x50, 0x65, 0xb9, 0x2, 0xdb, 0x85, 0xd2, 0x9c, 0xcf, 0xbc,
//      0x9b, 0xf0, 0xc7, 0x1, 0x1, 0xd1, 0xe5, 0x94, 0xd3, 0x4,
//      0x8f, 0xe7, 0x90, 0xcc, 0xcf, 0xf4, 0xb6, 0x8e, 0xaa, 0x91,
//      0xf1, 0xea, 0xcf, 0xc4, 0xd4, 0xcc, 0x1e, 0xd1, 0xb5, 0xc6,
//      0x97, 0x43, 0x90, 0xc2, 0xfd, 0xaf, 0xdf, 0xce, 0xe, 0xd6,
//      0xdd, 0xa0, 0x2, 0xed, 0xb4, 0xf6, 0xed, 0xe3, 0xa0, 0x86,
//      0xfe, 0x8d, 0x1, 0x1, 0x8f, 0x91, 0xe1, 0xff, 0x1, 0xae,
//      0xd3, 0x6c, 0x87, 0x42, 0x7, 0xda, 0x76, 0x46, 0xbf, 0x6a, 
//      0xb7, 0xed, 0xa9, 0x22, 0x3d, 0x19, 0x34, 0xa, 0xb5, 0x80...
//    }

  ASSERT_TRUE(toBinaryArray(block, binaryArray));
}

// toBinaryArray(const T& object)
TEST(CryptoNoteTools, 2)
{
  Block block = getRandBlock();

  BinaryArray binaryArray1;

  ASSERT_TRUE(toBinaryArray(block, binaryArray1));

  BinaryArray binaryArray2 = toBinaryArray(block);

  ASSERT_EQ(binaryArray1, binaryArray2);
}

// toBinaryArray(const BinaryArray& object, BinaryArray& binaryArray)
TEST(CryptoNoteTools, 3)
{
  Block block = getRandBlock();

  BinaryArray binaryArray1;

//  binaryArray1 = vector of length 13144 capacity 20590
//    {
//      0x1, 0x92, 0x1, 0xde, 0xaa, 0xdd, 0xba, 0x93, 0xce, 0xef, 
//      0xeb, 0xe9, 0x1, 0x42, 0x81, 0x16, 0xe, 0x90, 0x8f, 0x2,
//      0x4d, 0x58, 0xdb, 0xde, 0xba, 0x72, 0xbd, 0x1b, 0x4f, 0x99,
//      0x77, 0x75, 0xd, 0x38, 0x35, 0x66, 0x85, 0xd5, 0x84, 0xd,
//      0xe, 0x29, 0xe5, 0xf0, 0x40, 0xa7, 0xa6, 0xdd, 0x78, 0x1,
//      0xc2, 0xa0, 0xe4, 0xdc, 0x96, 0xa0, 0xba, 0xe7, 0x78, 0x6e,
//      0xff, 0xfe, 0xd6, 0x81, 0x9b, 0x2, 0x2, 0xf5, 0xd6, 0xf0,
//      0xf4, 0xba, 0xb9, 0xdf, 0xb2, 0x50, 0x1, 0xa7, 0xb7, 0x90,
//      0xa7, 0x2, 0xf4, 0x54, 0x18, 0xd5, 0x6b, 0xf0, 0xc0, 0x9e,
//      0xfe, 0xb6, 0x6e, 0xf7, 0x4e, 0x26, 0x35, 0x4e, 0x51, 0xe1, 
//      0x61, 0x56, 0x8b, 0xa, 0xc2, 0xd9, 0x5c, 0x64, 0xe6, 0xe2,
//      0x9a, 0xb2, 0x31, 0x8, 0x2, 0x9c, 0xea, 0xd3, 0x8d, 0x82,
//      0xf2, 0xe8, 0x87, 0xda, 0x1, 0x1, 0xc8, 0x95, 0xd1, 0xd7,
//      0xb, 0x2f, 0xc7, 0x3a, 0x5d, 0xc2, 0xaf, 0x50, 0x8b, 0xe2,
//      0xc2, 0xbe, 0xa6, 0xfd, 0xb0, 0x37, 0xed, 0x2b, 0x49, 0x62,
//      0x5c, 0x5d, 0xb, 0x7e, 0x5d, 0xda, 0xfa, 0x30, 0x77, 0x64,
//      0xdf, 0x4a, 0xd3, 0x2, 0xfa, 0xc3, 0x9b, 0xe6, 0x8a, 0xca,
//      0xe4, 0xec, 0x95, 0x1, 0x1, 0xad, 0xbc, 0xe2, 0xb, 0x62,
//      0x74, 0x45, 0xd8, 0xd9, 0xe2, 0x26, 0x8f, 0x97, 0xfc, 0xa3, 
//      0x6c, 0x47, 0xf2, 0xe5, 0xd8, 0x3c, 0x77, 0xf2, 0x87, 0x3e...
//    }

  ASSERT_TRUE(toBinaryArray(block, binaryArray1));

  BinaryArray binaryArray2;

// binaryArray2 is the same as binaryArray1 but with 2 or 3 new entries added to the front

//  binaryArray2 = vector of length 13146 capacity 13146
//    {
//      0xd8, 0x66, 0x1, 0x92, 0x1, 0xde, 0xaa, 0xdd, 0xba, 0x93, 
//      0xce, 0xef, 0xeb, 0xe9, 0x1, 0x42, 0x81, 0x16, 0xe, 0x90,
//      0x8f, 0x2, 0x4d, 0x58, 0xdb, 0xde, 0xba, 0x72, 0xbd, 0x1b,
//      0x4f, 0x99, 0x77, 0x75, 0xd, 0x38, 0x35, 0x66, 0x85, 0xd5,
//      0x84, 0xd, 0xe, 0x29, 0xe5, 0xf0, 0x40, 0xa7, 0xa6, 0xdd,
//      0x78, 0x1, 0xc2, 0xa0, 0xe4, 0xdc, 0x96, 0xa0, 0xba, 0xe7,
//      0x78, 0x6e, 0xff, 0xfe, 0xd6, 0x81, 0x9b, 0x2, 0x2, 0xf5,
//      0xd6, 0xf0, 0xf4, 0xba, 0xb9, 0xdf, 0xb2, 0x50, 0x1, 0xa7,
//      0xb7, 0x90, 0xa7, 0x2, 0xf4, 0x54, 0x18, 0xd5, 0x6b, 0xf0,
//      0xc0, 0x9e, 0xfe, 0xb6, 0x6e, 0xf7, 0x4e, 0x26, 0x35, 0x4e, 
//      0x51, 0xe1, 0x61, 0x56, 0x8b, 0xa, 0xc2, 0xd9, 0x5c, 0x64,
//      0xe6, 0xe2, 0x9a, 0xb2, 0x31, 0x8, 0x2, 0x9c, 0xea, 0xd3,
//      0x8d, 0x82, 0xf2, 0xe8, 0x87, 0xda, 0x1, 0x1, 0xc8, 0x95,
//      0xd1, 0xd7, 0xb, 0x2f, 0xc7, 0x3a, 0x5d, 0xc2, 0xaf, 0x50,
//      0x8b, 0xe2, 0xc2, 0xbe, 0xa6, 0xfd, 0xb0, 0x37, 0xed, 0x2b,
//      0x49, 0x62, 0x5c, 0x5d, 0xb, 0x7e, 0x5d, 0xda, 0xfa, 0x30,
//      0x77, 0x64, 0xdf, 0x4a, 0xd3, 0x2, 0xfa, 0xc3, 0x9b, 0xe6,
//      0x8a, 0xca, 0xe4, 0xec, 0x95, 0x1, 0x1, 0xad, 0xbc, 0xe2,
//      0xb, 0x62, 0x74, 0x45, 0xd8, 0xd9, 0xe2, 0x26, 0x8f, 0x97, 
//      0xfc, 0xa3, 0x6c, 0x47, 0xf2, 0xe5, 0xd8, 0x3c, 0x77, 0xf2...
//    }

  ASSERT_TRUE(toBinaryArray(binaryArray1, binaryArray2));

  // sizeDiff is equal to 2 or 3
  size_t sizeDiff = binaryArray2.size() - binaryArray1.size();

  ASSERT_TRUE(std::equal(binaryArray2.begin() + sizeDiff, binaryArray2.end(), binaryArray1.begin()));
}

// fromBinaryArray
TEST(CryptoNoteTools, 4)
{
  Block block;

  // nonce
  block.nonce = 2222222222;

  // timestamp
  block.timestamp = 5555555555;

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

  BinaryArray binaryArray;

  ASSERT_TRUE(toBinaryArray(block, binaryArray));

  Block blockOutput;

  ASSERT_TRUE(fromBinaryArray(blockOutput, binaryArray));

  ASSERT_EQ(blockOutput.nonce, 2222222222);
  ASSERT_EQ(blockOutput.timestamp, 5555555555); 
}

// getObjectBinarySize()
TEST(CryptoNoteTools, 5)
{
  Block block = getRandBlock();

  BinaryArray binaryArray;

  ASSERT_TRUE(toBinaryArray(block, binaryArray));

  size_t size1;

  ASSERT_TRUE(getObjectBinarySize(block, size1));

  ASSERT_EQ(size1, binaryArray.size());

  size_t size2 = getObjectBinarySize(block);

  ASSERT_EQ(size1, size2);
}

// getBinaryArrayHash()
TEST(CryptoNoteTools, 6)
{
  Block block = getRandBlock();
  BinaryArray binaryArray;
  toBinaryArray(block, binaryArray);

  Crypto::Hash hash;

  getBinaryArrayHash(binaryArray, hash);

  ASSERT_EQ(sizeof(hash.data)/sizeof(hash.data[0]), 32);
}

// getInputAmount()
// KeyInput
TEST(CryptoNoteTools, 7)
{
  Transaction transaction;
  
  for (uint8_t i = 0; i < 100; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = 10;

    transaction.inputs.push_back(keyInput);
  }

  uint64_t totalAmount = getInputAmount(transaction);

  ASSERT_EQ(totalAmount, 1000);
}

// getInputAmount()
// MultisignatureInput
TEST(CryptoNoteTools, 8)
{
  Transaction transaction;
  
  for (uint8_t i = 0; i < 100; ++i)
  {
    MultisignatureInput multisignatureInput;
    multisignatureInput.amount = 10;

    transaction.inputs.push_back(multisignatureInput);
  }

  uint64_t totalAmount = getInputAmount(transaction);

  ASSERT_EQ(totalAmount, 1000);
}

// getInputAmounts()
// KeyInput
TEST(CryptoNoteTools, 9)
{
  Transaction transaction;

  std::vector<uint64_t> amountsIn;
  
  for (uint8_t i = 1; i < 10; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = i;

    amountsIn.push_back(i);

    transaction.inputs.push_back(keyInput);
  }

  std::vector<uint64_t> amountsOut = getInputsAmounts(transaction);

  ASSERT_TRUE(std::equal(amountsOut.begin(), amountsOut.end(), amountsIn.begin()));
}

// getInputAmounts()
// MultisignatureInput
TEST(CryptoNoteTools, 10)
{
  Transaction transaction;

  std::vector<uint64_t> amountsIn;
  
  for (uint8_t i = 1; i < 10; ++i)
  {
    MultisignatureInput multisignatureInput;
    multisignatureInput.amount = i;

    amountsIn.push_back(i);

    transaction.inputs.push_back(multisignatureInput);
  }

  std::vector<uint64_t> amountsOut = getInputsAmounts(transaction);

  ASSERT_TRUE(std::equal(amountsOut.begin(), amountsOut.end(), amountsIn.begin()));
}

// getOutputAmount()
TEST(CryptoNoteTools, 11)
{
  Transaction transaction;

  TransactionOutput transactionOutput;

  transactionOutput.amount = 100;

  transaction.outputs.push_back(transactionOutput);

  uint64_t amountOut = getOutputAmount(transaction);

  ASSERT_EQ(amountOut, 100);
}

// getOutputAmount()
TEST(CryptoNoteTools, 12)
{
  Transaction transaction;

  for (int i = 0; i < 100; i++)
  {
    TransactionOutput transactionOutput;

    transactionOutput.amount = 10;

    transaction.outputs.push_back(transactionOutput);
  }

  uint64_t amountOut = getOutputAmount(transaction);

  ASSERT_EQ(amountOut, 1000);
}

// decomposeAmount
TEST(CryptoNoteTools, 13)
{
  uint64_t amount = 123456789;
  uint64_t dustThreshold = 10;
  std::vector<uint64_t> decomposedAmounts;

  decomposeAmount(amount, dustThreshold, decomposedAmounts);

  // first entry is the change
  std::vector<uint64_t> expectedAmounts = {9, 80, 700, 6000, 50000, 400000, 3000000, 20000000, 100000000};

  ASSERT_TRUE(std::equal(decomposedAmounts.begin(), decomposedAmounts.end(), expectedAmounts.begin()));
}

// decomposeAmount
TEST(CryptoNoteTools, 14)
{
  uint64_t amount = 123456789;
  uint64_t dustThreshold = 100;
  std::vector<uint64_t> decomposedAmounts;

  decomposeAmount(amount, dustThreshold, decomposedAmounts);

  // first entry is the change
  std::vector<uint64_t> expectedAmounts = {89, 700, 6000, 50000, 400000, 3000000, 20000000, 100000000};

  ASSERT_TRUE(std::equal(decomposedAmounts.begin(), decomposedAmounts.end(), expectedAmounts.begin()));
}

// decomposeAmount
TEST(CryptoNoteTools, 15)
{
  uint64_t amount = 123456789;
  uint64_t dustThreshold = 1000;
  std::vector<uint64_t> decomposedAmounts;

  decomposeAmount(amount, dustThreshold, decomposedAmounts);

  // first entry is the change
  std::vector<uint64_t> expectedAmounts = {789, 6000, 50000, 400000, 3000000, 20000000, 100000000};

  ASSERT_TRUE(std::equal(decomposedAmounts.begin(), decomposedAmounts.end(), expectedAmounts.begin()));
}

// getObjectHash()
TEST(CryptoNoteTools, 16)
{
  Block block = getRandBlock();

  Crypto::Hash hash1;

  ASSERT_TRUE(getObjectHash(block, hash1));

  Crypto::Hash hash2;

  size_t size;

  ASSERT_TRUE(getObjectHash(block, hash2, size));

  Crypto::Hash hash3 = getObjectHash(block);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
  ASSERT_TRUE(hashesEqual(hash1, hash3));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}