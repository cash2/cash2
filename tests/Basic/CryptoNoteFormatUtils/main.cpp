// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteConfig.h"
#include <Logging/LoggerGroup.h>
#include <random>
#include <string>

using namespace CryptoNote;

/*

My Notes

parseAndValidateTransactionFromBinaryArray()

constructTransaction()
is_out_to_acc()
is_out_to_acc()
lookup_acc_outs()
lookup_acc_outs()
get_tx_fee()
get_tx_fee()
generate_key_image_helper()
short_hash_str()

get_block_hashing_blob()
get_aux_block_header_hash()
get_block_hash()
get_block_hash()
get_block_longhash()
get_inputs_money_amount()
get_outs_money_amount()
check_inputs_types_supported()
check_outs_valid()
checkMultisignatureInputsDiff()

check_money_overflow()
check_outs_overflow()
check_inputs_overflow()
get_block_height()
relative_output_offsets_to_absolute()
absolute_output_offsets_to_relative()

decompose_amount_into_digits()

get_tx_tree_hash()
get_tx_tree_hash()
get_tx_tree_hash()

//////////////////////////////////////////////////////////////////////////

struct MultisignatureOutput {
  std::vector<Crypto::PublicKey> keys;
  uint8_t requiredSignatureCount;
};

struct MultisignatureInput {
  uint64_t amount;
  uint8_t signatureCount;
  uint32_t outputIndex;
};

struct KeyDerivation {
  uint8_t data[32];
};

struct AccountKeys {
  AccountPublicAddress address;
  Crypto::SecretKey spendSecretKey;
  Crypto::SecretKey viewSecretKey;
};

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

struct KeyOutput {
  Crypto::PublicKey key;
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

*/

// Helper functions

// chunk handler for decompose_amount_into_digits
struct chunk_handler_t
{
  void operator()(uint64_t chunk) const
  {
    m_chunks.push_back(chunk);
  }

  void clear()
  {
    m_chunks.clear();
  }

  mutable std::vector<uint64_t> m_chunks;
};

// dust handler for decompose_amount_into_digits
struct dust_handler_t
{
  dust_handler_t()
    : m_dust(0)
    , m_has_dust(false)
  {
  }

  void operator()(uint64_t dust) const
  {
    m_dust = dust;
    m_has_dust = true;
  }

  void clear()
  {
    m_dust = 0;
    m_has_dust = false;
  }

  mutable uint64_t m_dust;
  mutable bool m_has_dust;
};

// tells if two vectors of hashes are equal
bool intVectorsEqual(std::vector<uint32_t> a, std::vector<uint32_t> b)
{
  if (a.size() != b.size())
  {
    return false;
  }

  for (size_t i = 0; i < a.size(); ++i)
  {
    if (a[i] != b[i])
    {
      return false;
    }
  }

  return true;
}

int loopCount = 100;

// decompose_amount_into_digits()
TEST(cryptoNoteFormatUtils, 1)
{
  uint64_t amount = 123456789;
  uint64_t dust_threshold = 10;
  chunk_handler_t chunkHandler;
  dust_handler_t dustHandler;

  decompose_amount_into_digits(amount, dust_threshold, chunkHandler, dustHandler);

  ASSERT_EQ(chunkHandler.m_chunks[0], 80);
  ASSERT_EQ(chunkHandler.m_chunks[1], 700);
  ASSERT_EQ(chunkHandler.m_chunks[2], 6000);
  ASSERT_EQ(chunkHandler.m_chunks[3], 50000);
  ASSERT_EQ(chunkHandler.m_chunks[4], 400000);
  ASSERT_EQ(chunkHandler.m_chunks[5], 3000000);
  ASSERT_EQ(chunkHandler.m_chunks[6], 20000000);
  ASSERT_EQ(chunkHandler.m_chunks[7], 100000000);
  ASSERT_EQ(dustHandler.m_dust, 9);
}

// decompose_amount_into_digits()
TEST(cryptoNoteFormatUtils, 2)
{
  uint64_t amount = 123456789;
  uint64_t dust_threshold = 50000;
  chunk_handler_t chunkHandler;
  dust_handler_t dustHandler;

  decompose_amount_into_digits(amount, dust_threshold, chunkHandler, dustHandler);

  ASSERT_EQ(chunkHandler.m_chunks[0], 50000);
  ASSERT_EQ(chunkHandler.m_chunks[1], 400000);
  ASSERT_EQ(chunkHandler.m_chunks[2], 3000000);
  ASSERT_EQ(chunkHandler.m_chunks[3], 20000000);
  ASSERT_EQ(chunkHandler.m_chunks[4], 100000000);
  ASSERT_EQ(dustHandler.m_dust, 6789);
}

// get_tx_fee()
TEST(cryptoNoteFormatUtils, 3)
{
  Transaction transaction;
  
  // inputs
  // total amount is 100
  for (uint8_t i = 0; i < 10; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = 10;

    keyInput.keyImage = getRandKeyImage();

    transaction.inputs.push_back(keyInput);
  }

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = 99;

  transaction.outputs.push_back(transactionOutput);

  uint64_t fee1;

  ASSERT_TRUE(get_tx_fee(transaction, fee1));

  uint64_t fee2 = get_tx_fee(transaction);

  ASSERT_EQ(fee1, 1);
  ASSERT_EQ(fee2, 1);
  ASSERT_EQ(fee1, fee2);
}

// get_inputs_money_amount()
TEST(cryptoNoteFormatUtils, 4)
{
  Transaction transaction;
  
  // inputs
  // total amount is 100
  for (uint8_t i = 0; i < 10; ++i)
  {
    KeyInput keyInput;
    keyInput.amount = 10;

    keyInput.keyImage = getRandKeyImage();

    transaction.inputs.push_back(keyInput);
  }

  uint64_t totalAmount;

  ASSERT_TRUE(get_inputs_money_amount(transaction, totalAmount));

  ASSERT_EQ(totalAmount, 100);
}

// get_outs_money_amount()
TEST(cryptoNoteFormatUtils, 5)
{
  Transaction transaction;

  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();
  transaction.outputs.push_back(transactionOutput);

  uint64_t amountOut = get_outs_money_amount(transaction);

  ASSERT_EQ(amountOut, transactionOutput.amount);
}

// get_block_height()
TEST(cryptoNoteFormatUtils, 6)
{
  uint32_t blockHeight = getRandUint32_t();

  Block block = getRandBlockAtHeight(blockHeight);

  uint32_t blockHeightReturned = get_block_height(block);

  ASSERT_EQ(blockHeightReturned, blockHeight);
}

// check_money_overflow()
// check_input_overflow()
// input does not overflow
TEST(cryptoNoteFormatUtils, 7)
{
  Transaction transaction;
  
  KeyInput keyInput;
  keyInput.amount = getRandUint64_t();
  transaction.inputs.push_back(keyInput);

  // returns true if money does not overflow (this is weird)
  ASSERT_TRUE(check_money_overflow(transaction));
  ASSERT_TRUE(check_inputs_overflow(transaction));
}

// check_money_overflow()
// check_input_overflow()
// input overflow
TEST(cryptoNoteFormatUtils, 8)
{
  Transaction transaction;

  KeyInput keyInput;
  
  // input 1
  keyInput.amount = UINT64_MAX;
  transaction.inputs.push_back(keyInput);

  // input 2
  keyInput.amount = 1;
  transaction.inputs.push_back(keyInput);

  // returns false if money overflows (this is weird)
  ASSERT_FALSE(check_money_overflow(transaction));
  ASSERT_FALSE(check_inputs_overflow(transaction));
}

// check_money_overflow()
// check_outs_overflow()
// output does not overflow
TEST(cryptoNoteFormatUtils, 9)
{
  Transaction transaction;
  
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();
  transaction.outputs.push_back(transactionOutput);

  // returns true if money does not overflow (this is weird)
  ASSERT_TRUE(check_money_overflow(transaction));
  ASSERT_TRUE(check_outs_overflow(transaction));
}

// check_money_overflow()
// check_outs_overflow()
// output overflows
TEST(cryptoNoteFormatUtils, 10)
{
  Transaction transaction;
  
  TransactionOutput transactionOutput;
  
  // output 1
  transactionOutput.amount = UINT64_MAX;
  transaction.outputs.push_back(transactionOutput);

  // output 2
  transactionOutput.amount = 1;
  transaction.outputs.push_back(transactionOutput);

  // returns false if money overflows (this is weird)
  ASSERT_FALSE(check_money_overflow(transaction));
  ASSERT_FALSE(check_outs_overflow(transaction));
}

// check_money_overflow()
// check_inputs_overflow()
// check_outs_overflow()
// input and output does not overflow
TEST(cryptoNoteFormatUtils, 11)
{
  Transaction transaction;

  // input
  KeyInput keyInput;
  keyInput.amount = getRandUint64_t();
  transaction.inputs.push_back(keyInput);
  
  // output
  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();
  transaction.outputs.push_back(transactionOutput);

  // returns true if money does not overflow (this is weird)
  ASSERT_TRUE(check_money_overflow(transaction));
  ASSERT_TRUE(check_inputs_overflow(transaction));
  ASSERT_TRUE(check_outs_overflow(transaction));
}

// check_money_overflow()
// check_inputs_overflow()
// check_outs_overflow()
// input and output overflows
TEST(cryptoNoteFormatUtils, 12)
{
  Transaction transaction;
  
  // inputs
  KeyInput keyInput;
  
  // input 1
  keyInput.amount = UINT64_MAX;
  transaction.inputs.push_back(keyInput);

  // input 2
  keyInput.amount = 1;
  transaction.inputs.push_back(keyInput);

  // outputs
  TransactionOutput transactionOutput;
  
  // output 1
  transactionOutput.amount = UINT64_MAX;
  transaction.outputs.push_back(transactionOutput);

  // output 2
  transactionOutput.amount = 1;
  transaction.outputs.push_back(transactionOutput);

  // returns false if money overflows (this is weird)
  ASSERT_FALSE(check_money_overflow(transaction));
  ASSERT_FALSE(check_inputs_overflow(transaction));
  ASSERT_FALSE(check_outs_overflow(transaction));
}

// check_inputs_types_supported()
TEST(cryptoNoteFormatUtils, 13)
{
  Transaction transaction1;

  // KeyInput
  KeyInput keyInput;
  transaction1.inputs.push_back(keyInput);

  // MultisignatureInput
  MultisignatureInput multisignatureInput;
  transaction1.inputs.push_back(multisignatureInput);

  ASSERT_TRUE(check_inputs_types_supported(transaction1));

  Transaction transaction2;

  // BaseInput
  BaseInput baseInput;
  transaction2.inputs.push_back(baseInput);

  ASSERT_FALSE(check_inputs_types_supported(transaction2));
}

// check_outs_valid()
// success
TEST(cryptoNoteFormatUtils, 14)
{
  Transaction transaction;

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = 100;

  KeyOutput keyOutput;

  KeyPair keyPair = generateKeyPair();

  keyOutput.key = keyPair.publicKey;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;

  ASSERT_TRUE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "");
}

// check_outs_valid()
// fail
// amount 0
TEST(cryptoNoteFormatUtils, 15)
{
  Transaction transaction;

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = 0;

  KeyOutput keyOutput;

  KeyPair keyPair = generateKeyPair();

  keyOutput.key = keyPair.publicKey;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;

  ASSERT_FALSE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "Zero amount ouput");
}

// check_outs_valid()
// fail
// invalid output public key
TEST(cryptoNoteFormatUtils, 16)
{

  Transaction transaction;

  // outputs
  TransactionOutput transactionOutput;
  transactionOutput.amount = 100;

  KeyOutput keyOutput;

  // I am not sure why this public key is invalid, but check_key() says it is invalid
  keyOutput.key = {0x75, 0x63, 0xdc, 0x8d, 0x2e, 0x23, 0xbb, 0x8f, 0xbc, 0x24, 0x60, 0xa, 0xec, 0x11, 0xa1, 0xc8, 0xdb, 0xcb, 0x68, 0x99, 0xd6, 0xa2, 0xce, 0x97, 0x23, 0xe, 0xa0, 0xd8, 0xcb, 0xe8, 0x7f, 0x41};
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;
  ASSERT_FALSE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "Output with invalid key");
}

// check_outs_valid()
// multisignature output success
TEST(cryptoNoteFormatUtils, 17)
{
  Transaction transaction;

  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  MultisignatureOutput multisignatureOutput;

  multisignatureOutput.requiredSignatureCount = 10;

  for (int i = 0; i < multisignatureOutput.requiredSignatureCount; ++i)
  {
    KeyPair keyPair = generateKeyPair();

    multisignatureOutput.keys.push_back(keyPair.publicKey);
  }

  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;
  ASSERT_TRUE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "");
}

// check_outs_valid()
// multisignature output fail
// too few keys
TEST(cryptoNoteFormatUtils, 18)
{
  Transaction transaction;

  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  MultisignatureOutput multisignatureOutput;

  multisignatureOutput.requiredSignatureCount = 10;

  // required signature count is 10 but only 9 public keys
  for (int i = 0; i < multisignatureOutput.requiredSignatureCount - 1; ++i)
  {
    KeyPair keyPair = generateKeyPair();

    multisignatureOutput.keys.push_back(keyPair.publicKey);
  }

  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;
  ASSERT_FALSE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "Multisignature output with invalid required signature count");
}

// check_outs_valid()
// multisignature output fail
// invalid key
TEST(cryptoNoteFormatUtils, 19)
{
  Transaction transaction;

  TransactionOutput transactionOutput;
  transactionOutput.amount = getRandUint64_t();

  MultisignatureOutput multisignatureOutput;

  multisignatureOutput.requiredSignatureCount = 10;

  for (int i = 0; i < multisignatureOutput.requiredSignatureCount; ++i)
  {
    multisignatureOutput.keys.push_back({0x75, 0x63, 0xdc, 0x8d, 0x2e, 0x23, 0xbb, 0x8f, 0xbc, 0x24, 0x60, 0xa, 0xec, 0x11, 0xa1, 0xc8, 0xdb, 0xcb, 0x68, 0x99, 0xd6, 0xa2, 0xce, 0x97, 0x23, 0xe, 0xa0, 0xd8, 0xcb, 0xe8, 0x7f, 0x41});
  }

  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  std::string error;
  ASSERT_FALSE(check_outs_valid(transaction, &error));
  ASSERT_EQ(error, "Multisignature output with invalid public key");
}

// checkMultisignatureInputsDiff()
TEST(cryptoNoteFormatUtils, 20)
{
  Transaction transaction;

  MultisignatureInput input1;
  input1.amount = 100;
  input1.outputIndex = 1;
  transaction.inputs.push_back(input1);

  MultisignatureInput input2;
  input2.amount = 200;
  input2.outputIndex = 2;
  transaction.inputs.push_back(input2);

  ASSERT_TRUE(checkMultisignatureInputsDiff(transaction));
}

// checkMultisignatureInputsDiff()
// fail
TEST(cryptoNoteFormatUtils, 21)
{
  Transaction transaction;

  MultisignatureInput input1;
  input1.amount = 100;
  input1.outputIndex = 1;
  transaction.inputs.push_back(input1);

  MultisignatureInput input2;
  input2.amount = 100;
  input2.outputIndex = 1;
  transaction.inputs.push_back(input2);

  ASSERT_FALSE(checkMultisignatureInputsDiff(transaction));
}

// get_tx_tree_hash()
TEST(cryptoNoteFormatUtils, 22)
{
  Block block;

  Crypto::Hash blockHash1 = get_tx_tree_hash(block);
  Crypto::Hash blockHash2 = get_tx_tree_hash(block);

  ASSERT_EQ(blockHash1, blockHash2);

  Block randBlock = getRandBlock();

  Crypto::Hash randBlockHash = get_tx_tree_hash(randBlock);

  ASSERT_NE(randBlockHash, blockHash1);
  ASSERT_NE(randBlockHash, blockHash2);
}

// get_block_hash()
TEST(cryptoNoteFormatUtils, 23)
{
  Block block = getRandBlock();

  Crypto::Hash blockHash1 = get_block_hash(block);
  Crypto::Hash blockHash2 = get_block_hash(block);

  ASSERT_EQ(blockHash1, blockHash2);

  Block block3 = getRandBlock();

  Crypto::Hash blockHash3 = get_block_hash(block3);

  ASSERT_NE(blockHash3, blockHash1);
  ASSERT_NE(blockHash3, blockHash2);
}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24)
{
  Block block = getRandBlock();

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  Example binary array:
//
//  binaryArray =
//  {
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x98, 0xd6,
//    0xad, 0x39, 0x44, 0xc9, 0x4, 0x34, 0xb2, 0x9e, 0x46, 0x4d,
//    0x54, 0xc4, 0xef, 0xaa, 0xa7, 0x25, 0x8e, 0x4b, 0x1c, 0x61, 
//    0xaa, 0xdd, 0x45, 0x86, 0x18, 0xd4, 0xa6, 0xd2, 0x99, 0x96,
//    0x1, 0xc2, 0xe5, 0xdb, 0xe9, 0xdd, 0x1e, 0x76, 0x5c, 0x5f,
//    0x8, 0x78, 0x4d, 0xd0, 0xa4, 0x99, 0x70, 0x52, 0x56, 0xc5,
//    0x2b, 0x88, 0x97, 0xe3, 0x52, 0x50, 0x2e, 0x12, 0xec, 0xd6,
//    0x96, 0x8b, 0xbb, 0x63, 0x88, 0x9d, 0x29, 0x7e, 0x7d, 0x5,
//    0x2
//  }

}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24a)
{
  Block block;

  block.previousBlockHash = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  block.nonce = 0;
  block.timestamp = 0;
  block.merkleRoot = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  binaryArray (length 80) =
//  {
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
//  }

}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24b)
{
  Block block;

  block.previousBlockHash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  block.nonce = 2;
  block.timestamp = 3;
  block.merkleRoot = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  binaryArray (length 80) =
//  {
//    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
//    0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x15, 0xcc, 0x64, 0xda, 0x4d, 0x98, 0xc0, 0x93, 0x2f, 0x1f, 0xc6, 0xaa, 0x0d, 0xff, 0x4a, 0x21, 0x12, 0xa4, 0x0f, 0xbe, 0x2c, 0x53, 0x30, 0xb8, 0xaf, 0xf2, 0xd4, 0xa9, 0xa1, 0xef, 0xb2, 0x4f
//  }

  std::string str = Common::toHex(binaryArray.data(), binaryArray.size());

  ASSERT_EQ("01010101010101010101010101010101010101010101010101010101010101010200000000000000030000000000000015cc64da4d98c0932f1fc6aa0dff4a2112a40fbe2c5330b8aff2d4a9a1efb24f", str);
}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24c)
{
  Block block;

  block.previousBlockHash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  block.nonce = 2;
  block.timestamp = 1538092926;
  block.merkleRoot = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  binaryArray (length 80) =
//  {
//    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
//    0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//    0x7e, 0x6f, 0xad, 0x5b, 0x0, 0x0, 0x0, 0x0,
//    0x15, 0xcc, 0x64, 0xda, 0x4d, 0x98, 0xc0, 0x93, 0x2f, 0x1f, 0xc6, 0xaa, 0x0d, 0xff, 0x4a, 0x21, 0x12, 0xa4, 0x0f, 0xbe, 0x2c, 0x53, 0x30, 0xb8, 0xaf, 0xf2, 0xd4, 0xa9, 0xa1, 0xef, 0xb2, 0x4f
//  }

    std::string str = Common::toHex(binaryArray.data(), binaryArray.size());

    ASSERT_EQ("010101010101010101010101010101010101010101010101010101010101010102000000000000007e6fad5b0000000015cc64da4d98c0932f1fc6aa0dff4a2112a40fbe2c5330b8aff2d4a9a1efb24f", str);
}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24d)
{
  Block block;

  block.previousBlockHash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  block.nonce = 1538092926;
  block.timestamp = 1538092926;
  block.merkleRoot = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  binaryArray (length 80) =
//  {
//    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
//    0x7e, 0x6f, 0xad, 0x5b, 0x0, 0x0, 0x0, 0x0,
//    0x7e, 0x6f, 0xad, 0x5b, 0x0, 0x0, 0x0, 0x0,
//    0x15, 0xcc, 0x64, 0xda, 0x4d, 0x98, 0xc0, 0x93, 0x2f, 0x1f, 0xc6, 0xaa, 0x0d, 0xff, 0x4a, 0x21, 0x12, 0xa4, 0x0f, 0xbe, 0x2c, 0x53, 0x30, 0xb8, 0xaf, 0xf2, 0xd4, 0xa9, 0xa1, 0xef, 0xb2, 0x4f
//  }

    std::string str = Common::toHex(binaryArray.data(), binaryArray.size());

    ASSERT_EQ("01010101010101010101010101010101010101010101010101010101010101017e6fad5b000000007e6fad5b0000000015cc64da4d98c0932f1fc6aa0dff4a2112a40fbe2c5330b8aff2d4a9a1efb24f", str);
}

// get_block_hashing_blob()
TEST(cryptoNoteFormatUtils, 24e)
{
  Block block;

  block.previousBlockHash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  block.nonce = 1538092926;
  block.timestamp = 1538092926;
  block.merkleRoot = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  BinaryArray binaryArray;

  ASSERT_TRUE(get_block_hashing_blob(block, binaryArray));

//  binaryArray (length 80) =
//  {
//    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 
//    0x7e, 0x6f, 0xad, 0x5b, 0x0, 0x0, 0x0, 0x0,
//    0x7e, 0x6f, 0xad, 0x5b, 0x0, 0x0, 0x0, 0x0,
//    0x15, 0xcc, 0x64, 0xda, 0x4d, 0x98, 0xc0, 0x93, 0x2f, 0x1f, 0xc6, 0xaa, 0x0d, 0xff, 0x4a, 0x21, 0x12, 0xa4, 0x0f, 0xbe, 0x2c, 0x53, 0x30, 0xb8, 0xaf, 0xf2, 0xd4, 0xa9, 0xa1, 0xef, 0xb2, 0x4f
//  }

    std::string str = Common::toHex(binaryArray.data(), binaryArray.size());

    ASSERT_EQ("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207e6fad5b000000007e6fad5b0000000015cc64da4d98c0932f1fc6aa0dff4a2112a40fbe2c5330b8aff2d4a9a1efb24f", str);
}

// get_aux_block_header_hash()
TEST(cryptoNoteFormatUtils, 25)
{
  Block block = getRandBlock();

  Crypto::Hash blockHash1;

  ASSERT_TRUE(get_aux_block_header_hash(block, blockHash1));

  // For some reason, get_aux_block_header_hash() and get_block_hash() do the same thing
  Crypto::Hash blockHash2;

  ASSERT_TRUE(get_block_hash(block, blockHash2));

  ASSERT_EQ(blockHash1, blockHash2);
}

// get_block_longhash()
TEST(cryptoNoteFormatUtils, 26)
{
  Block block = getRandBlock();

  Crypto::Hash blockHash;

  Crypto::cn_context context;

  ASSERT_TRUE(get_block_longhash(context, block, blockHash));

//   Example of blockHash:
//
//   blockHash =
//     {
//       0x1, 0x52, 0xaa, 0x2b, 0x95, 0x18, 0x5c, 0xb3, 0x5e, 0xad,
//       0x14, 0x93, 0xe0, 0xeb, 0xa8, 0xb4, 0xa3, 0xcb, 0x3a, 0x7a,
//       0xb, 0x3f, 0x9d, 0xde, 0x94, 0x8c, 0x1, 0x8e, 0xd9, 0xad,
//       0xd0, 0x62
//     }
}

// short_hash_str()
TEST(cryptoNoteFormatUtils, 27)
{
  Crypto::Hash hash = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  std::string shortHashStr = short_hash_str(hash);

  // How short_hash_str() works:
  //
  // convert hash in decimal to hex = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
  // pod_to_hex(hash) = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  // delete 48 characters starting at position 8 = "010203041d1e1f20"
  // insert ellipses = "01020304....1d1e1f20"

  ASSERT_EQ(shortHashStr, "01020304....1d1e1f20");
}

// relative_output_offsets_to_absolute()
TEST(cryptoNoteFormatUtils, 28)
{
  std::vector<uint32_t> vectorInput = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  // starting at position 1, change the value to itself plus previous position's value
  std::vector<uint32_t> vectorOutput = relative_output_offsets_to_absolute(vectorInput);

  std::vector<uint32_t> expectedOutput = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55};

  ASSERT_TRUE(intVectorsEqual(vectorOutput, expectedOutput));
}

// absolute_output_offsets_to_relative()
TEST(cryptoNoteFormatUtils, 29)
{
  std::vector<uint32_t> vectorInput = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55};

  // starting at the end, change the value to itself minus previous position's value
  std::vector<uint32_t> vectorOutput = absolute_output_offsets_to_relative(vectorInput);

  std::vector<uint32_t> expectedOutput = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  ASSERT_TRUE(intVectorsEqual(vectorOutput, expectedOutput));
}

// is_out_to_acc()
TEST(cryptoNoteFormatUtils, 30)
{
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  KeyPair transactionKeyPair = generateKeyPair();

  Crypto::PublicKey viewPublicKey = viewKeyPair.publicKey;
  Crypto::SecretKey viewSecretKey = viewKeyPair.secretKey;

  Crypto::PublicKey spendPublicKey = spendKeyPair.publicKey;
  Crypto::SecretKey spendSecretKey = spendKeyPair.secretKey;
  
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;

  AccountKeys accountKeys;

  accountKeys.viewSecretKey = viewSecretKey;
  accountKeys.spendSecretKey = spendSecretKey;
  accountKeys.address.viewPublicKey = viewPublicKey;
  accountKeys.address.spendPublicKey = spendPublicKey;

  // To generate an ephemeral key used to send money to:
  //
  // The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in "extra" field.
  // Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view" key.
  // The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public key.
  // The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key (to spend the money).

  Crypto::KeyDerivation derivation;
  generate_key_derivation(transactionPublicKey, accountKeys.viewSecretKey, derivation);

  Crypto::PublicKey keyOutputPublicKey;
  size_t keyOutputIndex = 0;

  derive_public_key(derivation, keyOutputIndex, accountKeys.address.spendPublicKey, keyOutputPublicKey);

  KeyOutput keyOutput;
  keyOutput.key = keyOutputPublicKey;

  ASSERT_TRUE(is_out_to_acc(accountKeys, keyOutput, transactionPublicKey, keyOutputIndex));
}

// lookup_acc_outs()
TEST(cryptoNoteFormatUtils, 31)
{
  Transaction transaction;

  // outputs
  
  // set up account keys
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys accountKeys;

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  // get key output public key
  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;

  Crypto::KeyDerivation derivation;
  generate_key_derivation(transactionPublicKey, accountKeys.viewSecretKey, derivation);

  Crypto::PublicKey keyOutputPublicKey;
  size_t keyOutputIndex = 0;

  derive_public_key(derivation, keyOutputIndex, accountKeys.address.spendPublicKey, keyOutputPublicKey);

  KeyOutput keyOutput;
  keyOutput.key = keyOutputPublicKey;

  TransactionOutput transactionOutput;

  transactionOutput.amount = 100;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // extra

  // 1 means we are creating a transaction public key
  transaction.extra.push_back(1);

  for (int i = 0; i < 32; ++i)
  {
    // add transaction public key to extra field
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  std::vector<size_t> outs;
  uint64_t moneyTransfered;

  ASSERT_TRUE(lookup_acc_outs(accountKeys, transaction, outs, moneyTransfered));
  ASSERT_EQ(moneyTransfered, 100);
  ASSERT_EQ(outs.size(), 1);
}

// constructTransaction()
// no inputs and no outputs
TEST(cryptoNoteFormatUtils, 32)
{
  // account keys
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys senderAccountKeys;

  senderAccountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  senderAccountKeys.viewSecretKey = viewKeyPair.secretKey;
  senderAccountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  senderAccountKeys.spendSecretKey = spendKeyPair.secretKey;

  // TransactionSourceEntry vector
  std::vector<TransactionSourceEntry> sources;

  // TransactionDestinationEntry vector
  std::vector<TransactionDestinationEntry> destinations;

  // extra
  std::vector<uint8_t> extra;

  // 1 means we are creating a transaction public key
  extra.push_back(1);

  KeyPair transactionKeyPair = generateKeyPair();

  for (int i = 0; i < 32; ++i)
  {
    // add transaction public key to extra field
    extra.push_back(transactionKeyPair.publicKey.data[i]);
  }

  // transaction
  Transaction transaction;

  // unlock time
  uint64_t unlockTime = getRandUint64_t();

  // logger
  Logging::LoggerGroup logger;

  Crypto::SecretKey transactionSecretKeyIgnore;
  ASSERT_TRUE(constructTransaction(senderAccountKeys, sources, destinations, extra, transaction, unlockTime, transactionSecretKeyIgnore, logger));

  ASSERT_EQ(transaction.version, CURRENT_TRANSACTION_VERSION);
  ASSERT_EQ(transaction.unlockTime, unlockTime);
  // transaction.extra contains the extra vector plus a public key appended on, so we want only the first 33 characters
  ASSERT_TRUE(std::equal(transaction.extra.begin(), transaction.extra.begin() + 33, extra.begin()));
  ASSERT_EQ(transaction.inputs.size(), 0);
  ASSERT_EQ(transaction.outputs.size(), 0);
}

// constructTransaction()
TEST(cryptoNoteFormatUtils, 33)
{
  // account keys
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys senderAccountKeys;

  senderAccountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  senderAccountKeys.viewSecretKey = viewKeyPair.secretKey;
  senderAccountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  senderAccountKeys.spendSecretKey = spendKeyPair.secretKey;

  // key output
  KeyPair transactionKeyPair = generateKeyPair();

  Crypto::KeyDerivation derivation;
  generate_key_derivation(transactionKeyPair.publicKey, senderAccountKeys.viewSecretKey, derivation);

  Crypto::PublicKey keyOutputPublicKey;
  size_t keyOutputIndex = 0;

  derive_public_key(derivation, keyOutputIndex, senderAccountKeys.address.spendPublicKey, keyOutputPublicKey);

  // TransactionSourceEntry vector
  std::vector<TransactionSourceEntry> sources;

  TransactionSourceEntry transactionSourceEntry;
  // KeyPair outputEntryKeyPair = generateKeyPair();
  TransactionSourceEntry::OutputEntry outputEntry(0, keyOutputPublicKey);
  transactionSourceEntry.outputs.push_back(outputEntry);
  transactionSourceEntry.realOutput = 0;
  transactionSourceEntry.realTransactionPublicKey = transactionKeyPair.publicKey;
  transactionSourceEntry.realOutputIndexInTransaction = 0;
  transactionSourceEntry.amount = 100;
  sources.push_back(transactionSourceEntry);

  // TransactionDestinationEntry vector
  std::vector<TransactionDestinationEntry> destinations;

  AccountPublicAddress accountPublicAddress;

  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  TransactionDestinationEntry transactionDestinationEntry(100, accountPublicAddress);

  destinations.push_back(transactionDestinationEntry);

  // extra
  std::vector<uint8_t> extra;

  // 1 means we are creating a transaction public key
  extra.push_back(1);

  for (int i = 0; i < 32; ++i)
  {
    // add transaction public key to extra field
    extra.push_back(transactionKeyPair.publicKey.data[i]);
  }

  // transaction
  Transaction transaction;

  // unlock time
  uint64_t unlockTime = getRandUint64_t();

  // logger
  Logging::LoggerGroup logger;

  Crypto::SecretKey transactionSecretKeyIgnore;

  ASSERT_TRUE(constructTransaction(senderAccountKeys, sources, destinations, extra, transaction, unlockTime, transactionSecretKeyIgnore, logger));

  ASSERT_EQ(transaction.version, CURRENT_TRANSACTION_VERSION);
  ASSERT_EQ(transaction.unlockTime, unlockTime);
  // transaction.extra contains the extra vector plus a public key appended on, so we want only the first 33 characters
  ASSERT_TRUE(std::equal(transaction.extra.begin(), transaction.extra.begin() + 33, extra.begin()));
  ASSERT_EQ(transaction.inputs.size(), 1);
  ASSERT_EQ(transaction.outputs.size(), 1);
}

// generate_key_image_helper()
TEST(cryptoNoteFormatUtils, 34)
{
  // account keys
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys accountKeys;

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  // transaction public key
  KeyPair transactionKeyPair = generateKeyPair();

  // real output index
  size_t realOutputIndex = 0;

  KeyPair ephemeralKeyPair;

  Crypto::KeyImage keyImage;

  ASSERT_TRUE(generate_key_image_helper(accountKeys, transactionKeyPair.publicKey, realOutputIndex, ephemeralKeyPair, keyImage));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}