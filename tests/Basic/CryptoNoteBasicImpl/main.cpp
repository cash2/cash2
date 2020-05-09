// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteConfig.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

struct KeyPair {
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
};

struct PublicKey {
  uint8_t data[32];
};

struct SecretKey {
  uint8_t data[32];
};

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

*/

// getPenalizedAmount()
// currentBlockSize < medianBlockSize
TEST(cryptoNoteBasicImpl, 1)
{
  uint64_t amount = 100;

  size_t medianBlockSize = 1000;

  size_t currentBlockSize = 900;

  uint64_t penalizedAmount = getPenalizedAmount(amount, medianBlockSize, currentBlockSize);

  ASSERT_EQ(amount, penalizedAmount);
}

// getPenalizedAmount()
// currentBlockSize = medianBlockSize
TEST(cryptoNoteBasicImpl, 2)
{
  uint64_t amount = 100;

  size_t medianBlockSize = 1000;

  size_t currentBlockSize = 1000;

  uint64_t penalizedAmount = getPenalizedAmount(amount, medianBlockSize, currentBlockSize);

  // amount = 100
  // penalizedAmount = 100
  ASSERT_EQ(amount, penalizedAmount);
}

// getPenalizedAmount()
// currentBlockSize > medianBlockSize
TEST(cryptoNoteBasicImpl, 3)
{
  uint64_t amount = 100;

  size_t medianBlockSize = 1000;

  size_t currentBlockSize = 1500;

  uint64_t penalizedAmount = getPenalizedAmount(amount, medianBlockSize, currentBlockSize);

  // amount = 100
  // penalizedAmount = 75
  ASSERT_LT(penalizedAmount, amount);
}

// getPenalizedAmount()
// currentBlockSize > medianBlockSize
TEST(cryptoNoteBasicImpl, 4)
{
  uint64_t amount = 100;

  size_t medianBlockSize = 1000;

  size_t currentBlockSize = 2000;

  uint64_t penalizedAmount = getPenalizedAmount(amount, medianBlockSize, currentBlockSize);

  // amount = 100
  // penalizedAmount = 0
  ASSERT_LT(penalizedAmount, amount);
}

// getPenalizedAmount()
// currentBlockSize > medianBlockSize
// max sizes
TEST(cryptoNoteBasicImpl, 5)
{
  uint64_t amount = 100;

  size_t medianBlockSize = 4294967295;

  size_t currentBlockSize = 4294967295;

  uint64_t penalizedAmount = getPenalizedAmount(amount, medianBlockSize, currentBlockSize);

  // amount = 100
  // penalizedAmount = 0
  ASSERT_EQ(penalizedAmount, amount);
}

// getAccountAddressAsStr()
TEST(cryptoNoteBasicImpl, 6)
{
  uint64_t prefix = 0x06; // '2'
  AccountPublicAddress address;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  address.viewPublicKey = viewKeyPair.publicKey;
  address.spendPublicKey = spendKeyPair.publicKey;

  // accountAddressStr is "22pkk7iWNdy3G1zpuFz4GNbCwRKXGYvLfG9kdXeqBgqSEmaPP5vCmBD6uMbZwHgY5s5HMvrx8FqheGrisDQ3Aib7E8Tt12h"
  std::string accountAddressStr = getAccountAddressAsStr(prefix, address);

  ASSERT_EQ(accountAddressStr[0], '2');
}

// parseAccountAddressString()
TEST(cryptoNoteBasicImpl, 7)
{
  uint64_t prefix = 0x06; // '2'
  AccountPublicAddress addressIn;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  addressIn.viewPublicKey = viewKeyPair.publicKey;
  addressIn.spendPublicKey = spendKeyPair.publicKey;

  // accountAddressStr is "22pkk7iWNdy3G1zpuFz4GNbCwRKXGYvLfG9kdXeqBgqSEmaPP5vCmBD6uMbZwHgY5s5HMvrx8FqheGrisDQ3Aib7E8Tt12h"
  std::string accountAddressStr = getAccountAddressAsStr(prefix, addressIn);

  AccountPublicAddress addressOut;

  ASSERT_TRUE(parseAccountAddressString(prefix, addressOut, accountAddressStr));

  ASSERT_EQ(addressIn.viewPublicKey, addressOut.viewPublicKey);
  ASSERT_EQ(addressIn.spendPublicKey, addressOut.spendPublicKey);
}

// is_coinbase()
TEST(cryptoNoteBasicImpl, 8)
{
  Transaction transaction = getRandCoinbaseTransaction();

  ASSERT_TRUE(is_coinbase(transaction));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}