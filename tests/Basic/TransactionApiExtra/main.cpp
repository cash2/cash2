// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/TransactionApiExtra.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

class TransactionExtra
public
  TransactionExtra()
  TransactionExtra()
  parse()
  get()
  set()
  append()
  getPublicKey()
  serialize()
private
  find()
  find()
  std::vector<CryptoNote::TransactionExtraField> fields

struct TransactionExtraPadding {
  size_t size
}

struct TransactionExtraPublicKey {
  Crypto::PublicKey publicKey
}

struct TransactionExtraNonce {
  std::vector<uint8_t> nonce
}

*/

uint32_t loopCount = 100;

// default constructor
TEST(TransactionApiExtra, 1)
{
  TransactionExtra transactionExtra();
}

// constructor
TEST(TransactionApiExtra, 2)
{
  std::vector<uint8_t> extra;

  TransactionExtra transactionExtra(extra);
}

// parse() and get()
// TransactionExtraPadding
TEST(TransactionApiExtra, 3)
{
  std::vector<uint8_t> extra = {0, 0, 0, 0, 0};

  TransactionExtra transactionExtra(extra);

  ASSERT_TRUE(transactionExtra.parse(extra));

  TransactionExtraPadding transactionExtraPadding;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPadding));

  ASSERT_EQ(5, transactionExtraPadding.size);

  TransactionExtraPublicKey transactionExtraPublicKey;
  TransactionExtraNonce transactionExtraNonce;

  ASSERT_FALSE(transactionExtra.get(transactionExtraPublicKey));
  ASSERT_FALSE(transactionExtra.get(transactionExtraNonce));
}

// parse() and get()
// transactionExtraPublicKey
TEST(TransactionApiExtra, 4)
{
  std::vector<uint8_t> extra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  TransactionExtra transactionExtra(extra);

  ASSERT_TRUE(transactionExtra.parse(extra));

  TransactionExtraPublicKey transactionExtraPublicKey;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPublicKey));

  Crypto::PublicKey publicKeyExpected = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  ASSERT_TRUE(publicKeysEqual(publicKeyExpected, transactionExtraPublicKey.publicKey));

  TransactionExtraPadding transactionExtraPadding;
  TransactionExtraNonce transactionExtraNonce;

  ASSERT_FALSE(transactionExtra.get(transactionExtraPadding));
  ASSERT_FALSE(transactionExtra.get(transactionExtraNonce));
}

// parse() and get()
// TransactionExtraNonce
TEST(TransactionApiExtra, 5)
{
  std::vector<uint8_t> extra = {2, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

  TransactionExtra transactionExtra(extra);

  ASSERT_TRUE(transactionExtra.parse(extra));

  TransactionExtraNonce transactionExtraNonce;

  ASSERT_TRUE(transactionExtra.get(transactionExtraNonce));

  std::vector<uint8_t> nonceExpected = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

  ASSERT_TRUE(std::equal(transactionExtraNonce.nonce.begin(), transactionExtraNonce.nonce.end(), nonceExpected.begin()));

  TransactionExtraPadding transactionExtraPadding;
  TransactionExtraPublicKey transactionExtraPublicKey;

  ASSERT_FALSE(transactionExtra.get(transactionExtraPadding));
  ASSERT_FALSE(transactionExtra.get(transactionExtraPublicKey));
}

// set() and get()
// transactionExtraPadding 1
TEST(TransactionApiExtra, 6)
{
  TransactionExtra transactionExtra;

  TransactionExtraPadding transactionExtraPadding;
  transactionExtraPadding.size = 5;

  transactionExtra.set(transactionExtraPadding);

  TransactionExtraPadding transactionExtraPaddingOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPaddingOut));

  ASSERT_EQ(5, transactionExtraPaddingOut.size);
}

// set() and get()
// transactionExtraPadding 2
TEST(TransactionApiExtra, 7)
{
  TransactionExtra transactionExtra;

  TransactionExtraPadding transactionExtraPadding1;
  transactionExtraPadding1.size = 5;

  TransactionExtraPadding transactionExtraPadding2;
  transactionExtraPadding2.size = 10;

  transactionExtra.set(transactionExtraPadding1);
  // transactionExtraPadding2 replaces transactionExtraPadding1
  transactionExtra.set(transactionExtraPadding2);

  TransactionExtraPadding transactionExtraPaddingOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPaddingOut));

  ASSERT_EQ(10, transactionExtraPaddingOut.size);
}

// set() and get()
// transactionExtraPublicKey 1
TEST(TransactionApiExtra, 8)
{
  TransactionExtra transactionExtra;

  TransactionExtraPublicKey transactionExtraPublicKey;
  transactionExtraPublicKey.publicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  transactionExtra.set(transactionExtraPublicKey);

  TransactionExtraPublicKey transactionExtraPublicKeyOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPublicKeyOut));

  ASSERT_TRUE(publicKeysEqual(transactionExtraPublicKey.publicKey, transactionExtraPublicKeyOut.publicKey));
}

// set() and get()
// transactionExtraPublicKey 2
TEST(TransactionApiExtra, 9)
{
  TransactionExtra transactionExtra;

  TransactionExtraPublicKey transactionExtraPublicKey1;
  transactionExtraPublicKey1.publicKey = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  TransactionExtraPublicKey transactionExtraPublicKey2;
  transactionExtraPublicKey2.publicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  transactionExtra.set(transactionExtraPublicKey1);
  transactionExtra.set(transactionExtraPublicKey2);

  TransactionExtraPublicKey transactionExtraPublicKeyOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraPublicKeyOut));

  ASSERT_TRUE(publicKeysEqual(transactionExtraPublicKey2.publicKey, transactionExtraPublicKeyOut.publicKey));
}

// set() and get()
// transactionExtraNonce 1
TEST(TransactionApiExtra, 10)
{
  TransactionExtra transactionExtra;

  TransactionExtraNonce transactionExtraNonce;
  transactionExtraNonce.nonce = {2, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  transactionExtra.set(transactionExtraNonce);

  TransactionExtraNonce transactionExtraNonceOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraNonceOut));

  ASSERT_EQ(transactionExtraNonceOut.nonce.size(), 12);
  ASSERT_TRUE(std::equal(transactionExtraNonceOut.nonce.begin(), transactionExtraNonceOut.nonce.end(), transactionExtraNonce.nonce.begin()));
}

// set() and get()
// transactionExtraNonce 2
TEST(TransactionApiExtra, 11)
{
  TransactionExtra transactionExtra;

  TransactionExtraNonce transactionExtraNonce1;
  transactionExtraNonce1.nonce = {2, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  TransactionExtraNonce transactionExtraNonce2;
  transactionExtraNonce2.nonce = {2, 5, 9, 9, 9, 9, 9};

  transactionExtra.set(transactionExtraNonce1);
  transactionExtra.set(transactionExtraNonce2);

  TransactionExtraNonce transactionExtraNonceOut;

  ASSERT_TRUE(transactionExtra.get(transactionExtraNonceOut));

  ASSERT_EQ(transactionExtraNonceOut.nonce.size(), 7);
  ASSERT_TRUE(std::equal(transactionExtraNonceOut.nonce.begin(), transactionExtraNonceOut.nonce.end(), transactionExtraNonce2.nonce.begin()));
}

// append()
TEST(TransactionApiExtra, 12)
{
  TransactionExtra transactionExtra;

  TransactionExtraPadding transactionExtraPadding;
  transactionExtraPadding.size = 5;

  TransactionExtraPublicKey transactionExtraPublicKey;
  transactionExtraPublicKey.publicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  TransactionExtraNonce transactionExtraNonce;
  transactionExtraNonce.nonce = {2, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  transactionExtra.append(transactionExtraPadding);
  transactionExtra.append(transactionExtraPublicKey);
  transactionExtra.append(transactionExtraNonce);

  TransactionExtraPadding transactionExtraPaddingOut;
  ASSERT_TRUE(transactionExtra.get(transactionExtraPaddingOut));
  ASSERT_EQ(5, transactionExtraPaddingOut.size);

  TransactionExtraPublicKey transactionExtraPublicKeyOut;
  ASSERT_TRUE(transactionExtra.get(transactionExtraPublicKeyOut));
  ASSERT_TRUE(publicKeysEqual(transactionExtraPublicKey.publicKey, transactionExtraPublicKeyOut.publicKey));

  TransactionExtraNonce transactionExtraNonceOut;
  ASSERT_TRUE(transactionExtra.get(transactionExtraNonceOut));
  ASSERT_EQ(transactionExtraNonceOut.nonce.size(), 12);
  ASSERT_TRUE(std::equal(transactionExtraNonceOut.nonce.begin(), transactionExtraNonceOut.nonce.end(), transactionExtraNonce.nonce.begin()));
}

// getPublicKey()
TEST(TransactionApiExtra, 13)
{
  TransactionExtra transactionExtra;

  TransactionExtraPublicKey transactionExtraPublicKey;
  transactionExtraPublicKey.publicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  transactionExtra.set(transactionExtraPublicKey);

  Crypto::PublicKey publicKey;

  ASSERT_TRUE(transactionExtra.getPublicKey(publicKey));

  ASSERT_TRUE(publicKeysEqual(transactionExtraPublicKey.publicKey, publicKey));
}

// serialize()
// transactionExtraPadding
TEST(TransactionApiExtra, 14)
{
  TransactionExtra transactionExtra;

  TransactionExtraPadding transactionExtraPadding;
  transactionExtraPadding.size = 5;

  transactionExtra.set(transactionExtraPadding);

  std::vector<uint8_t> serialized = transactionExtra.serialize();

  std::vector<uint8_t> expected = {0, 0, 0, 0, 0};

  ASSERT_TRUE(std::equal(serialized.begin(), serialized.end(), expected.begin()));
}

// serialize()
// transactionExtraPadding
TEST(TransactionApiExtra, 15)
{
  TransactionExtra transactionExtra;

  TransactionExtraPublicKey transactionExtraPublicKey;
  transactionExtraPublicKey.publicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  transactionExtra.set(transactionExtraPublicKey);

  std::vector<uint8_t> serialized = transactionExtra.serialize();

  std::vector<uint8_t> expected = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  ASSERT_TRUE(std::equal(serialized.begin(), serialized.end(), expected.begin()));
}

// serialize()
// transactionExtraNonce
TEST(TransactionApiExtra, 16)
{
  TransactionExtra transactionExtra;

  TransactionExtraNonce transactionExtraNonce;
  transactionExtraNonce.nonce = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  transactionExtra.set(transactionExtraNonce);

  std::vector<uint8_t> serialized = transactionExtra.serialize();

  std::vector<uint8_t> expected = {2, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  ASSERT_TRUE(std::equal(serialized.begin(), serialized.end(), expected.begin()));
}


int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}