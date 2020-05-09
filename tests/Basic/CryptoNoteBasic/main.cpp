// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include "CryptoNoteCore/CryptoNoteBasic.h"

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

*/

TEST(cryptoNoteBasic, 1)
{
  KeyPair keyPair = generateKeyPair();

  ASSERT_NE(keyPair.publicKey.data, NULL_PUBLIC_KEY.data);

  ASSERT_NE(keyPair.secretKey.data, NULL_SECRET_KEY.data);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}