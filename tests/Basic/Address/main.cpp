// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "Crypto/crypto-ops.h"
#include "Crypto/hash.h"
#include "Crypto/crypto.h"
#include "Crypto-tests.h"

#include <string>
#include <iostream>

using namespace CryptoNote;

TEST(address, 1)
{
  char hash[32];
  std::string str = "Hello World";

  Crypto::cn_fast_hash(str.data(), str.size(), hash);
  std::string hashStr = Common::toHex(hash, 32);
  ASSERT_EQ("1dc01772ee0171f5f614c673e3c7fa1107a8cf727bdf5a6dadb379e93c0d1d00", hashStr);
}

TEST(address, 2)
{
  Crypto::SecretKey secretKey =
  {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0
  };

  ASSERT_TRUE(check_scalar(secretKey));
}

TEST(address, 3)
{
  Crypto::SecretKey secretKey =
  {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1
  };

  ASSERT_TRUE(check_scalar(secretKey));
}

TEST(address, 4)
{
  Crypto::SecretKey secretKey =
  {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1
  };

  Crypto::PublicKey publicKey;
  ASSERT_TRUE(secret_key_to_public_key(secretKey, publicKey));
}





















TEST(address, 40)
{
  std::string str = "Hello World";
  bool spendSecretKeyFound = false;
  bool viewSecretKeyFound = false;

  for (int i = 0; i < 100; i++)
  {
    char hash[32];
    Crypto::cn_fast_hash(str.data(), str.size(), hash);
    str = Common::toHex(hash, 32);

    Crypto::SecretKey secretKey;
    for (int i = 0; i < 32; i++)
    {
      secretKey.data[i] = hash[i];
    }

    if (check_scalar(secretKey))
    {
      std::cout << "Spend Secret Key Found : " << str << std::endl;
      break;
    }
  }
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}