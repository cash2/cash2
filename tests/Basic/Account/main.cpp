// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "CryptoNoteCore/Account.h"

using namespace CryptoNote;

// My Notes:
//
//  struct AccountPublicAddress {
//    Crypto::PublicKey spendPublicKey;
//    Crypto::PublicKey viewPublicKey;
//  };
//
//  struct AccountKeys {
//    AccountPublicAddress address;
//    Crypto::SecretKey spendSecretKey;
//    Crypto::SecretKey viewSecretKey;
//  };
//
//  struct SecretKey {
//    uint8_t data[32];
//  };
//
//  struct PublicKey {
//    uint8_t data[32];
//  };

// AccountBase() and getAccountKeys()
TEST(account, 1)
{
  AccountBase accountBase;
  AccountKeys accountKeys = accountBase.getAccountKeys();

  size_t viewPublicKeySize = sizeof(accountKeys.address.viewPublicKey.data) / sizeof(accountKeys.address.viewPublicKey.data[0]);
  size_t spendPublicKeySize = sizeof(accountKeys.address.spendPublicKey.data) / sizeof(accountKeys.address.spendPublicKey.data[0]);
  size_t viewSecretKeySize = sizeof(accountKeys.viewSecretKey.data) / sizeof(accountKeys.viewSecretKey.data[0]);
  size_t spendSecretKeySize = sizeof(accountKeys.spendSecretKey.data) / sizeof(accountKeys.spendSecretKey.data[0]);

  // check that the size of the keys are 32 ints long
  ASSERT_EQ(viewPublicKeySize, 32);
  ASSERT_EQ(spendPublicKeySize, 32);
  ASSERT_EQ(viewSecretKeySize, 32);
  ASSERT_EQ(spendSecretKeySize, 32);

  // check that all 32 ints of the keys are zero
  for (uint8_t i = 0; i < viewPublicKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.address.viewPublicKey.data[i], 0);
  }

  for (uint8_t i = 0; i < spendPublicKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.address.spendPublicKey.data[i], 0);
  }

  for (uint8_t i = 0; i < viewSecretKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.viewSecretKey.data[i], 0);
  }

  for (uint8_t i = 0; i < spendSecretKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.spendSecretKey.data[i], 0);
  }
}

// generate()
TEST(account, 2)
{
  AccountBase accountBase;
  AccountKeys accountKeys = accountBase.getAccountKeys();

  // fill in values for keys so that they are no longer just zeros
  accountBase.generate();

  accountKeys = accountBase.getAccountKeys();

  size_t viewPublicKeySize = sizeof(accountKeys.address.viewPublicKey.data) / sizeof(accountKeys.address.viewPublicKey.data[0]);
  size_t spendPublicKeySize = sizeof(accountKeys.address.spendPublicKey.data) / sizeof(accountKeys.address.spendPublicKey.data[0]);
  size_t viewSecretKeySize = sizeof(accountKeys.viewSecretKey.data) / sizeof(accountKeys.viewSecretKey.data[0]);
  size_t spendSecretKeySize = sizeof(accountKeys.spendSecretKey.data) / sizeof(accountKeys.spendSecretKey.data[0]);

  // check that the size of the keys are still 32 ints long
  ASSERT_EQ(viewPublicKeySize, 32);
  ASSERT_EQ(spendPublicKeySize, 32);
  ASSERT_EQ(viewSecretKeySize, 32);
  ASSERT_EQ(spendSecretKeySize, 32);

  // check that each key is not all zeros
  int zeroCounter = 0;
  for (uint8_t i = 0; i < viewPublicKeySize; ++i)
  {
    if (accountKeys.address.viewPublicKey.data[i] == 0)
    {
      ++zeroCounter;
    }
  }
  ASSERT_NE(zeroCounter, viewPublicKeySize);

  zeroCounter = 0;
  for (uint8_t i = 0; i < spendPublicKeySize; ++i)
  {
    if (accountKeys.address.spendPublicKey.data[i] == 0)
    {
      ++zeroCounter;
    }
  }
  ASSERT_NE(zeroCounter, spendPublicKeySize);

  zeroCounter = 0;
  for (uint8_t i = 0; i < viewSecretKeySize; ++i)
  {
    if (accountKeys.viewSecretKey.data[i] == 0)
    {
      ++zeroCounter;
    }
  }
  ASSERT_NE(zeroCounter, viewSecretKeySize);

  zeroCounter = 0;
  for (uint8_t i = 0; i < spendSecretKeySize; ++i)
  {
    if (accountKeys.spendSecretKey.data[i] == 0)
    {
      ++zeroCounter;
    }
  }
  ASSERT_NE(zeroCounter, spendSecretKeySize);
}

// setAccountKeys() and getAccountKeys()
TEST(account, 3)
{
  AccountBase accountBase;
  AccountKeys accountKeys = accountBase.getAccountKeys();

  size_t viewPublicKeySize = sizeof(accountKeys.address.viewPublicKey.data) / sizeof(accountKeys.address.viewPublicKey.data[0]);
  size_t spendPublicKeySize = sizeof(accountKeys.address.spendPublicKey.data) / sizeof(accountKeys.address.spendPublicKey.data[0]);
  size_t viewSecretKeySize = sizeof(accountKeys.viewSecretKey.data) / sizeof(accountKeys.viewSecretKey.data[0]);
  size_t spendSecretKeySize = sizeof(accountKeys.spendSecretKey.data) / sizeof(accountKeys.spendSecretKey.data[0]);

  // fill in values for randome keys
  AccountKeys randAccountKeys;

  for (size_t i = 0; i < viewPublicKeySize; ++i)
  {
    randAccountKeys.address.viewPublicKey.data[i] = rand() % 256;
  }

  for (size_t i = 0; i < spendPublicKeySize; ++i)
  {
    randAccountKeys.address.spendPublicKey.data[i] = rand() % 256;
  }

  for (size_t i = 0; i < viewSecretKeySize; ++i)
  {
    randAccountKeys.viewSecretKey.data[i] = rand() % 256;
  }

  for (size_t i = 0; i < spendSecretKeySize; ++i)
  {
    randAccountKeys.spendSecretKey.data[i] = rand() % 256;
  }

  accountBase.setAccountKeys(randAccountKeys);

  accountKeys = accountBase.getAccountKeys();

  viewPublicKeySize = sizeof(accountKeys.address.viewPublicKey.data) / sizeof(accountKeys.address.viewPublicKey.data[0]);
  spendPublicKeySize = sizeof(accountKeys.address.spendPublicKey.data) / sizeof(accountKeys.address.spendPublicKey.data[0]);
  viewSecretKeySize = sizeof(accountKeys.viewSecretKey.data) / sizeof(accountKeys.viewSecretKey.data[0]);
  spendSecretKeySize = sizeof(accountKeys.spendSecretKey.data) / sizeof(accountKeys.spendSecretKey.data[0]);

  // check that the size of the keys are still 32 ints long
  ASSERT_EQ(viewPublicKeySize, 32);
  ASSERT_EQ(spendPublicKeySize, 32);
  ASSERT_EQ(viewSecretKeySize, 32);
  ASSERT_EQ(spendSecretKeySize, 32);

  // check that keys match
  for (uint8_t i = 0; i < viewPublicKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.address.viewPublicKey.data[i], randAccountKeys.address.viewPublicKey.data[i]);
  }

  for (uint8_t i = 0; i < spendPublicKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.address.spendPublicKey.data[i], randAccountKeys.address.spendPublicKey.data[i]);
  }
  
  for (uint8_t i = 0; i < viewSecretKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.viewSecretKey.data[i], randAccountKeys.viewSecretKey.data[i]);
  }

  for (uint8_t i = 0; i < spendSecretKeySize; ++i)
  {
    ASSERT_EQ(accountKeys.spendSecretKey.data[i], randAccountKeys.spendSecretKey.data[i]);
  }
  
}

// set_createtime() and get_createtime()
TEST(account, 4)
{
  AccountBase accountBase;

  for (int i = 0; i < 1000; ++i)
  {
    uint64_t randTime = rand();

    // set creation time to a random time
    accountBase.set_createtime(randTime);

    // get creation time
    ASSERT_EQ(accountBase.get_createtime(), randTime);
  }
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}