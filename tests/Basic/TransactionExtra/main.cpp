// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

#define TX_EXTRA_PADDING_MAX_COUNT          60
#define TX_EXTRA_NONCE_MAX_COUNT            60
#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_NONCE_PAYMENT_ID           0x00

struct TransactionExtraPadding {
  size_t size
}

struct TransactionExtraPublicKey {
  Crypto::PublicKey publicKey
}

struct TransactionExtraNonce {
  std::vector<uint8_t> nonce
}

using TransactionExtraField = boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce>

findTransactionExtraFieldByType()
parseTransactionExtra()
writeTransactionExtra()
getTransactionPublicKeyFromExtra()
addTransactionPublicKeyToExtra()
addExtraNonceToTransactionExtra()
setPaymentIdToTransactionExtraNonce()
getPaymentIdFromTransactionExtraNonce()
createTxExtraWithPaymentId()
getPaymentIdFromTxExtra()
parsePaymentId()

*/

uint32_t loopCount = 100;

// findTransactionExtraFieldByType()
// TransactionExtraPadding 1
TEST(TransactionExtra, 1)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraPadding transactionExtraPaddingInput;
  transactionExtraPaddingInput.size = 5;

  transactionExtraFields.push_back(transactionExtraPaddingInput);

  TransactionExtraPadding transactionExtraPaddingOutput;; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraPaddingOutput));

  ASSERT_EQ(transactionExtraPaddingOutput.size, 5);

  ASSERT_NE(&transactionExtraPaddingInput, &transactionExtraPaddingOutput);
}

// findTransactionExtraFieldByType()
// TransactionExtraPadding 2
// find only the first occurrence
TEST(TransactionExtra, 2)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraPadding transactionExtraPaddingInput1;
  transactionExtraPaddingInput1.size = 5;

  TransactionExtraPadding transactionExtraPaddingInput2;
  transactionExtraPaddingInput2.size = 10;

  transactionExtraFields.push_back(transactionExtraPaddingInput1);
  transactionExtraFields.push_back(transactionExtraPaddingInput2);

  TransactionExtraPadding transactionExtraPaddingOutput;; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraPaddingOutput));

  ASSERT_EQ(transactionExtraPaddingOutput.size, 5);

  ASSERT_NE(&transactionExtraPaddingInput1, &transactionExtraPaddingOutput);
}

// findTransactionExtraFieldByType()
// TransactionExtraPublicKey 1
TEST(TransactionExtra, 3)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraPublicKey transactionExtraPublicKeyInput;
  Crypto::PublicKey tempPublicKey = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  transactionExtraPublicKeyInput.publicKey = tempPublicKey;

  transactionExtraFields.push_back(transactionExtraPublicKeyInput);

  TransactionExtraPublicKey transactionExtraPublicKeyOutput; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraPublicKeyOutput));

  size_t publicKeySize = sizeof(tempPublicKey.data) / sizeof(tempPublicKey.data[0]);

  for (size_t i = 0; i < publicKeySize; i++)
  {
    ASSERT_EQ(transactionExtraPublicKeyInput.publicKey.data[i], transactionExtraPublicKeyOutput.publicKey.data[i]);
  }

  ASSERT_NE(&transactionExtraPublicKeyInput, &transactionExtraPublicKeyOutput);
}

// findTransactionExtraFieldByType()
// TransactionExtraPublicKey 2
// find only the first occurrence
TEST(TransactionExtra, 4)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraPublicKey transactionExtraPublicKeyInput1;
  Crypto::PublicKey tempPublicKey1 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  transactionExtraPublicKeyInput1.publicKey = tempPublicKey1;

  TransactionExtraPublicKey transactionExtraPublicKeyInput2;
  Crypto::PublicKey tempPublicKey2 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  transactionExtraPublicKeyInput2.publicKey = tempPublicKey2;

  transactionExtraFields.push_back(transactionExtraPublicKeyInput1);
  transactionExtraFields.push_back(transactionExtraPublicKeyInput2);

  TransactionExtraPublicKey transactionExtraPublicKeyOutput; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraPublicKeyOutput));

  size_t publicKeySize = sizeof(tempPublicKey1.data) / sizeof(tempPublicKey1.data[0]);

  for (size_t i = 0; i < publicKeySize; i++)
  {
    ASSERT_EQ(transactionExtraPublicKeyInput1.publicKey.data[i], transactionExtraPublicKeyOutput.publicKey.data[i]);
  }

  ASSERT_NE(&transactionExtraPublicKeyInput1, &transactionExtraPublicKeyOutput);
}

// findTransactionExtraFieldByType()
// TransactionExtraNonce
TEST(TransactionExtra, 5)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraNonce transactionExtraNonceInput;

  transactionExtraNonceInput.nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

  transactionExtraFields.push_back(transactionExtraNonceInput);

  TransactionExtraNonce transactionExtraNonceOutput; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraNonceOutput));

  for (size_t i = 0; i < transactionExtraNonceInput.nonce.size(); i++)
  {
    ASSERT_EQ(transactionExtraNonceInput.nonce[i], transactionExtraNonceOutput.nonce[i]);
  }

  ASSERT_NE(&transactionExtraNonceInput, &transactionExtraNonceOutput);
}

// findTransactionExtraFieldByType()
// TransactionExtraNonce
// find first occurrence only
TEST(TransactionExtra, 6)
{
  std::vector<TransactionExtraField> transactionExtraFields;

  TransactionExtraNonce transactionExtraNonceInput1;
  transactionExtraNonceInput1.nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

  TransactionExtraNonce transactionExtraNonceInput2;
  transactionExtraNonceInput2.nonce = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19};

  transactionExtraFields.push_back(transactionExtraNonceInput1);
  transactionExtraFields.push_back(transactionExtraNonceInput2);

  TransactionExtraNonce transactionExtraNonceOutput; 

  ASSERT_TRUE(findTransactionExtraFieldByType(transactionExtraFields, transactionExtraNonceOutput));

  for (size_t i = 0; i < transactionExtraNonceInput1.nonce.size(); i++)
  {
    ASSERT_EQ(transactionExtraNonceInput1.nonce[i], transactionExtraNonceOutput.nonce[i]);
  }

  ASSERT_NE(&transactionExtraNonceInput1, &transactionExtraNonceOutput);
}

// parseTransactionExtra()
// transactionExtra empty
TEST(TransactionExtra, 7)
{
  std::vector<uint8_t> transactionExtra;

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(transactionExtraFields.size(), 0);
}

// parseTransactionExtra()
// transactionExtraPadding success
TEST(TransactionExtra, 8)
{
  // 0 signifies transactionExtraPadding
  std::vector<uint8_t> transactionExtra = {0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(transactionExtraFields.size(), 1);
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[0].type());
  ASSERT_EQ(boost::get<TransactionExtraPadding>(transactionExtraFields[0]).size, 1);
}

// parseTransactionExtra()
// transactionExtraPadding success
TEST(TransactionExtra, 9)
{
  std::vector<uint8_t> transactionExtra = {0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(transactionExtraFields.size(), 1);
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[0].type());
  ASSERT_EQ(boost::get<TransactionExtraPadding>(transactionExtraFields[0]).size, 5);
}

// parseTransactionExtra()
// transactionExtraPadding success
// random padding size
TEST(TransactionExtra, 10)
{
  std::vector<uint8_t> transactionExtra;

  uint8_t randPaddingSize = getRandUint8_t() % 10;

  for (uint8_t i = 0; i < randPaddingSize; i++)
  {
    transactionExtra.push_back(0);
  }

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(transactionExtraFields.size(), 1);
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[0].type());
  ASSERT_EQ(boost::get<TransactionExtraPadding>(transactionExtraFields[0]).size, randPaddingSize);
}

// parseTransactionExtra()
// transactionExtraPadding fail
TEST(TransactionExtra, 11)
{
  std::vector<uint8_t> transactionExtra = {0, 1};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  // all values for transactionExtraPadding should be 0
  ASSERT_FALSE(parseTransactionExtra(transactionExtra, transactionExtraFields));
}

// parseTransactionExtra()
// transactionExtraPadding fail
TEST(TransactionExtra, 12)
{
  std::vector<uint8_t> transactionExtra = {0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_FALSE(parseTransactionExtra(transactionExtra, transactionExtraFields));
}

// parseTransactionExtra()
// TransactionExtraPublicKey
TEST(TransactionExtra, 13)
{
  // 1 signifies a TransactionExtraPublicKey
  // the public key is thirty-two 2's
  std::vector<uint8_t> transactionExtra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));
  
  // check that the type returned is TransactionExtraPublicKey
  ASSERT_EQ(typeid(TransactionExtraPublicKey), transactionExtraFields[0].type());

  // get public key length
  TransactionExtraPublicKey transactionExtraPublicKeyOutput = boost::get<TransactionExtraPublicKey>(transactionExtraFields[0]);
  size_t publicKeyLength = sizeof(transactionExtraPublicKeyOutput.publicKey.data) / sizeof(transactionExtraPublicKeyOutput.publicKey.data[0]);

  ASSERT_EQ(32, publicKeyLength);

  for (int i = 0; i < publicKeyLength; i++)
  {
    ASSERT_EQ(2, boost::get<TransactionExtraPublicKey>(transactionExtraFields[0]).publicKey.data[i]);
  }

  // check transactionExtraFields size
  ASSERT_EQ(1, transactionExtraFields.size());
}

// parseTransactionExtra()
// TransactionExtraPublicKey and TransactionExtraPadding
TEST(TransactionExtra, 14)
{
  // 1 signifies a TransactionExtraPublicKey
  // the public key is thirty-two 2's
  // add five 0's on the end
  std::vector<uint8_t> transactionExtra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));
  
  // check transactionExtraFields size
  ASSERT_EQ(2, transactionExtraFields.size());

  // check the types returned
  ASSERT_EQ(typeid(TransactionExtraPublicKey), transactionExtraFields[0].type());
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[1].type());

  // transactionExtraPublicKey
  TransactionExtraPublicKey transactionExtraPublicKey = boost::get<TransactionExtraPublicKey>(transactionExtraFields[0]);
  size_t publicKeyLength = sizeof(transactionExtraPublicKey.publicKey.data) / sizeof(transactionExtraPublicKey.publicKey.data[0]);

  ASSERT_EQ(32, publicKeyLength);

  for (int i = 0; i < publicKeyLength; i++)
  {
    ASSERT_EQ(2, transactionExtraPublicKey.publicKey.data[i]);
  }

  // transactionExtraPadding
  ASSERT_EQ(5, boost::get<TransactionExtraPadding>(transactionExtraFields[1]).size);
}

// parseTransactionExtra()
// TransactionExtraNonce
TEST(TransactionExtra, 15)
{
  // 2 signifies a TransactionExtraNonce
  // 1 tells the size
  // 35 is the value of the nonce
  std::vector<uint8_t> transactionExtra = {2, 1, 35};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(1, transactionExtraFields.size());
  ASSERT_EQ(typeid(TransactionExtraNonce), transactionExtraFields[0].type());

  TransactionExtraNonce transactionExtraNonce = boost::get<TransactionExtraNonce>(transactionExtraFields[0]);

  ASSERT_EQ(1, transactionExtraNonce.nonce.size());
  ASSERT_EQ(35, transactionExtraNonce.nonce[0]);
}

// parseTransactionExtra()
// TransactionExtraNonce
TEST(TransactionExtra, 16)
{
  // 2 signifies a TransactionExtraNonce
  // 10 tells the size
  // {0, 1, 2, 3, 4, 5, 6, 7, 8, 9} is the value of the nonce
  std::vector<uint8_t> transactionExtra = {2, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(1, transactionExtraFields.size());
  ASSERT_EQ(typeid(TransactionExtraNonce), transactionExtraFields[0].type());

  TransactionExtraNonce transactionExtraNonce = boost::get<TransactionExtraNonce>(transactionExtraFields[0]);

  ASSERT_EQ(10, transactionExtraNonce.nonce.size());
  ASSERT_TRUE(std::equal(transactionExtra.begin() + 2, transactionExtra.begin() + 12, transactionExtraNonce.nonce.begin()));
}

// parseTransactionExtra()
// TransactionExtraNonce, then TransactionExtraPublicKey, then TransactionExtraPadding
TEST(TransactionExtra, 17)
{
  // transactionExtra[0] = 2 signifies a TransactionExtraNonce
  // transactionExtra[1] = 10 tells the nonce size
  // transactionExtra[2 - 11] is the value of the nonce
  // transactionExtra[12] = 1 signifies a TransactionExtraPublicKey
  // transactionExtra[13 - 44] is the public key
  // transactionExtra[45] = 0 signifies a TransactionExtraPadding
  // transactionExtra[45 - 49] is the padding
  std::vector<uint8_t> transactionExtra = {2, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(3, transactionExtraFields.size());

  ASSERT_EQ(typeid(TransactionExtraNonce), transactionExtraFields[0].type());
  ASSERT_EQ(typeid(TransactionExtraPublicKey), transactionExtraFields[1].type());
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[2].type());

  TransactionExtraNonce transactionExtraNonce = boost::get<TransactionExtraNonce>(transactionExtraFields[0]);
  ASSERT_EQ(10, transactionExtraNonce.nonce.size());
  ASSERT_TRUE(std::equal(transactionExtra.begin() + 2, transactionExtra.begin() + 12, transactionExtraNonce.nonce.begin()));

  // transactionExtraPublicKey
  TransactionExtraPublicKey transactionExtraPublicKey = boost::get<TransactionExtraPublicKey>(transactionExtraFields[1]);
  size_t publicKeyLength = sizeof(transactionExtraPublicKey.publicKey.data) / sizeof(transactionExtraPublicKey.publicKey.data[0]);

  ASSERT_EQ(32, publicKeyLength);

  for (int i = 0; i < publicKeyLength; i++)
  {
    ASSERT_EQ(2, transactionExtraPublicKey.publicKey.data[i]);
  }

  // transactionExtraPadding
  ASSERT_EQ(5, boost::get<TransactionExtraPadding>(transactionExtraFields[2]).size);
}

// parseTransactionExtra()
// TransactionExtraPublicKey, then TransactionExtraNonce, then TransactionExtraPadding
TEST(TransactionExtra, 18)
{
  // transactionExtra[0] = 1 signifies a TransactionExtraPublicKey
  // transactionExtra[1 - 33] is the public key
  // transactionExtra[34] = 2 signifies a TransactionExtraNonce
  // transactionExtra[35] = 10 tells the nonce size
  // transactionExtra[36 - 45] is the value of the nonce
  // transactionExtra[46] = 0 signifies a TransactionExtraPadding
  // transactionExtra[46 - 49] is the padding
  std::vector<uint8_t> transactionExtra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(3, transactionExtraFields.size());

  ASSERT_EQ(typeid(TransactionExtraPublicKey), transactionExtraFields[0].type());
  ASSERT_EQ(typeid(TransactionExtraNonce), transactionExtraFields[1].type());
  ASSERT_EQ(typeid(TransactionExtraPadding), transactionExtraFields[2].type());

  // transactionExtraPublicKey
  TransactionExtraPublicKey transactionExtraPublicKey = boost::get<TransactionExtraPublicKey>(transactionExtraFields[0]);
  size_t publicKeyLength = sizeof(transactionExtraPublicKey.publicKey.data) / sizeof(transactionExtraPublicKey.publicKey.data[0]);

  ASSERT_EQ(32, publicKeyLength);

  for (int i = 0; i < publicKeyLength; i++)
  {
    ASSERT_EQ(2, transactionExtraPublicKey.publicKey.data[i]);
  }

  // transactionExtraNonce
  TransactionExtraNonce transactionExtraNonce = boost::get<TransactionExtraNonce>(transactionExtraFields[1]);
  ASSERT_EQ(10, transactionExtraNonce.nonce.size());
  ASSERT_TRUE(std::equal(transactionExtra.begin() + 35, transactionExtra.begin() + 45, transactionExtraNonce.nonce.begin()));

  // transactionExtraPadding
  ASSERT_EQ(5, boost::get<TransactionExtraPadding>(transactionExtraFields[2]).size);
}

// writeTransactionExtra()
// transactionExtra empty
TEST(TransactionExtra, 19)
{
  std::vector<uint8_t> transactionExtra;
  std::vector<TransactionExtraField> transactionExtraFields;

  ASSERT_TRUE(writeTransactionExtra(transactionExtra, transactionExtraFields));

  ASSERT_EQ(transactionExtra.size(), 0);
}

// writeTransactionExtra()
// transactionExtraPadding
TEST(TransactionExtra, 20)
{
  std::vector<uint8_t> transactionExtraInput = {0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtraInput, transactionExtraFields));

  std::vector<uint8_t> transactionExtraOutput;

  ASSERT_TRUE(writeTransactionExtra(transactionExtraOutput, transactionExtraFields));

  ASSERT_TRUE(std::equal(transactionExtraOutput.begin(), transactionExtraOutput.end(), transactionExtraInput.begin()));
}

// writeTransactionExtra()
// transactionExtraPadding
TEST(TransactionExtra, 21)
{
  std::vector<uint8_t> transactionExtraInput = {0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtraInput, transactionExtraFields));

  std::vector<uint8_t> transactionExtraOutput;

  ASSERT_TRUE(writeTransactionExtra(transactionExtraOutput, transactionExtraFields));

  ASSERT_TRUE(std::equal(transactionExtraOutput.begin(), transactionExtraOutput.end(), transactionExtraInput.begin()));
}

// writeTransactionExtra()
// transactionExtraPadding
// random
TEST(TransactionExtra, 22)
{
  std::vector<uint8_t> transactionExtraInput;

  uint8_t randPaddingSize = getRandUint8_t() % 10;

  for (uint8_t i = 0; i < randPaddingSize; i++)
  {
    transactionExtraInput.push_back(0);
  }

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtraInput, transactionExtraFields));

  std::vector<uint8_t> transactionExtraOutput;

  ASSERT_TRUE(writeTransactionExtra(transactionExtraOutput, transactionExtraFields));

  ASSERT_TRUE(std::equal(transactionExtraOutput.begin(), transactionExtraOutput.end(), transactionExtraInput.begin()));
}

// writeTransactionExtra()
// TransactionExtraPublicKey
TEST(TransactionExtra, 23)
{
  std::vector<uint8_t> transactionExtraInput = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtraInput, transactionExtraFields));

  std::vector<uint8_t> transactionExtraOutput;

  ASSERT_TRUE(writeTransactionExtra(transactionExtraOutput, transactionExtraFields));

  ASSERT_TRUE(std::equal(transactionExtraOutput.begin(), transactionExtraOutput.end(), transactionExtraInput.begin()));
}

// writeTransactionExtra()
// TransactionExtraPublicKey and TransactionExtraPadding
TEST(TransactionExtra, 24)
{
  std::vector<uint8_t> transactionExtraInput = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0};

  std::vector<TransactionExtraField> transactionExtraFields;
  
  ASSERT_TRUE(parseTransactionExtra(transactionExtraInput, transactionExtraFields));

  std::vector<uint8_t> transactionExtraOutput;

  ASSERT_TRUE(writeTransactionExtra(transactionExtraOutput, transactionExtraFields));

  ASSERT_TRUE(std::equal(transactionExtraOutput.begin(), transactionExtraOutput.end(), transactionExtraInput.begin()));
}

// getTransactionPublicKeyFromExtra()
TEST(TransactionExtra, 25)
{
  // 1 signifies a TransactionExtraPublicKey
  // The public key is thirty-two 2's
  std::vector<uint8_t> transactionExtra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  Crypto::PublicKey publicKey = getTransactionPublicKeyFromExtra(transactionExtra);

  for (int i = 0; i < 32; i++)
  {
    ASSERT_EQ(2, publicKey.data[i]);
  }
}

// getTransactionPublicKeyFromExtra()
TEST(TransactionExtra, 26)
{
  // 1 signifies a TransactionExtraPublicKey
  // The public key is the rest
  std::vector<uint8_t> transactionExtra = {1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

  Crypto::PublicKey publicKey = getTransactionPublicKeyFromExtra(transactionExtra);

  for (int i = 0; i < 32; i++)
  {
    ASSERT_EQ(i, publicKey.data[i]);
  }
}

// addTransactionPublicKeyToExtra() 1
TEST(TransactionExtra, 27)
{
  std::vector<uint8_t> transactionExtra;
  Crypto::PublicKey transactionPublicKey = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  ASSERT_TRUE(addTransactionPublicKeyToExtra(transactionExtra, transactionPublicKey));

  // transactionExtra[0] = 1 signifies a TransactionPublicKey
  ASSERT_EQ(1, transactionExtra[0]);

  for (int i = 1; i < 33; i++)
  {
    ASSERT_EQ(2, transactionExtra[i]);
  }
}

// addTransactionPublicKeyToExtra() 2
TEST(TransactionExtra, 28)
{
  std::vector<uint8_t> transactionExtra;
  Crypto::PublicKey transactionPublicKey = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  ASSERT_TRUE(addTransactionPublicKeyToExtra(transactionExtra, transactionPublicKey));

  ASSERT_EQ(1, transactionExtra[0]);

  for (int i = 1; i < 33; i++)
  {
    ASSERT_EQ(i, transactionExtra[i]);
  }
}

// addExtraNonceToTransactionExtra()
TEST(TransactionExtra, 29)
{
  std::vector<uint8_t> transactionExtra;
  BinaryArray extraNonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  ASSERT_TRUE(addExtraNonceToTransactionExtra(transactionExtra, extraNonce));

  ASSERT_EQ(12, transactionExtra.size());

  // transactionExtra[0] == 2 signifies a TransactionExtraNonce
  ASSERT_EQ(2, transactionExtra[0]);
  // transactionExtra[1] == 10 tells the size of the nonce
  ASSERT_EQ(10, transactionExtra[1]);

  // check nonce value
  for (int i = 1; i < 11; i++)
  {
    ASSERT_EQ(i, transactionExtra[i + 1]);
  }
}

// setPaymentIdToTransactionExtraNonce()
TEST(TransactionExtra, 30)
{
  std::vector<uint8_t> extraNonce;
  Crypto::Hash paymentId = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  setPaymentIdToTransactionExtraNonce(extraNonce, paymentId);

  // extraNonce[0] == 0 signifies TX_EXTRA_NONCE_PAYMENT_ID
  ASSERT_EQ(extraNonce[0], 0);

  // check nonce value
  for (int i = 1; i < 33; i++)
  {
    ASSERT_EQ(extraNonce[i], 1);
  }
}

// setPaymentIdToTransactionExtraNonce()
// random hash
TEST(TransactionExtra, 31)
{
  std::vector<uint8_t> extraNonce;
  Crypto::Hash paymentId = getRandHash();

  setPaymentIdToTransactionExtraNonce(extraNonce, paymentId);

  // extraNonce[0] == 0 signifies TX_EXTRA_NONCE_PAYMENT_ID
  ASSERT_EQ(extraNonce[0], 0);

  // check nonce value
  for (int i = 1; i < 33; i++)
  {
    ASSERT_EQ(extraNonce[i], paymentId.data[i - 1]);
  }
}

// getPaymentIdFromTransactionExtraNonce()
TEST(TransactionExtra, 32)
{
  std::vector<uint8_t> extraNonce = {0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  Crypto::Hash paymentId;

  ASSERT_TRUE(getPaymentIdFromTransactionExtraNonce(extraNonce, paymentId));

  // check value
  for (int i = 0; i < 32; i++)
  {
    ASSERT_EQ(paymentId.data[i], 2);
  }
}

// parsePaymentId()
TEST(TransactionExtra, 33)
{
  Crypto::Hash paymentId;
  std::string paymentIdString = "0202020202020202020202020202020202020202020202020202020202020202";

  // converts paymentId string to paymentId
  ASSERT_TRUE(parsePaymentId(paymentIdString, paymentId));

  Crypto::Hash paymentIdExpected = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}; 

  ASSERT_TRUE(hashesEqual(paymentId, paymentIdExpected));
}

// parsePaymentId()
TEST(TransactionExtra, 34)
{
  Crypto::Hash paymentId;
  std::string paymentIdString = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

  // converts paymentId string to paymentId
  ASSERT_TRUE(parsePaymentId(paymentIdString, paymentId));

  Crypto::Hash paymentIdExpected = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}; 

  ASSERT_TRUE(hashesEqual(paymentId, paymentIdExpected));
}

// createTxExtraWithPaymentId()
TEST(TransactionExtra, 35)
{
  std::string paymentIdString = "0202020202020202020202020202020202020202020202020202020202020202";
  std::vector<uint8_t> extra;

  ASSERT_TRUE(createTxExtraWithPaymentId(paymentIdString, extra));

  // added by addExtraNonceToTransactionExtra
  ASSERT_EQ(TX_EXTRA_NONCE, extra[0]);
  ASSERT_EQ(33, extra[1]);
  // added by setPaymentIdToTransactionExtraNonce
  ASSERT_EQ(TX_EXTRA_NONCE_PAYMENT_ID, extra[2]);

  for (int i = 3; i < extra.size(); i++)
  {
    ASSERT_EQ(2, extra[i]);
  }
}

// createTxExtraWithPaymentId()
TEST(TransactionExtra, 36)
{
  std::string paymentIdString = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
  std::vector<uint8_t> extra;

  ASSERT_TRUE(createTxExtraWithPaymentId(paymentIdString, extra));

  ASSERT_EQ(TX_EXTRA_NONCE, extra[0]);
  ASSERT_EQ(33, extra[1]);
  ASSERT_EQ(TX_EXTRA_NONCE_PAYMENT_ID, extra[2]);

  for (int i = 3; i < extra.size(); i++)
  {
    ASSERT_EQ(i - 3, extra[i]);
  }
}

// getPaymentIdFromTxExtra()
TEST(TransactionExtra, 37)
{
  // extra[0] == 2 means TX_EXTRA_NONCE
  // extra[1] == 33 means the length remaining
  // extra[2] == 0 means TX_EXTRA_NONCE_PAYMENT_ID
  std::vector<uint8_t> extra = {2, 33, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  Crypto::Hash paymentId;

  ASSERT_TRUE(getPaymentIdFromTxExtra(extra, paymentId));

  Crypto::Hash paymentIdExpected = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  ASSERT_TRUE(hashesEqual(paymentId, paymentIdExpected));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}