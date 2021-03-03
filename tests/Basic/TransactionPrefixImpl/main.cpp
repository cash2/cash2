// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/TransactionPrefixImpl.cpp"

using namespace CryptoNote;

/*

My Notes

class TransactionPrefixImpl
public
  *TransactionPrefixImpl()
  *TransactionPrefixImpl()
  ~TransactionPrefixImpl()
  *getTransactionHash()
  *getTransactionPrefixHash()
  *getTransactionPublicKey()
  *getUnlockTime()
  *getPaymentId()
  *getExtraNonce()
  *getExtra()
  *getInputCount()
  *getInputTotalAmount()
  *getInputType()
  *getInput()
  getInput()
  *getOutputCount()
  *getOutputTotalAmount()
  *getOutputType()
  *getOutput()
  getOutput()
  *getRequiredSignaturesCount()
  *findOutputsToAccount()
  *validateInputs()
  *validateOutputs()
  *validateSignatures()
  *getTransactionData()
  *getTransactionSecretKey()

private
  TransactionPrefix m_txPrefix
  TransactionExtra m_extra
  Hash m_txHash

*/

// TransactionPrefixImpl()
TEST(TransactionPrefixImpl, 1)
{
  TransactionPrefixImpl();
}

// TransactionPrefixImpl(TransactionPrefix, transactionHash)
TEST(TransactionPrefixImpl, 2)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl(transactionPrefix, transactionHash);
}

// getTransactionHash()
TEST(TransactionPrefixImpl, 3)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  Crypto::Hash transactionHashRet = transactionPrefixImpl.getTransactionHash();

  ASSERT_TRUE(hashesEqual(transactionHash, transactionHashRet));
}

// getTransactionPrefixHash()
TEST(TransactionPrefixImpl, 4)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  Crypto::Hash transactionPrefixHash = getObjectHash(transactionPrefix);
  Crypto::Hash transactionPrefixHashRet = transactionPrefixImpl.getTransactionPrefixHash();

  ASSERT_TRUE(hashesEqual(transactionPrefixHashRet, transactionPrefixHash));
}

// getTransactionPublicKey()
TEST(TransactionPrefixImpl, 5)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  Crypto::PublicKey transactionPublicKey = getTransactionPublicKeyFromExtra(transaction.extra);

  Crypto::PublicKey transactionPublicKeyRet = transactionPrefixImpl.getTransactionPublicKey();

  ASSERT_TRUE(publicKeysEqual(transactionPublicKey, transactionPublicKeyRet));
}

// getUnlockTime()
TEST(TransactionPrefixImpl, 6)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  uint64_t unlockTime = transactionPrefixImpl.getUnlockTime();

  ASSERT_EQ(transaction.unlockTime, unlockTime);
}

// getPaymentId()
TEST(TransactionPrefixImpl, 7)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  Crypto::Hash paymentId1;
  ASSERT_TRUE(getPaymentIdFromTxExtra(transaction.extra, paymentId1));

  Crypto::Hash paymentId2;
  ASSERT_TRUE(transactionPrefixImpl.getPaymentId(paymentId2));

  ASSERT_TRUE(hashesEqual(paymentId1, paymentId2));
}

// getExtraNonce()
TEST(TransactionPrefixImpl, 8)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  BinaryArray nonce;
  ASSERT_TRUE(transactionPrefixImpl.getExtraNonce(nonce));

//  nonce =
//    {
//      0x0, 0x8, 0x7e, 0xc6, 0x6b, 0x3c, 0xdd, 0xa0, 0xb, 0x4,
//      0x3, 0x93, 0x31, 0xf1, 0x8c, 0x41, 0x50, 0x5f, 0xf5, 0xd,
//      0x72, 0x39, 0x15, 0xf1, 0xd, 0xe5, 0x46, 0xe1, 0x13, 0xe8,
//      0xb6, 0x59, 0x57
//    }

  ASSERT_TRUE(std::equal(transaction.extra.begin() + 2, transaction.extra.end(), nonce.begin()));

//  transaction.extra =
//    {
//      0x2, 0x21, 0x0, 0x8, 0x7e, 0xc6, 0x6b, 0x3c, 0xdd, 0xa0, 
//      0xb, 0x4, 0x3, 0x93, 0x31, 0xf1, 0x8c, 0x41, 0x50, 0x5f,
//      0xf5, 0xd, 0x72, 0x39, 0x15, 0xf1, 0xd, 0xe5, 0x46, 0xe1,
//      0x13, 0xe8, 0xb6, 0x59, 0x57
//    }

}

// getExtra()
TEST(TransactionPrefixImpl, 9)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  BinaryArray transactionExtraRet = transactionPrefixImpl.getExtra();

  ASSERT_TRUE(std::equal(transaction.extra.begin(), transaction.extra.end(), transactionExtraRet.begin()));
}

// getInputCount()
TEST(TransactionPrefixImpl, 10)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  size_t inputCount = transactionPrefixImpl.getInputCount();

  ASSERT_EQ(transaction.inputs.size(), inputCount);
}

// getInputTotalAmount()
TEST(TransactionPrefixImpl, 11)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  uint64_t inputTotalAmount1 = transactionPrefixImpl.getInputTotalAmount();

  uint64_t inputTotalAmount2 = 0;
  // start at index 1 to skip the coinbase input
  for (int i = 1; i < transaction.inputs.size(); i++)
  {
    KeyInput keyInput = boost::get<KeyInput>(transaction.inputs[i]);
    inputTotalAmount2 += keyInput.amount;
  }

  ASSERT_EQ(inputTotalAmount1, inputTotalAmount2);
}

// getInputType()
TEST(TransactionPrefixImpl, 12)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  size_t index = 0;
  TransactionTypes::InputType inputType = transactionPrefixImpl.getInputType(index);
  // first input is the coinbase input
  // I don't know why base input equals Generating
  ASSERT_EQ(inputType, TransactionTypes::InputType::Generating);

  for (index = 1; index < transaction.inputs.size(); index++)
  {
    inputType = transactionPrefixImpl.getInputType(index);
    ASSERT_EQ(TransactionTypes::InputType::Key, inputType);
  }
}

// getInput()
TEST(TransactionPrefixImpl, 13)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  for (size_t i = 1; i < transaction.inputs.size(); i++)
  {
    KeyInput keyInput1;
    transactionPrefixImpl.getInput(i, keyInput1);
    Crypto::Hash keyInputHash1 = getObjectHash(keyInput1);

    KeyInput keyInput2 = boost::get<KeyInput>(transaction.inputs[i]);
    Crypto::Hash keyInputHash2 = getObjectHash(keyInput2);

    ASSERT_TRUE(hashesEqual(keyInputHash1, keyInputHash2));
  } 
}

// getOutputCount()
TEST(TransactionPrefixImpl, 14)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  size_t outputCount = transactionPrefixImpl.getOutputCount();

  ASSERT_EQ(transaction.outputs.size(), outputCount);
}

// getOutputTotalAmount()
TEST(TransactionPrefixImpl, 15)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  uint64_t outputTotalAmount1 = transactionPrefixImpl.getOutputTotalAmount();

  uint64_t outputTotalAmount2 = 0;
  for (int i = 0; i < transaction.outputs.size(); i++)
  {
    TransactionOutput transactionOutput = transaction.outputs[i];
    outputTotalAmount2 += transactionOutput.amount;
  }

  ASSERT_EQ(outputTotalAmount1, outputTotalAmount2);
}

// getOutputType()
TEST(TransactionPrefixImpl, 16)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  for (size_t index = 0; index < transaction.outputs.size(); index++)
  {
    TransactionTypes::OutputType outputType = transactionPrefixImpl.getOutputType(index);
    ASSERT_EQ(TransactionTypes::OutputType::Key, outputType);
  }
}

// getOutput()
TEST(TransactionPrefixImpl, 17)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  for (size_t i = 0; i < transaction.outputs.size(); i++)
  {
    KeyOutput keyOutput1;
    uint64_t amountIgnore;
    transactionPrefixImpl.getOutput(i, keyOutput1, amountIgnore);
    Crypto::Hash keyOutputHash1 = getObjectHash(keyOutput1);

    KeyOutput keyOutput2 = boost::get<KeyOutput>(transaction.outputs[i].target);
    Crypto::Hash keyOutputHash2 = getObjectHash(keyOutput2);

    ASSERT_TRUE(hashesEqual(keyOutputHash1, keyOutputHash2));
  } 
}

// getRequiredSignaturesCount()
TEST(TransactionPrefixImpl, 18)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  // start at 1 to skip the coinbase input
  for (int i = 1; i < transaction.inputs.size(); i++)
  {
    size_t requiredSignaturesCount = transactionPrefixImpl.getRequiredSignaturesCount(i);
    KeyInput keyInput = boost::get<KeyInput>(transaction.inputs[i]);
    ASSERT_EQ(keyInput.outputIndexes.size(), requiredSignaturesCount);  // should be equal to 1 based on how getRandTransaction is defined
  }
  
}

// findOutputsToAccount()
TEST(TransactionPrefixImpl, 19)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;
  Crypto::SecretKey viewSecretKey = viewKeyPair.secretKey;
  std::vector<uint32_t> outs;
  uint64_t outputAmount;
  ASSERT_TRUE(transactionPrefixImpl.findOutputsToAccount(accountPublicAddress, viewSecretKey, outs, outputAmount));

  ASSERT_EQ(0, outs.size());
  ASSERT_EQ(0, outputAmount);
}

// validateInputs()
TEST(TransactionPrefixImpl, 20)
{
  Transaction transaction = getRandTransaction2();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  ASSERT_TRUE(transactionPrefixImpl.validateInputs());
}

// validateOutputs()
TEST(TransactionPrefixImpl, 21)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  ASSERT_TRUE(transactionPrefixImpl.validateOutputs());
}

// validateSignatures()
TEST(TransactionPrefixImpl, 22)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  ASSERT_ANY_THROW(transactionPrefixImpl.validateSignatures());
}

// getTransactionData()
TEST(TransactionPrefixImpl, 23)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  ASSERT_NO_THROW(transactionPrefixImpl.getTransactionData());
}

// getTransactionSecretKey()
TEST(TransactionPrefixImpl, 24)
{
  Transaction transaction = getRandTransaction();

  TransactionPrefix transactionPrefix = transaction;
  Crypto::Hash transactionHash = getObjectHash(transaction);
  TransactionPrefixImpl transactionPrefixImpl(transactionPrefix, transactionHash);

  Crypto::SecretKey secretKey;

  ASSERT_FALSE(transactionPrefixImpl.getTransactionSecretKey(secretKey));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}