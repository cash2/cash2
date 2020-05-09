// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteConfig.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

checkInputsKeyimagesDiff()
getRequiredSignaturesCount()
getTransactionInputAmount()
getTransactionInputType()
getInputChecked()
getInputChecked()
isOutToKey()
getTransactionOutputType()
getOutputChecked()
getOutputChecked()
findOutputsToAccount()

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

typedef boost::variant<BaseInput, KeyInput, MultisignatureInput> TransactionInput;

struct KeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  Crypto::KeyImage keyImage;
};

struct KeyImage {
  uint8_t data[32];
};

struct MultisignatureInput {
  uint64_t amount;
  uint8_t signatureCount;
  uint32_t outputIndex;
};

*/

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

uint32_t loopCount = 100;

// checkInputsKeyimagesDiff
TEST(transactionUtils, 1)
{
  Transaction transaction;

  ASSERT_TRUE(checkInputsKeyimagesDiff(transaction));

  for (uint32_t i = 0; i < loopCount; i++)
  {
    KeyInput keyInput;
    keyInput.amount = getRandUint64_t();

    uint8_t numOutputIndexes = getRandUint8_t();

    for (uint8_t j = 0; j < numOutputIndexes; j++)
    {
      keyInput.outputIndexes.push_back(getRandUint32_t());
    }

    keyInput.keyImage = getRandKeyImage();

    transaction.inputs.push_back(keyInput);

    ASSERT_TRUE(checkInputsKeyimagesDiff(transaction));
  }
}

// getRequiredSignaturesCount()
// keyInput
TEST(transactionUtils, 2)
{
  KeyInput keyInput;

  uint8_t numOutputIndexes = getRandUint8_t();

  for (uint8_t j = 0; j < numOutputIndexes; j++)
  {
    keyInput.outputIndexes.push_back(getRandUint32_t());
  }

  size_t requiredSignatureCount = getRequiredSignaturesCount(keyInput);

  ASSERT_EQ(requiredSignatureCount, numOutputIndexes);
}

// getRequiredSignaturesCount()
// MultisignatureInput
TEST(transactionUtils, 3)
{
  MultisignatureInput multisignatureInput;

  multisignatureInput.signatureCount = getRandUint8_t();

  size_t requiredSignatureCount = getRequiredSignaturesCount(multisignatureInput);

  ASSERT_EQ(requiredSignatureCount, multisignatureInput.signatureCount);
}

// getTransactionInputAmount()
// keyInput
TEST(transactionUtils, 4)
{
  KeyInput keyInput;

  keyInput.amount = getRandUint64_t();

  size_t transactionInputAmount = getTransactionInputAmount(keyInput);

  ASSERT_EQ(transactionInputAmount, keyInput.amount);
}

// getTransactionInputAmount()
// MultisignatureInput
TEST(transactionUtils, 5)
{
  MultisignatureInput multisignatureInput;

  multisignatureInput.amount = getRandUint64_t();

  size_t transactionInputAmount = getTransactionInputAmount(multisignatureInput);

  ASSERT_EQ(transactionInputAmount, multisignatureInput.amount);
}

// getTransactionInputType()
// KeyInput
TEST(transactionUtils, 6)
{
  KeyInput keyInput;

  TransactionTypes::InputType transactionInputType = getTransactionInputType(keyInput);

  ASSERT_EQ(transactionInputType, TransactionTypes::InputType::Key);
}

// getTransactionInputType()
// MultisignatureInput
TEST(transactionUtils, 7)
{
  MultisignatureInput multisignatureInput;

  TransactionTypes::InputType transactionInputType = getTransactionInputType(multisignatureInput);

  ASSERT_EQ(transactionInputType, TransactionTypes::InputType::Multisignature);
}

// getTransactionInputType()
// BaseInput
TEST(transactionUtils, 8)
{
  BaseInput baseInput;

  TransactionTypes::InputType transactionInputType = getTransactionInputType(baseInput);

  ASSERT_EQ(transactionInputType, TransactionTypes::InputType::Generating);
}

// getInputChecked()
// KeyInput
TEST(transactionUtils, 9)
{
  Transaction transaction;

  std::vector<KeyInput> keyInputs;

  for (uint32_t i = 0; i < loopCount; i++)
  {
    KeyInput keyInput;

    keyInput.amount = getRandUint64_t();
    keyInput.keyImage = getRandKeyImage();

    uint8_t randNumOutputIndexes = getRandUint8_t();
    for (uint8_t j = 0; j < randNumOutputIndexes; j++)
    {
      keyInput.outputIndexes.push_back(getRandUint32_t());
    }

    keyInputs.push_back(keyInput);

    transaction.inputs.push_back(keyInput);
  }

  for (uint32_t i = 0; i < keyInputs.size(); i++)
  {
    TransactionInput transactionInput = getInputChecked(transaction, i);

    KeyInput keyInput = boost::get<KeyInput>(transactionInput);

    // check amounts are equal
    ASSERT_EQ(keyInput.amount, keyInputs[i].amount);
    // check outputIndexes are equal
    ASSERT_TRUE(std::equal(keyInput.outputIndexes.begin(), keyInput.outputIndexes.end(), keyInputs[i].outputIndexes.begin()));
    // check keyImages are equal
    for (uint8_t j = 0; j < 32; j++)
    {
      ASSERT_EQ(keyInput.keyImage.data[j], keyInputs[i].keyImage.data[j]);
    }
  }

  for (uint32_t i = 1; i < loopCount; i++)
  {
    // check index
    ASSERT_ANY_THROW(getInputChecked(transaction, keyInputs.size() + i));

    // check input type
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Multisignature));
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Generating));
  }
}

// getInputChecked()
// MultisignatureInput
TEST(transactionUtils, 10)
{
  Transaction transaction;

  std::vector<MultisignatureInput> multisignatureInputs;

  for (uint32_t i = 0; i < loopCount; i++)
  {
    MultisignatureInput multisignatureInput;

    multisignatureInput.amount = getRandUint64_t();
    multisignatureInput.signatureCount = getRandUint8_t();
    multisignatureInput.outputIndex = getRandUint32_t();

    multisignatureInputs.push_back(multisignatureInput);

    transaction.inputs.push_back(multisignatureInput);
  }

  for (uint32_t i = 0; i < multisignatureInputs.size(); i++)
  {
    TransactionInput transactionInput = getInputChecked(transaction, i);

    MultisignatureInput multisignatureInput = boost::get<MultisignatureInput>(transactionInput);

    // check amounts are equal
    ASSERT_EQ(multisignatureInput.amount, multisignatureInputs[i].amount);
    // check signatureCount are equal
    ASSERT_EQ(multisignatureInput.signatureCount, multisignatureInputs[i].signatureCount);
    // check outputIndex are equal
    ASSERT_EQ(multisignatureInput.outputIndex, multisignatureInputs[i].outputIndex);
  }

  for (uint32_t i = 1; i < loopCount; i++)
  {
    // check index
    ASSERT_ANY_THROW(getInputChecked(transaction, multisignatureInputs.size() + i));

    // check input type
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Key));
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Generating));
  }
}

// getInputChecked()
// BaseInput
TEST(transactionUtils, 11)
{
  Transaction transaction;

  std::vector<BaseInput> baseInputs;

  for (uint32_t i = 0; i < loopCount; i++)
  {
    BaseInput baseInput;

    baseInput.blockIndex = getRandUint32_t();

    baseInputs.push_back(baseInput);

    transaction.inputs.push_back(baseInput);
  }

  for (uint32_t i = 0; i < baseInputs.size(); i++)
  {
    TransactionInput transactionInput = getInputChecked(transaction, i);

    BaseInput baseInput = boost::get<BaseInput>(transactionInput);

    // check blockIndex are equal
    ASSERT_EQ(baseInput.blockIndex, baseInputs[i].blockIndex);
  }

  for (uint32_t i = 1; i < loopCount; i++)
  {
    // check index
    ASSERT_ANY_THROW(getInputChecked(transaction, baseInputs.size() + i));

    // check input type
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Key));
    ASSERT_ANY_THROW(getInputChecked(transaction, i, TransactionTypes::InputType::Multisignature));
  }
}

// getTransactionOutputType()
// keyOutput
TEST(transactionUtils, 12)
{
  KeyOutput keyOutput;

  TransactionTypes::OutputType transactionOutputType = getTransactionOutputType(keyOutput);

  ASSERT_EQ(transactionOutputType, TransactionTypes::OutputType::Key);
}

// getTransactionOutputType()
// MultisignatureOutput
TEST(transactionUtils, 13)
{
  MultisignatureOutput multisignatureOutput;

  TransactionTypes::OutputType transactionOutputType = getTransactionOutputType(multisignatureOutput);

  ASSERT_EQ(transactionOutputType, TransactionTypes::OutputType::Multisignature);
}

// getTransactionOutputType()
// KeyOutput
TEST(transactionUtils, 14)
{
  KeyOutput keyOutput;

  TransactionTypes::OutputType transactionOutputType = getTransactionOutputType(keyOutput);

  ASSERT_EQ(transactionOutputType, TransactionTypes::OutputType::Key);
}

// getTransactionOutputType()
// MultisignatureOutput
TEST(transactionUtils, 15)
{
  MultisignatureOutput multisignatureOutput;

  TransactionTypes::OutputType transactionOutputType = getTransactionOutputType(multisignatureOutput);

  ASSERT_EQ(transactionOutputType, TransactionTypes::OutputType::Multisignature);
}

// getOutputChecked()
// KeyOutput
TEST(transactionUtils, 16)
{
  Transaction transaction;

  std::vector<KeyOutput> keyOutputs;

  for (uint32_t i = 0; i < loopCount; i++)
  {
    TransactionOutput transactionOutput;

    KeyOutput keyOutput;

    keyOutput.key = getRandPublicKey();

    keyOutputs.push_back(keyOutput);

    transactionOutput.target = keyOutput;

    transaction.outputs.push_back(transactionOutput);
  }

  for (uint32_t i = 0; i < keyOutputs.size(); i++)
  {
    TransactionOutput transactionOutput = getOutputChecked(transaction, i);

    KeyOutput keyOutput = boost::get<KeyOutput>(transactionOutput.target);

    // check KeyOutput public keys are equal
    for (uint8_t j = 0; j < 32; j++)
    {
      ASSERT_EQ(keyOutput.key.data[j], keyOutputs[i].key.data[j]);
    }
  }

  for (uint32_t i = 1; i < loopCount; i++)
  {
    // check index
    ASSERT_ANY_THROW(getOutputChecked(transaction, keyOutputs.size() + i));

    // check input type
    ASSERT_ANY_THROW(getOutputChecked(transaction, i, TransactionTypes::OutputType::Multisignature));
  }
}

// getOutputChecked()
// MultisignatureOutput
TEST(transactionUtils, 17)
{
  Transaction transaction;

  std::vector<MultisignatureOutput> multisignatureOutputs;

  uint8_t randNumPublicKeys = getRandUint8_t();

  for (uint32_t i = 0; i < loopCount; i++)
  {
    TransactionOutput transactionOutput;

    MultisignatureOutput multisignatureOutput;

    multisignatureOutput.requiredSignatureCount = getRandUint8_t();

    for (uint8_t j = 0; j < randNumPublicKeys; j++)
    {
      multisignatureOutput.keys.push_back(getRandPublicKey());
    }

    multisignatureOutputs.push_back(multisignatureOutput);

    transactionOutput.target = multisignatureOutput;

    transaction.outputs.push_back(transactionOutput);
  }

  for (uint32_t i = 0; i < multisignatureOutputs.size(); i++)
  {
    TransactionOutput transactionOutput = getOutputChecked(transaction, i);

    MultisignatureOutput multisignatureOutput = boost::get<MultisignatureOutput>(transactionOutput.target);

    // check MultisignatureOutput requiredSignatureCounts are equal
    ASSERT_EQ(multisignatureOutput.requiredSignatureCount, multisignatureOutputs[i].requiredSignatureCount);

    // check MultisignatureOutput public keys are equal
    for (uint8_t j = 0; j < randNumPublicKeys; j++)
    {
      for (uint8_t k = 0; k < 32; k++)
      {
        ASSERT_EQ(multisignatureOutput.keys[j].data[k], multisignatureOutputs[i].keys[j].data[k]);
      }
    }
  }

  for (uint32_t i = 1; i < loopCount; i++)
  {
    // check index
    ASSERT_ANY_THROW(getOutputChecked(transaction, multisignatureOutputs.size() + i));

    // check input type
    ASSERT_ANY_THROW(getOutputChecked(transaction, i, TransactionTypes::OutputType::Key));
  }
}

// isOutToKey()
TEST(transactionUtils, 18)
{
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;

  Crypto::KeyDerivation derivation;
  generate_key_derivation(transactionPublicKey, viewKeyPair.secretKey, derivation);

  Crypto::PublicKey keyOutputPublicKey;
  size_t keyOutputIndex = 0;
  derive_public_key(derivation, keyOutputIndex, spendKeyPair.publicKey, keyOutputPublicKey);

  ASSERT_TRUE(isOutToKey(spendKeyPair.publicKey, keyOutputPublicKey, derivation, keyOutputIndex));
}

// findOutputsToAccount()
TEST(transactionUtils, 19)
{
  Transaction transaction;

  // set up account keys
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys accountKeys;

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  // get key output one-time public key
  KeyPair transactionKeyPair = generateKeyPair();

  Crypto::KeyDerivation derivation;
  generate_key_derivation(accountKeys.address.viewPublicKey, transactionKeyPair.secretKey, derivation);

  Crypto::PublicKey keyOutputOneTimePublicKey;
  size_t keyOutputIndex = 0;

  derive_public_key(derivation, keyOutputIndex, accountKeys.address.spendPublicKey, keyOutputOneTimePublicKey);

  KeyOutput keyOutput;
  keyOutput.key = keyOutputOneTimePublicKey;

  TransactionOutput transactionOutput;

  transactionOutput.amount = 100;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // add transaction public key to transaction.extra

  // 1 signifies a transaction public key
  transaction.extra.push_back(1);

  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionKeyPair.publicKey.data[i]);
  }

  std::vector<uint32_t> outputIndexes;
  uint64_t amount;

  ASSERT_TRUE(findOutputsToAccount(transaction, accountKeys.address, accountKeys.viewSecretKey, outputIndexes, amount));
  
  // check amount
  ASSERT_EQ(amount, 100);
  // check output size
  ASSERT_EQ(outputIndexes.size(), 1);
  ASSERT_EQ(keyOutputIndex, outputIndexes[0]);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}