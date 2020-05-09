// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/Transaction.cpp"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

derivePublicKey()

class TransactionImpl {
public
  TransactionImpl()
  TransactionImpl()
  TransactionImpl()
  getTransactionHash()
  getTransactionPrefixHash()
  getTransactionPublicKey()
  getUnlockTime()
  getPaymentId()
  getExtraNonce()
  getExtra()
  getInputCount()
  getInputTotalAmount()
  getInputType()
  getInput()
  getInput()
  getOutputCount()
  getOutputTotalAmount()
  getOutputType()
  getOutput()
  getOutput()
  getRequiredSignaturesCount()
  findOutputsToAccount()
  validateInputs()
  validateOutputs()
  validateSignatures()
  getTransactionData()
  setUnlockTime()
  setPaymentId()
  setExtraNonce()
  appendExtra()
  addInput()
  addInput()
  addInput()
  addOutput()
  addOutput()
  addOutput()
  addOutput()
  signInputKey()
  signInputMultisignature()
  signInputMultisignature()
  getTransactionSecretKey()
  setTransactionSecretKey()
private
  invalidateHash()
  getSignatures()
  txSecretKey()
  checkIfSigning()

  CryptoNote::Transaction transaction
  boost::optional<SecretKey> secretKey
  mutable boost::optional<Hash> transactionHash
  TransactionExtra extra
}

createTransaction()
createTransaction()
createTransaction()
TransactionImpl()
TransactionImpl()
TransactionImpl()
invalidateHash()
getTransactionHash()
getTransactionPrefixHash()
getTransactionPublicKey()
getUnlockTime()
setUnlockTime()
getTransactionSecretKey()
setTransactionSecretKey()
addInput()
addInput()
addInput()
addOutput()
addOutput()
addOutput()
addOutput()
signInputKey()
signInputMultisignature()
signInputMultisignature()
getSignatures()
getTransactionData()
setPaymentId()
getPaymentId()
setExtraNonce()
appendExtra()
getExtraNonce()
getExtra()
getInputCount()
getInputTotalAmount()
getInputType()
getInput()
getInput()
getOutputCount()
getOutputTotalAmount()
getOutputType()
getOutput()
getOutput()
findOutputsToAccount()
getRequiredSignaturesCount()
validateInputs()
validateOutputs()
validateSignatures()

struct TransactionPrefix {
  uint8_t version
  uint64_t unlockTime
  std::vector<TransactionInput> inputs
  std::vector<TransactionOutput> outputs
  std::vector<uint8_t> extra
}

struct Transaction : public TransactionPrefix {
  std::vector<std::vector<Crypto::Signature>> signatures
}

struct GlobalOutput {
  Crypto::PublicKey targetKey
  uint32_t outputIndex
}

typedef std::vector<GlobalOutput> GlobalOutputsContainer

struct OutputKeyInfo {
  Crypto::PublicKey transactionPublicKey
  size_t transactionIndex
  size_t outputInTransaction
}

struct InputKeyInfo {
  uint64_t amount
  GlobalOutputsContainer outputs
  OutputKeyInfo realOutput
}

struct Signature {
  uint8_t data[64]
}

void derivePublicKey(const AccountPublicAddress& to, const SecretKey& txKey, size_t outputIndex, PublicKey& ephemeralKey) {
  KeyDerivation derivation;
  generate_key_derivation(to.viewPublicKey, txKey, derivation);
  derive_public_key(derivation, outputIndex, to.spendPublicKey, ephemeralKey);
}

struct KeyDerivation {
  uint8_t data[32]
}

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey
  Crypto::PublicKey viewPublicKey
}

struct KeyInput {
  uint64_t amount
  std::vector<uint32_t> outputIndexes
  Crypto::KeyImage keyImage
}

struct KeyOutput {
  Crypto::PublicKey key
}

*/

uint32_t loopCount = 100;

// TransactionImpl()
TEST(Transaction, 1)
{
  TransactionImpl();
}

// TransactionImpl(binaryArray)
TEST(Transaction, 2)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  BinaryArray binaryArray;

  ASSERT_TRUE(toBinaryArray(transaction, binaryArray));

  TransactionImpl transactionImpl(binaryArray);
}

// TransactionImpl(transaction)
TEST(Transaction, 3)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  TransactionImpl transactionImpl(transaction);
}

// getTransactionHash()
TEST(Transaction, 4)
{
  Transaction transaction = getBasicTransaction();

  TransactionImpl transactionImpl(transaction);

  Crypto::Hash transactionHash = getObjectHash(transaction);

  Crypto::Hash transactionHashOutput = transactionImpl.getTransactionHash();

  ASSERT_TRUE(hashesEqual(transactionHash, transactionHashOutput));
}

// getTransactionPrefixHash()
TEST(Transaction, 5)
{
  Transaction transaction = getBasicTransaction();

  TransactionImpl transactionImpl(transaction);

  // commented out to suppress unused variable warning
  // Crypto::Hash txPrefixHash = transactionImpl.getTransactionPrefixHash();
}

// getTransactionPublicKey
TEST(Transaction, 6)
{
  Transaction transaction;

  transaction.extra = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

  TransactionImpl transactionImpl(transaction);

  Crypto::PublicKey publicKey = transactionImpl.getTransactionPublicKey();

  for (int i = 0; i < 32; ++i)
  {
    ASSERT_EQ(2, publicKey.data[i]);
  }
}

// getTransactionPublicKey
TEST(Transaction, 7)
{
  Transaction transaction;

  transaction.unlockTime = 1;

  TransactionImpl transactionImpl(transaction);

  uint64_t unlockTime = transactionImpl.getUnlockTime();

  ASSERT_EQ(1, unlockTime);
}

// setUnlockTime()
TEST(Transaction, 8)
{
  Transaction transaction;

  transaction.unlockTime = 1;

  TransactionImpl transactionImpl(transaction);

  transactionImpl.setUnlockTime(50);

  uint64_t unlockTime = transactionImpl.getUnlockTime();

  ASSERT_EQ(50, unlockTime);
}

// getTransactionSecretKey()
// fail 1
TEST(Transaction, 9)
{
  Transaction transaction = getBasicTransaction();

  TransactionImpl transactionImpl(transaction);

  SecretKey secretKey;

  // secretKey member variable was not initialized by the constructor
  ASSERT_FALSE(transactionImpl.getTransactionSecretKey(secretKey));
}

// getTransactionSecretKey()
// fail 2
TEST(Transaction, 10)
{
  Transaction transaction = getBasicTransaction();

  BinaryArray binaryArray = toBinaryArray(transaction);

  TransactionImpl transactionImpl(binaryArray);

  SecretKey secretKey;

  // secretKey member variable was not initialized by the constructor
  ASSERT_FALSE(transactionImpl.getTransactionSecretKey(secretKey));
}

// getTransactionSecretKey()
// success
TEST(Transaction, 11)
{
  TransactionImpl transactionImpl;

  SecretKey secretKey;

  ASSERT_TRUE(transactionImpl.getTransactionSecretKey(secretKey));
}

// setTransactionSecretKey()
// success
TEST(Transaction, 12)
{
  Transaction transaction;

  KeyPair transactionKeyPair = generateKeyPair();

  // add public key to transaction extra
  transaction.extra.push_back(1);

  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionKeyPair.publicKey.data[i]);
  }

  TransactionImpl transactionImpl(transaction);

  ASSERT_NO_THROW(transactionImpl.setTransactionSecretKey(transactionKeyPair.secretKey));
}

// setTransactionSecretKey()
// fail
TEST(Transaction, 13)
{
  Transaction transaction;

  KeyPair transactionKeyPair = generateKeyPair();

  // add public key to transaction extra
  transaction.extra.push_back(1);

  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(2);
  }

  TransactionImpl transactionImpl(transaction);

  ASSERT_ANY_THROW(transactionImpl.setTransactionSecretKey(transactionKeyPair.secretKey));
}

// addInput(keyInput)
TEST(Transaction, 14)
{
  TransactionImpl transactionImpl;

  KeyInput keyInput;
  keyInput.amount = 100;
  keyInput.outputIndexes = {50};

  Crypto::KeyImage keyImage = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  keyInput.keyImage = keyImage;

  size_t index = transactionImpl.addInput(keyInput);

  ASSERT_EQ(0, index);
}

// addInput(keyInput) fail
// checkIfSigning() throws error
TEST(Transaction, 15)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  std::vector<Crypto::Signature> temp;
  temp.push_back(getRandSignature());
  transaction.signatures.push_back(temp);

  TransactionImpl transactionImpl(transaction);

  KeyInput keyInput;
  keyInput.amount = 100;
  keyInput.outputIndexes = {50};

  Crypto::KeyImage keyImage = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  keyInput.keyImage = keyImage;

  ASSERT_ANY_THROW(transactionImpl.addInput(keyInput));

  // ASSERT_EQ(0, index);
}

// addInput(senderKeys, info, ephKeys)
TEST(Transaction, 16)
{
  TransactionImpl transactionImpl;

  // sender keys
  AccountKeys senderKeys;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  senderKeys.address.viewPublicKey = viewKeyPair.publicKey;
  senderKeys.viewSecretKey = viewKeyPair.secretKey;
  senderKeys.address.spendPublicKey = spendKeyPair.publicKey;
  senderKeys.spendSecretKey = spendKeyPair.secretKey;

  // input key info
  TransactionTypes::InputKeyInfo inputKeyInfo;
  inputKeyInfo.amount = 10;

  KeyPair transactionKeyPair = generateKeyPair();

  inputKeyInfo.realOutput.transactionPublicKey = transactionKeyPair.publicKey;
  inputKeyInfo.realOutput.outputInTransaction = 0;

  // ephemeral keys
  KeyPair ephemeralKeys = generateKeyPair();

  size_t index = transactionImpl.addInput(senderKeys, inputKeyInfo, ephemeralKeys);

  ASSERT_EQ(0, index);
}

// addInput(senderKeys, info, ephKeys) fail
// checkIfSigning() throws error
TEST(Transaction, 17)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  std::vector<Crypto::Signature> temp;
  temp.push_back(getRandSignature());
  transaction.signatures.push_back(temp);

  TransactionImpl transactionImpl(transaction);

  // sender keys
  AccountKeys senderKeys;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  senderKeys.address.viewPublicKey = viewKeyPair.publicKey;
  senderKeys.viewSecretKey = viewKeyPair.secretKey;
  senderKeys.address.spendPublicKey = spendKeyPair.publicKey;
  senderKeys.spendSecretKey = spendKeyPair.secretKey;

  // input key info
  TransactionTypes::InputKeyInfo inputKeyInfo;
  inputKeyInfo.amount = 10;

  KeyPair transactionKeyPair = generateKeyPair();

  inputKeyInfo.realOutput.transactionPublicKey = transactionKeyPair.publicKey;
  inputKeyInfo.realOutput.outputInTransaction = 0;

  // ephemeral keys
  KeyPair ephemeralKeys = generateKeyPair();

  ASSERT_ANY_THROW(transactionImpl.addInput(senderKeys, inputKeyInfo, ephemeralKeys));
}

// addInput(multisignatureInput)
TEST(Transaction, 18)
{
  TransactionImpl transactionImpl;

  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.signatureCount = 3;
  multisignatureInput.outputIndex = 0;

  size_t index = transactionImpl.addInput(multisignatureInput);

  ASSERT_EQ(0, index);
}

// addInput(multisignatureInput) fail
// checkIfSigning() throws error
TEST(Transaction, 19)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  std::vector<Crypto::Signature> temp;
  temp.push_back(getRandSignature());
  transaction.signatures.push_back(temp);

  TransactionImpl transactionImpl(transaction);

  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.signatureCount = 3;
  multisignatureInput.outputIndex = 0;

  ASSERT_ANY_THROW(transactionImpl.addInput(multisignatureInput));
}

// addOutput(amount, toAddress)
TEST(Transaction, 20)
{
  TransactionImpl transactionImpl;

  uint64_t amount = 10;

  AccountPublicAddress receiverAddress;
  receiverAddress.viewPublicKey = getRandPublicKey();
  receiverAddress.spendPublicKey = getRandPublicKey();

  size_t index = transactionImpl.addOutput(amount, receiverAddress);

  ASSERT_EQ(0, index);
}

// addOutput(amount, std::vector<AccountPublicAddress>, requiredSignatures)
TEST(Transaction, 21)
{
  TransactionImpl transactionImpl;

  uint64_t amount = 10;

  std::vector<AccountPublicAddress> receiversAddresses;
  AccountPublicAddress receiverAddress;
  receiverAddress.viewPublicKey = getRandPublicKey();
  receiverAddress.spendPublicKey = getRandPublicKey();
  receiversAddresses.push_back(receiverAddress);

  uint32_t numRequiredSignatures = 2;

  size_t index = transactionImpl.addOutput(amount, receiversAddresses, numRequiredSignatures);

  ASSERT_EQ(0, index);
}

// addOutput(amount, keyOutput)
TEST(Transaction, 22)
{
  TransactionImpl transactionImpl;

  uint64_t amount = 10;

  KeyOutput keyOutput;
  keyOutput.key = getRandPublicKey();

  size_t index = transactionImpl.addOutput(amount, keyOutput);

  ASSERT_EQ(0, index);
}

// addOutput(amount, multisignatureOutput)
TEST(Transaction, 23)
{
  TransactionImpl transactionImpl;

  uint64_t amount = 10;

  MultisignatureOutput multisignatureOutput;

  size_t index = transactionImpl.addOutput(amount, multisignatureOutput);

  ASSERT_EQ(0, index);
}

// signInputKey()
// I have no idea how this function works right now
TEST(Transaction, 24)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  transaction.unlockTime = 0;

  // inputKeyInfo
  TransactionTypes::InputKeyInfo inputKeyInfo;
  inputKeyInfo.amount = 11;

  TransactionTypes::GlobalOutput globalOutput0;
  KeyPair keyPair0 = generateKeyPair();
  globalOutput0.targetKey = keyPair0.publicKey;
  globalOutput0.outputIndex = 0;
  KeyImage keyImage0;
  Crypto::generate_key_image(keyPair0.publicKey, keyPair0.secretKey, keyImage0);

  TransactionTypes::GlobalOutput globalOutput1;
  KeyPair keyPair1 = generateKeyPair();
  globalOutput1.targetKey = keyPair1.publicKey;
  globalOutput1.outputIndex = 1;
  KeyImage keyImage1;
  Crypto::generate_key_image(keyPair1.publicKey, keyPair1.secretKey, keyImage1);

  TransactionTypes::GlobalOutput globalOutput2;
  KeyPair keyPair2 = generateKeyPair();
  globalOutput2.targetKey = keyPair2.publicKey;
  globalOutput2.outputIndex = 2;
  KeyImage keyImage2;
  Crypto::generate_key_image(keyPair2.publicKey, keyPair2.secretKey, keyImage2);

  inputKeyInfo.outputs.push_back(globalOutput0);
  inputKeyInfo.outputs.push_back(globalOutput1);
  inputKeyInfo.outputs.push_back(globalOutput2);

  inputKeyInfo.realOutput.transactionPublicKey = keyPair1.publicKey;
  inputKeyInfo.realOutput.transactionIndex = 1;
  inputKeyInfo.realOutput.outputInTransaction = 1;

  // transaction inputs
  KeyInput keyInput0;
  keyInput0.amount = 10;
  keyInput0.outputIndexes = {0, 1, 2};
  keyInput0.keyImage = keyImage0;
  transaction.inputs.push_back(keyInput0);

  KeyInput keyInput1;
  keyInput1.amount = 11;
  keyInput1.outputIndexes = {0, 1, 2};
  keyInput1.keyImage = keyImage1;
  transaction.inputs.push_back(keyInput1);

  KeyInput keyInput2;
  keyInput2.amount = 12;
  keyInput2.outputIndexes = {0, 1, 2};
  keyInput2.keyImage = keyImage2;
  transaction.inputs.push_back(keyInput2);

  TransactionImpl transactionImpl(transaction);

  size_t index = 1;
  KeyPair ephKeys = keyPair1;

  ASSERT_NO_THROW(transactionImpl.signInputKey(index, inputKeyInfo, ephKeys));
}

// signInputMultisignature(index, sourceTransactionKey, outputIndex, accountKeys)
TEST(Transaction, 25)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  transaction.unlockTime = 0;

  // transaction inputs
  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.signatureCount = 2;
  multisignatureInput.outputIndex = 1;
  
  transaction.inputs.push_back(multisignatureInput);
  
  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  PublicKey sourceTransactionKey;
  // I am not sure what outputIndex is used for right now
  // Any random number seems to work
  size_t outputIndex = getRandUint64_t();

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  AccountKeys accountKeys;
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  ASSERT_NO_THROW(transactionImpl.signInputMultisignature(index, sourceTransactionKey, outputIndex, accountKeys));
}

// signInputMultisignature(index, ephemeralKeys)
TEST(Transaction, 26)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  transaction.unlockTime = 0;

  // transaction inputs
  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.signatureCount = 2;
  multisignatureInput.outputIndex = 1;
  
  transaction.inputs.push_back(multisignatureInput);
  
  TransactionImpl transactionImpl(transaction);

  size_t index = 0;

  KeyPair ephemeralKeys = generateKeyPair();

  ASSERT_NO_THROW(transactionImpl.signInputMultisignature(index, ephemeralKeys));
}

// getTransactionData()
TEST(Transaction, 27)
{
  TransactionImpl transactionImpl;

  BinaryArray binaryArray = transactionImpl.getTransactionData();

  ASSERT_NE(0, binaryArray.size());
}

// getTransactionData()
TEST(Transaction, 28)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  BinaryArray binaryArray1 = toBinaryArray(transaction);

  BinaryArray binaryArray2 = transactionImpl.getTransactionData();

  ASSERT_TRUE(std::equal(binaryArray1.begin(), binaryArray1.end(), binaryArray2.begin()));
}

// setPaymentId()
TEST(Transaction, 29)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;

  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  Crypto::Hash paymentId = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  transactionImpl.setPaymentId(paymentId);

  // transaction.extra[0] = 2 signifies transaction extra nonce
  // transaction.extra[1] = 33 signifies the length
  // transaction.extra[2] = 0 signifies a transaction payment id
  // transaction.extra[3 - 34] is the payment id
  transaction.extra = {2, 33, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  BinaryArray binaryArray1 = toBinaryArray(transaction);

  BinaryArray binaryArray2 = transactionImpl.getTransactionData();

  ASSERT_TRUE(std::equal(binaryArray1.begin(), binaryArray1.end(), binaryArray2.begin()));
}

// getPaymentId()
// fail
TEST(Transaction, 30)
{
  TransactionImpl transactionImpl;

  Crypto::Hash hash;

  ASSERT_FALSE(transactionImpl.getPaymentId(hash));
}

// getPaymentId()
// success
TEST(Transaction, 31)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  Crypto::Hash paymentIdInput = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  transactionImpl.setPaymentId(paymentIdInput);

  Crypto::Hash paymentIdOutput;

  ASSERT_TRUE(transactionImpl.getPaymentId(paymentIdOutput));
  ASSERT_TRUE(hashesEqual(paymentIdOutput, paymentIdInput));
}

// setExtraNonce()
TEST(Transaction, 32)
{
  TransactionImpl transactionImpl;

  BinaryArray nonceInput = {2, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  transactionImpl.setExtraNonce(nonceInput);

  BinaryArray nonceOutput;

  ASSERT_TRUE(transactionImpl.getExtraNonce(nonceOutput));

  ASSERT_TRUE(std::equal(nonceInput.begin(), nonceInput.end(), nonceOutput.begin()));
}

// getExtraNonce()
TEST(Transaction, 33)
{
  TransactionImpl transactionImpl;

  BinaryArray nonceOutput;

  ASSERT_FALSE(transactionImpl.getExtraNonce(nonceOutput));

  BinaryArray nonceInput = {2, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  transactionImpl.setExtraNonce(nonceInput);

  ASSERT_TRUE(transactionImpl.getExtraNonce(nonceOutput));

  ASSERT_TRUE(std::equal(nonceInput.begin(), nonceInput.end(), nonceOutput.begin()));
}

// appendExtra() and getExtra()
TEST(Transaction, 34)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  BinaryArray extraDataInput = {2, 1, 1};

  transactionImpl.appendExtra(extraDataInput);

  BinaryArray extraDataOutput = transactionImpl.getExtra();

  ASSERT_TRUE(std::equal(extraDataInput.begin(), extraDataInput.end(), extraDataOutput.begin()));
}

// getInputCount()
TEST(Transaction, 35)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  for (int i = 0 ; i < 5; i++)
  {
    transaction.inputs.push_back(KeyInput());
  }

  TransactionImpl transactionImpl(transaction);

  size_t inputSize = transactionImpl.getInputCount();

  ASSERT_EQ(5, inputSize);
}

// getInputTotalAmount()
TEST(Transaction, 36)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  for (int i = 0 ; i < 5; i++)
  {
    KeyInput keyInput;
    keyInput.amount = 10;
    transaction.inputs.push_back(keyInput);
  }

  TransactionImpl transactionImpl(transaction);

  uint64_t inputTotalAmount = transactionImpl.getInputTotalAmount();

  ASSERT_EQ(50, inputTotalAmount);
}

// getInputType()
TEST(Transaction, 37)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  transaction.inputs.push_back(BaseInput());
  transaction.inputs.push_back(KeyInput());
  transaction.inputs.push_back(MultisignatureInput());

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  ASSERT_EQ(TransactionTypes::InputType::Generating, transactionImpl.getInputType(index));

  index = 1;
  ASSERT_EQ(TransactionTypes::InputType::Key, transactionImpl.getInputType(index));

  index = 2;
  ASSERT_EQ(TransactionTypes::InputType::Multisignature, transactionImpl.getInputType(index));
}

// getInput(keyInput)
TEST(Transaction, 38)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  KeyInput keyInput1;
  keyInput1.amount = 10;
  transaction.inputs.push_back(keyInput1);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  KeyInput keyInput2;
  transactionImpl.getInput(index, keyInput2);

  ASSERT_EQ(keyInput1.amount, keyInput2.amount);

  Crypto::Hash hash1 = getObjectHash(keyInput1);
  Crypto::Hash hash2 = getObjectHash(keyInput2);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
}

// getInput(multisignatureInput)
TEST(Transaction, 39)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  MultisignatureInput multisignatureInput1;
  multisignatureInput1.amount = 10;
  multisignatureInput1.signatureCount = 5;
  multisignatureInput1.outputIndex = 2;
  transaction.inputs.push_back(multisignatureInput1);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  MultisignatureInput multisignatureInput2;
  transactionImpl.getInput(index, multisignatureInput2);

  ASSERT_EQ(multisignatureInput1.amount, multisignatureInput2.amount);
  ASSERT_EQ(multisignatureInput1.signatureCount, multisignatureInput2.signatureCount);
  ASSERT_EQ(multisignatureInput1.outputIndex, multisignatureInput2.outputIndex);

  Crypto::Hash hash1 = getObjectHash(multisignatureInput1);
  Crypto::Hash hash2 = getObjectHash(multisignatureInput2);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
}

// getOutputCount()
TEST(Transaction, 40)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  for (int i = 0 ; i < 5; i++)
  {
    TransactionOutput transactionOutput;
    
    transactionOutput.amount = 10;
    transactionOutput.target = KeyOutput();

    transaction.outputs.push_back(transactionOutput);
  }

  TransactionImpl transactionImpl(transaction);

  size_t outputSize = transactionImpl.getOutputCount();

  ASSERT_EQ(5, outputSize);
}

//getOutputTotalAmount()
TEST(Transaction, 41)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  for (int i = 0 ; i < 5; i++)
  {
    TransactionOutput transactionOutput;

    transactionOutput.amount = 20;
    transactionOutput.target = KeyOutput();

    transaction.outputs.push_back(transactionOutput);
  }

  TransactionImpl transactionImpl(transaction);

  uint64_t outputTotalAmount = transactionImpl.getOutputTotalAmount();

  ASSERT_EQ(100, outputTotalAmount);
}

// getOutputType()
TEST(Transaction, 42)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  TransactionOutput transactionOutput1;
  transactionOutput1.amount = 10;
  transactionOutput1.target = KeyOutput();

  TransactionOutput transactionOutput2;
  transactionOutput2.amount = 20;
  transactionOutput2.target = MultisignatureOutput();

  transaction.outputs.push_back(transactionOutput1);
  transaction.outputs.push_back(transactionOutput2);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  ASSERT_EQ(TransactionTypes::OutputType::Key, transactionImpl.getOutputType(index));

  index = 1;
  ASSERT_EQ(TransactionTypes::OutputType::Multisignature, transactionImpl.getOutputType(index));
}

// getOutput(index, keyOutput, amount)
TEST(Transaction, 43)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;

  KeyOutput keyOutput;
  keyOutput.key = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  transactionOutput.target = keyOutput;
  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  KeyOutput keyOutputReturned;
  uint64_t amount;

  transactionImpl.getOutput(index, keyOutputReturned, amount);

  Crypto::Hash hash1 = getObjectHash(keyOutput);
  Crypto::Hash hash2 = getObjectHash(keyOutputReturned);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
  ASSERT_TRUE(publicKeysEqual(keyOutput.key, keyOutputReturned.key));
  ASSERT_EQ(10, amount);
}

// getOutput(index, multisignatureOutput, amount)
TEST(Transaction, 44)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;
  
  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;

  MultisignatureOutput multisignatureOutput;
  multisignatureOutput.keys.push_back({2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2});
  multisignatureOutput.requiredSignatureCount = 2;
  transactionOutput.target = multisignatureOutput;
  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  MultisignatureOutput multisignatureOutputReturned;
  uint64_t amount;

  transactionImpl.getOutput(index, multisignatureOutputReturned, amount);

  Crypto::Hash hash1 = getObjectHash(multisignatureOutput);
  Crypto::Hash hash2 = getObjectHash(multisignatureOutputReturned);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
  ASSERT_TRUE(publicKeysEqual(multisignatureOutput.keys[0], multisignatureOutputReturned.keys[0]));
  ASSERT_EQ(2, multisignatureOutputReturned.requiredSignatureCount);
  ASSERT_EQ(10, amount);
}

// findOutputsToAccount()
TEST(Transaction, 45)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  
  AccountPublicAddress receiverAddress;
  receiverAddress.viewPublicKey = viewKeyPair.publicKey;
  receiverAddress.spendPublicKey = spendKeyPair.publicKey;

  SecretKey viewSecretKey = viewKeyPair.secretKey;

  // sender creates the key output's one-time public key (receiver's stealth address)

  // create a random transaction public key
  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;

  Crypto::KeyDerivation derivation;
  generate_key_derivation(receiverAddress.viewPublicKey, transactionKeyPair.secretKey, derivation);

  Crypto::PublicKey keyOutputOneTimePublicKey;
  size_t keyOutputIndex = 0;

  derive_public_key(derivation, keyOutputIndex,receiverAddress.spendPublicKey, keyOutputOneTimePublicKey);

  KeyOutput keyOutput;
  keyOutput.key = keyOutputOneTimePublicKey;

  TransactionOutput transactionOutput;

  transactionOutput.amount = 100;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // 1 signifies a transaction public key
  transaction.extra.push_back(1);

  // add transaction public key to transaction.extra
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  TransactionImpl transactionImpl(transaction);

  std::vector<uint32_t> outputIndexes;
  uint64_t amount;

  ASSERT_TRUE(transactionImpl.findOutputsToAccount(receiverAddress, viewSecretKey, outputIndexes, amount));

  ASSERT_EQ(100, amount);
  ASSERT_EQ(1, outputIndexes.size());
  ASSERT_EQ(keyOutputIndex, outputIndexes[0]);
}

// getRequiredSignaturesCount()
// KeyInput
TEST(Transaction, 46)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyInput keyInput;

  for (int i = 0; i < 5; i++)
  {
    keyInput.outputIndexes.push_back(i);
  }

  transaction.inputs.push_back(keyInput);

  TransactionImpl transactionImpl(transaction);

  // key input is located at index 0 in transaction.inputs
  size_t index = 0;
  size_t requiredSignatureCount = transactionImpl.getRequiredSignaturesCount(index);

  ASSERT_EQ(5, requiredSignatureCount);
}

// getRequiredSignaturesCount()
// MultisignatureInput
TEST(Transaction, 47)
{
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureInput multisignatureInput;
  multisignatureInput.signatureCount = 5;

  transaction.inputs.push_back(multisignatureInput);

  TransactionImpl transactionImpl(transaction);

  size_t index = 0;
  size_t requiredSignatureCount = transactionImpl.getRequiredSignaturesCount(index);

  ASSERT_EQ(5, requiredSignatureCount);
}

// validateInputs()
TEST(Transaction, 48)
{
  TransactionImpl transactionImpl;

  ASSERT_TRUE(transactionImpl.validateInputs());
}

// validateInputs()
TEST(Transaction, 49)
{
  Transaction transaction;

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateInputs());
}

// validateInputs()
// success
// KeyInput
TEST(Transaction, 50)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyInput keyInput;

  transaction.inputs.push_back(keyInput);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateInputs());
}

// validateInputs()
// success
// MultisignatureInput
TEST(Transaction, 51)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureInput multisignatureInput;
  multisignatureInput.signatureCount = 5;

  transaction.inputs.push_back(multisignatureInput);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateInputs());
}

// validateInputs()
// fail
// amount overflows
TEST(Transaction, 52)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyInput keyInput1;
  keyInput1.amount = UINT64_MAX;
  keyInput1.outputIndexes.push_back(0);
  keyInput1.keyImage = getRandKeyImage();

  KeyInput keyInput2;
  keyInput2.amount = 1;
  keyInput2.outputIndexes.push_back(0);
  keyInput2.keyImage = getRandKeyImage();

  transaction.inputs.push_back(keyInput1);
  transaction.inputs.push_back(keyInput2);

  TransactionImpl transactionImpl(transaction);

  // amount overflow
  ASSERT_FALSE(transactionImpl.validateInputs());
}

// validateInputs()
// fail
// key image duplicate
TEST(Transaction, 53)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyInput keyInput1;
  keyInput1.amount = UINT64_MAX;
  keyInput1.outputIndexes.push_back(0);
  keyInput1.keyImage = getRandKeyImage();

  KeyInput keyInput2;
  keyInput2.amount = 1;
  keyInput2.outputIndexes.push_back(0);
  keyInput2.keyImage = keyInput1.keyImage;

  transaction.inputs.push_back(keyInput1);
  transaction.inputs.push_back(keyInput2);

  TransactionImpl transactionImpl(transaction);

  // key image duplicate
  ASSERT_FALSE(transactionImpl.validateInputs());
}

// validateInputs()
// fail
// MultisignatureInput duplicate
TEST(Transaction, 54)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureInput multisignatureInput;
  multisignatureInput.signatureCount = 5;

  transaction.inputs.push_back(multisignatureInput);
  transaction.inputs.push_back(multisignatureInput);

  TransactionImpl transactionImpl(transaction);

  // MultisignatureInput duplicate
  ASSERT_FALSE(transactionImpl.validateInputs());
}

// validateOutputs()
// KeyOutput
// success
TEST(Transaction, 55)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyOutput keyOutput;
  keyOutput.key = generateKeyPair().publicKey;

  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);
  
  ASSERT_TRUE(transactionImpl.validateOutputs());
}

// validateOutputs()
// KeyOutput
// fail amount equals 0
TEST(Transaction, 56)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyOutput keyOutput;
  keyOutput.key = generateKeyPair().publicKey;

  TransactionOutput transactionOutput;
  transactionOutput.amount = 0;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);
  
  // amount equals 0
  ASSERT_FALSE(transactionImpl.validateOutputs());
}

// validateOutputs()
// KeyOutput
// fail invalid key
TEST(Transaction, 57)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyOutput keyOutput;
  // I don't know why this key is considered invalid but it is
  keyOutput.key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);

  // invalid public key
  ASSERT_FALSE(transactionImpl.validateOutputs());
}

// validateOutputs()
// KeyOutput
// fail - amount overflows
TEST(Transaction, 58)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  KeyOutput keyOutput1;
  keyOutput1.key = generateKeyPair().publicKey;
  TransactionOutput transactionOutput1;
  transactionOutput1.amount = UINT64_MAX;
  transactionOutput1.target = keyOutput1;
  transaction.outputs.push_back(transactionOutput1);

  KeyOutput keyOutput2;
  keyOutput2.key = generateKeyPair().publicKey;
  TransactionOutput transactionOutput2;
  transactionOutput2.amount = 1;
  transactionOutput2.target = keyOutput2;
  transaction.outputs.push_back(transactionOutput2);

  TransactionImpl transactionImpl(transaction);

  // amount overflows
  ASSERT_FALSE(transactionImpl.validateOutputs());
}

// validateOutputs()
// MultisignatureOutput
// success
TEST(Transaction, 59)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureOutput multisignatureOutput;
  multisignatureOutput.requiredSignatureCount = 11;

  for (int i = 0; i < 20; i++)
  {
    KeyPair keyPair = generateKeyPair();
    multisignatureOutput.keys.push_back(keyPair.publicKey);
  }

  TransactionOutput transactionOutput;
  transactionOutput.amount = 10;
  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);
  
  ASSERT_TRUE(transactionImpl.validateOutputs());
}

// validateOutputs()
// MultisignatureOutput
// fail - number of required signatures > number of keys
TEST(Transaction, 60)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureOutput multisignatureOutput;
  multisignatureOutput.requiredSignatureCount = 11;

  for (int i = 0; i < 10; i++)
  {
    KeyPair keyPair = generateKeyPair();
    multisignatureOutput.keys.push_back(keyPair.publicKey);
  }

  TransactionOutput transactionOutput;
  transactionOutput.amount = 0;
  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);
  
  ASSERT_FALSE(transactionImpl.validateOutputs());
}

// validateOutputs()
// MultisignatureOutput
// fail - invalid public key
TEST(Transaction, 61)
{
  Transaction transaction;

  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = 0;

  MultisignatureOutput multisignatureOutput;
  multisignatureOutput.requiredSignatureCount = 11;

  PublicKey publicKey = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

  for (int i = 0; i < 10; i++)
  {
    multisignatureOutput.keys.push_back(publicKey);
  }

  TransactionOutput transactionOutput;
  transactionOutput.amount = 0;
  transactionOutput.target = multisignatureOutput;

  transaction.outputs.push_back(transactionOutput);

  TransactionImpl transactionImpl(transaction);

  // invalid public keys
  ASSERT_FALSE(transactionImpl.validateOutputs());
}

// validateSignatures()
// default constructor
TEST(Transaction, 62)
{
  TransactionImpl transactionImpl;

  ASSERT_TRUE(transactionImpl.validateSignatures());
}

// validateSignatures()
// KeyInput
// success
TEST(Transaction, 63)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // key input
  KeyInput keyInput;
  
  for(int i = 0; i < 5; i++)
  {
    keyInput.outputIndexes.push_back(i);
  }

  transaction.inputs.push_back(keyInput);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 5; i++)
  {
    // the number of signatures must equal the number of output indexes for each key input
    ringSignature.push_back(getRandSignature());
  }

  // the number of ring signatures must equal the number of key inputs
  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateSignatures());
}

// validateSignatures()
// KeyInput
// success
TEST(Transaction, 64)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // key input 1
  KeyInput keyInput1;
  keyInput1.outputIndexes.push_back(getRandUint8_t());
  transaction.inputs.push_back(keyInput1);

  // key input 2
  KeyInput keyInput2;
  keyInput2.outputIndexes.push_back(getRandUint8_t());
  keyInput2.outputIndexes.push_back(getRandUint8_t());
  transaction.inputs.push_back(keyInput2);

  // key input 3
  KeyInput keyInput3;
  keyInput3.outputIndexes.push_back(getRandUint8_t());
  keyInput3.outputIndexes.push_back(getRandUint8_t());
  keyInput3.outputIndexes.push_back(getRandUint8_t());
  transaction.inputs.push_back(keyInput3);

  // key input 4
  KeyInput keyInput4;
  keyInput4.outputIndexes.push_back(getRandUint8_t());
  keyInput4.outputIndexes.push_back(getRandUint8_t());
  keyInput4.outputIndexes.push_back(getRandUint8_t());
  keyInput4.outputIndexes.push_back(getRandUint8_t());
  transaction.inputs.push_back(keyInput4);

  // key input 5
  KeyInput keyInput5;
  keyInput5.outputIndexes.push_back(getRandUint8_t());
  keyInput5.outputIndexes.push_back(getRandUint8_t());
  keyInput5.outputIndexes.push_back(getRandUint8_t());
  keyInput5.outputIndexes.push_back(getRandUint8_t());
  keyInput5.outputIndexes.push_back(getRandUint8_t());
  transaction.inputs.push_back(keyInput5);

  // ring signatures
  // there must be one signature for every output index in a key input
  // a ring signature is made up of a group of signatures
  // there must be one ring signature for every key input
  
  // ring signature 1
  std::vector<Crypto::Signature> ringSignature1;
  ringSignature1.push_back(getRandSignature());
  transaction.signatures.push_back(ringSignature1);

  // ring signature 2
  std::vector<Crypto::Signature> ringSignature2;
  ringSignature2.push_back(getRandSignature());
  ringSignature2.push_back(getRandSignature());
  transaction.signatures.push_back(ringSignature2);

  // ring signature 3
  std::vector<Crypto::Signature> ringSignature3;
  ringSignature3.push_back(getRandSignature());
  ringSignature3.push_back(getRandSignature());
  ringSignature3.push_back(getRandSignature());
  transaction.signatures.push_back(ringSignature3);

  // ring signature 4
  std::vector<Crypto::Signature> ringSignature4;
  ringSignature4.push_back(getRandSignature());
  ringSignature4.push_back(getRandSignature());
  ringSignature4.push_back(getRandSignature());
  ringSignature4.push_back(getRandSignature());
  transaction.signatures.push_back(ringSignature4);

  // ring signature 5
  std::vector<Crypto::Signature> ringSignature5;
  ringSignature5.push_back(getRandSignature());
  ringSignature5.push_back(getRandSignature());
  ringSignature5.push_back(getRandSignature());
  ringSignature5.push_back(getRandSignature());
  ringSignature5.push_back(getRandSignature());
  transaction.signatures.push_back(ringSignature5);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateSignatures());
}

// validateSignatures()
// KeyInput
// success
TEST(Transaction, 65)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // key input 1
  KeyInput keyInput1;
  uint8_t randOutputIndexes1 = getRandUint8_t();
  for (int i = 0; i < randOutputIndexes1; i++)
  {
    keyInput1.outputIndexes.push_back(getRandUint8_t());
  }
  transaction.inputs.push_back(keyInput1);

  // key input 2
  KeyInput keyInput2;
  uint8_t randOutputIndexes2 = getRandUint8_t();
  for (int i = 0; i < randOutputIndexes2; i++)
  {
    keyInput2.outputIndexes.push_back(getRandUint8_t());
  }
  transaction.inputs.push_back(keyInput2);

  // key input 3
  KeyInput keyInput3;
  uint8_t randOutputIndexes3 = getRandUint8_t();
  for (int i = 0; i < randOutputIndexes3; i++)
  {
    keyInput3.outputIndexes.push_back(getRandUint8_t());
  }
  transaction.inputs.push_back(keyInput3);

  // key input 4
  KeyInput keyInput4;
  uint8_t randOutputIndexes4 = getRandUint8_t();
  for (int i = 0; i < randOutputIndexes4; i++)
  {
    keyInput4.outputIndexes.push_back(getRandUint8_t());
  }
  transaction.inputs.push_back(keyInput4);

  // key input 5
  KeyInput keyInput5;
  uint8_t randOutputIndexes5 = getRandUint8_t();
  for (int i = 0; i < randOutputIndexes5; i++)
  {
    keyInput5.outputIndexes.push_back(getRandUint8_t());
  }
  transaction.inputs.push_back(keyInput5);

  // ring signatures
  // there must be one signature for every output index in a key input
  // a ring signature is made up of a group of signatures
  // there must be one ring signature for every key input

  // ring siganture 1
  std::vector<Crypto::Signature> ringSignature1;
  for (int i = 0; i < randOutputIndexes1; i++)
  {
    ringSignature1.push_back(getRandSignature());
  }
  transaction.signatures.push_back(ringSignature1);

  // ring siganture 2
  std::vector<Crypto::Signature> ringSignature2;
  for (int i = 0; i < randOutputIndexes2; i++)
  {
    ringSignature2.push_back(getRandSignature());
  }
  transaction.signatures.push_back(ringSignature2);

  // ring siganture 3
  std::vector<Crypto::Signature> ringSignature3;
  for (int i = 0; i < randOutputIndexes3; i++)
  {
    ringSignature3.push_back(getRandSignature());
  }
  transaction.signatures.push_back(ringSignature3);

  // ring siganture 4
  std::vector<Crypto::Signature> ringSignature4;
  for (int i = 0; i < randOutputIndexes4; i++)
  {
    ringSignature4.push_back(getRandSignature());
  }
  transaction.signatures.push_back(ringSignature4);

  // ring siganture 5
  std::vector<Crypto::Signature> ringSignature5;
  for (int i = 0; i < randOutputIndexes5; i++)
  {
    ringSignature5.push_back(getRandSignature());
  }
  transaction.signatures.push_back(ringSignature5);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateSignatures());
}

// validateSignatures()
// KeyInput
// fail - number of signatures does not match the number of output indexes in a key input 
TEST(Transaction, 66)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // key input
  KeyInput keyInput;
  
  for(int i = 0; i < 5; i++)
  {
    keyInput.outputIndexes.push_back(i);
  }

  transaction.inputs.push_back(keyInput);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 4; i++)
  {
    // there are 5 output indexes for the key input but only 4 siganutres in the ring signature
    ringSignature.push_back(getRandSignature());
  }

  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  ASSERT_FALSE(transactionImpl.validateSignatures());
}

// validateSignatures()
// KeyInput
// fail - number of ring signatures does not match the number of key inputs 
TEST(Transaction, 67)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // key input1
  KeyInput keyInput1;

  for(int i = 0; i < 5; i++)
  {
    keyInput1.outputIndexes.push_back(i);
  }

  transaction.inputs.push_back(keyInput1);

  // key input2
  KeyInput keyInput2;

  for(int i = 0; i < 5; i++)
  {
    keyInput2.outputIndexes.push_back(i);
  }

  transaction.inputs.push_back(keyInput2);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 5; i++)
  {
    ringSignature.push_back(getRandSignature());
  }

  // there are 2 key inputs but only 1 ring signature
  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  ASSERT_FALSE(transactionImpl.validateSignatures());
}

// validateSignatures()
// MultisignatureInput
// success
TEST(Transaction, 68)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // multisignature input
  // multisiganture inputs only have 1 output index
  // the number of signatures required for that output index is signatureCount
  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.outputIndex = 2;
  multisignatureInput.signatureCount = 5;
  transaction.inputs.push_back(multisignatureInput);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 5; i++)
  {
    // the number of signatures must equal the number of signatureCount
    ringSignature.push_back(getRandSignature());
  }

  // the number of ring signatures must equal the number of multisignature inputs
  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  ASSERT_TRUE(transactionImpl.validateSignatures());
}

// validateSignatures()
// MultisignatureInput
// fail - number of signatures is less than the number of signatureCount
TEST(Transaction, 69)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // multisignature input
  // multisiganture inputs only have 1 output index
  // the number of signatures required for that output index is signatureCount
  MultisignatureInput multisignatureInput;
  multisignatureInput.amount = 10;
  multisignatureInput.outputIndex = 2;
  multisignatureInput.signatureCount = 10;
  transaction.inputs.push_back(multisignatureInput);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 5; i++)
  {
    // the number of signatures must equal the number of signatureCount
    ringSignature.push_back(getRandSignature());
  }

  // the number of ring signatures must equal the number of multisignature inputs
  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  // signatureCount is 10 but there are only 5 sigantures
  ASSERT_FALSE(transactionImpl.validateSignatures());
}

// validateSignatures()
// MultisignatureInput
// fail - the number of ring signatures is less than the number of multisignature inputs
TEST(Transaction, 70)
{
  Transaction transaction;

  // version
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // unlock time
  transaction.unlockTime = 0;

  // multisignature inputs
  // multisiganture inputs only have 1 output index
  // the number of signatures required for that output index is signatureCount

  // multisignature input 1
  MultisignatureInput multisignatureInput1;
  multisignatureInput1.amount = 10;
  multisignatureInput1.outputIndex = 2;
  multisignatureInput1.signatureCount = 10;
  transaction.inputs.push_back(multisignatureInput1);

  // multisignature input 2
  MultisignatureInput multisignatureInput2;
  multisignatureInput2.amount = 10;
  multisignatureInput2.outputIndex = 2;
  multisignatureInput2.signatureCount = 10;
  transaction.inputs.push_back(multisignatureInput2);

  // ring signature
  std::vector<Crypto::Signature> ringSignature;

  for(int i = 0; i < 10; i++)
  {
    // the number of signatures must equal the number of signatureCount
    ringSignature.push_back(getRandSignature());
  }

  // the number of ring signatures must equal the number of multisignature inputs
  transaction.signatures.push_back(ringSignature);

  TransactionImpl transactionImpl(transaction);

  // there are 2 multisignature inputs but only 1 ring signature
  ASSERT_FALSE(transactionImpl.validateSignatures());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}