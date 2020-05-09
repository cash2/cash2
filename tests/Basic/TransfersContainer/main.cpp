// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "IWallet.h"
#include "Transfers/TransfersContainer.h"
#include "Transfers/TransfersContainer.cpp"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNoteCore/Transaction.cpp"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class SpentOutputDescriptor {
public
  SpentOutputDescriptor()
  SpentOutputDescriptor()
  SpentOutputDescriptor()
  SpentOutputDescriptor()
  assign()
  assign()
  isValid()
  operator==()
  hash()
}

class TransfersContainer
{
public
  TransfersContainer()
  addTransaction()
  deleteUnconfirmedTransaction()
  markTransactionConfirmed()
  detach()
  advanceHeight()
  transfersCount()
  transactionsCount()
  balance()
  getOutputs()
  getTransactionInformation()
  getTransactionOutputs()
  getTransactionInputs()
  getUnconfirmedTransactions()
  getSpentOutputs()
  save()
  load()
}

*/

// SpentOutputDescriptor()
TEST(SpentOutputDescriptor, 1)
{
  SpentOutputDescriptor descriptor();
}

// SpentOutputDescriptor(transactionOutputInformationIn)
TEST(SpentOutputDescriptor, 2)
{
  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 0;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  SpentOutputDescriptor descriptor(txOutputInfo);
}

// SpentOutputDescriptor(keyImage)
TEST(SpentOutputDescriptor, 3)
{
  Crypto::KeyImage keyImage = getRandKeyImage();

  SpentOutputDescriptor descriptor(&keyImage);
}

// SpentOutputDescriptor(amount, globalOutputIndex)
TEST(SpentOutputDescriptor, 4)
{
  uint64_t amount = 0;
  uint32_t globalOutputIndex = 0;

  SpentOutputDescriptor descriptor(amount, globalOutputIndex);
}

// assign()
TEST(SpentOutputDescriptor, 5)
{
  Crypto::KeyImage keyImage1 = getRandKeyImage();

  SpentOutputDescriptor descriptor(&keyImage1);

  Crypto::KeyImage keyImage2 = getRandKeyImage();

  descriptor.assign(&keyImage2);
}

// SpentOutputDescriptor(amount, globalOutputIndex)
TEST(SpentOutputDescriptor, 6)
{
  uint64_t amount1 = 0;
  uint32_t globalOutputIndex1 = 0;

  SpentOutputDescriptor descriptor(amount1, globalOutputIndex1);

  uint64_t amount2 = 1;
  uint32_t globalOutputIndex2 = 1;

  descriptor.assign(amount2, globalOutputIndex2);
}

// isValid()
TEST(SpentOutputDescriptor, 7)
{
  Crypto::KeyImage keyImage = getRandKeyImage();
  SpentOutputDescriptor descriptor(&keyImage);

  ASSERT_TRUE(descriptor.isValid());
}

// operator==()
TEST(SpentOutputDescriptor, 8)
{
  Crypto::KeyImage keyImage = getRandKeyImage();
  
  SpentOutputDescriptor descriptor1(&keyImage);
  SpentOutputDescriptor descriptor2(&keyImage);

  ASSERT_TRUE(descriptor1 == descriptor2);
}

// hash()
TEST(SpentOutputDescriptor, 9)
{
  Crypto::KeyImage keyImage = getRandKeyImage();
  SpentOutputDescriptor descriptor(&keyImage);

  descriptor.hash();

  // descriptor.hash() = 0x752883b4e1ee508f (8442142314413838479)
}

// TransfersContainer()
TEST(TransfersContainer, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;

  TransfersContainer container(currency, transactionSpendableAge);
}

// addTransaction()
TEST(TransfersContainer, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));
}

// deleteUnconfirmedTransaction()
TEST(TransfersContainer, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_TRUE(container.deleteUnconfirmedTransaction(transactionHash));

}

// markTransactionConfirmed()
TEST(TransfersContainer, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  block.height = 1;

  std::vector<uint32_t> globalIndexes = {0};
  ASSERT_TRUE(container.markTransactionConfirmed(block, transactionHash, globalIndexes));
}

// detach()
TEST(TransfersContainer, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;

  Transaction transaction = getRandTransaction();

  Crypto::Hash transactionHash = getObjectHash(transaction);

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  uint32_t height = 0;
  std::vector<Crypto::Hash> transactionHashes = container.detach(height);

  ASSERT_EQ(1, transactionHashes.size());
  ASSERT_TRUE(hashesEqual(transactionHash, transactionHashes[0]));
}

// advanceHeight()
TEST(TransfersContainer, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  uint32_t height = 10;
  ASSERT_TRUE(container.advanceHeight(height));
}

// transfersCount()
TEST(TransfersContainer, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  size_t transfersCount = container.transfersCount();
  ASSERT_EQ(0, transfersCount);

  TransactionBlockInfo block;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  transfersCount = container.transfersCount();
  ASSERT_EQ(1, transfersCount);
}

// transactionsCount()
TEST(TransfersContainer, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  size_t transactionsCount = container.transactionsCount();
  ASSERT_EQ(0, transactionsCount);

  TransactionBlockInfo block;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  transactionsCount = container.transactionsCount();
  ASSERT_EQ(1, transactionsCount);
}

// balance()
TEST(TransfersContainer, 9)
{
  // flags = 0x101
  // state = 0x1
  // IncludeTypeKey = 0x100
  // flags & IncludeTypeKey != 0
  // flags & state != 0

  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  uint32_t flags = 257; // 0x101
  size_t balance = container.balance(flags);
  ASSERT_EQ(0, balance);

  TransactionBlockInfo block;
  block.height = 1;

  Transaction transaction = getRandTransaction();
  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  // current blockchain height must be greater than unlock time and blockHeight + spendableAge
  uint32_t height = 5;
  ASSERT_TRUE(container.advanceHeight(height));

  balance = container.balance(flags);
  ASSERT_EQ(1, balance);
}

// getOutputs()
TEST(TransfersContainer, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  std::vector<TransactionOutputInformation> transfersRet;
  uint32_t flags = 257; // 0x101
  container.getOutputs(transfersRet, flags);
  ASSERT_EQ(0, transfersRet.size());
  ASSERT_EQ(257, flags);
  transfersRet.clear();

  TransactionBlockInfo block;
  block.height = 1;

  Transaction transaction = getRandTransaction();
  transaction.unlockTime = 0;

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  // current blockchain height must be greater than unlock time and blockHeight + spendableAge
  uint32_t height = 5;
  ASSERT_TRUE(container.advanceHeight(height));

  container.getOutputs(transfersRet, flags);
  ASSERT_EQ(1, transfersRet.size());
  ASSERT_EQ(257, flags);
  transfersRet.clear();
}

// getTransactionInformation()
TEST(TransfersContainer, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = 1;

  Transaction transaction = getRandTransaction();

  Crypto::Hash transactionHash = getObjectHash(transaction);

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  TransactionInformation transactionInfo;
  ASSERT_TRUE(container.getTransactionInformation(transactionHash, transactionInfo));

  ASSERT_TRUE(hashesEqual(transactionHash, transactionInfo.transactionHash));
  Crypto::PublicKey transactionPublicKey = getTransactionPublicKeyFromExtra(transaction.extra);
  ASSERT_TRUE(publicKeysEqual(transactionPublicKey, transactionInfo.publicKey));
  ASSERT_EQ(block.height, transactionInfo.blockHeight);
  ASSERT_EQ(transaction.unlockTime, transactionInfo.unlockTime);
  ASSERT_EQ(transaction.extra, transactionInfo.extra);
}

// getTransactionOutputs()
TEST(TransfersContainer, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = 1;

  Transaction transaction = getRandTransaction();
  transaction.unlockTime = 0;

  Crypto::Hash transactionHash = getObjectHash(transaction);

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  // current blockchain height must be greater than unlock time and blockHeight + spendableAge
  uint32_t height = 5;
  ASSERT_TRUE(container.advanceHeight(height));

  uint32_t flags = 257; // 0x101
  std::vector<TransactionOutputInformation> transactionOutputInfos = container.getTransactionOutputs(transactionHash, flags);

  ASSERT_EQ(1, transactionOutputInfos.size());
  ASSERT_EQ(TransactionTypes::OutputType::Key, transactionOutputInfos[0].type);
  ASSERT_EQ(1, transactionOutputInfos[0].amount);
  ASSERT_EQ(0, transactionOutputInfos[0].globalOutputIndex);
  ASSERT_EQ(0, transactionOutputInfos[0].outputInTransaction);
  ASSERT_TRUE(hashesEqual(transactionHash, transactionOutputInfos[0].transactionHash));
  ASSERT_TRUE(publicKeysEqual(txOutputInfo.transactionPublicKey, transactionOutputInfos[0].transactionPublicKey));
}

// getTransactionInputs()
// cannot make function return size greater than 0
// skip for now
TEST(TransfersContainer, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = 1;

  Transaction transaction = getRandTransaction();
  transaction.unlockTime = 0;

  Crypto::Hash transactionHash = getObjectHash(transaction);

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = 0;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  // current blockchain height must be greater than unlock time and blockHeight + spendableAge
  uint32_t height = 5;
  ASSERT_TRUE(container.advanceHeight(height));

  uint32_t flags = 0;
  std::vector<TransactionOutputInformation> transactionOutputInfos = container.getTransactionInputs(transactionHash, flags);

  ASSERT_EQ(0, transactionOutputInfos.size());
}

// getUnconfirmedTransactions()
TEST(TransfersContainer, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  std::vector<Crypto::Hash> unconfirmedTransactions;
  container.getUnconfirmedTransactions(unconfirmedTransactions);

  ASSERT_EQ(1, unconfirmedTransactions.size());
  ASSERT_TRUE(hashesEqual(transactionHash, unconfirmedTransactions[0]));
}

// getSpentOutputs()
// cannot make function return size greater than 0
// skip for now
TEST(TransfersContainer, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  TransactionBlockInfo block;
  block.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;

  Transaction transaction = getRandTransaction();

  TransactionImpl transactionImpl(transaction);

  std::vector<TransactionOutputInformationIn> transfers;

  TransactionOutputInformationIn txOutputInfo;
  txOutputInfo.keyImage = getRandKeyImage();
  txOutputInfo.type = TransactionTypes::OutputType::Key;
  txOutputInfo.amount = 1;
  txOutputInfo.globalOutputIndex = UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX;
  txOutputInfo.outputInTransaction = 0;
  txOutputInfo.transactionHash = getRandHash();
  txOutputInfo.transactionPublicKey = getRandPublicKey();
  txOutputInfo.outputKey = getRandPublicKey();

  transfers.push_back(txOutputInfo);

  ASSERT_TRUE(container.addTransaction(block, transactionImpl, transfers));

  std::vector<TransactionSpentOutputInformation> spentOutputs = container.getSpentOutputs();

  ASSERT_EQ(0, spentOutputs.size());
}

// save()
TEST(TransfersContainer, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  std::stringstream ss;

  container.save(ss);
}

// load()
TEST(TransfersContainer, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  size_t transactionSpendableAge = 0;
  TransfersContainer container(currency, transactionSpendableAge);

  std::stringstream ss;

  container.save(ss);

  container.load(ss);
}











int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}