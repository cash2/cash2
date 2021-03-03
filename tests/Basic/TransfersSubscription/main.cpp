// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "Transfers/TransfersSubscription.h"
#include "Transfers/TransfersContainer.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNoteCore/Transaction.cpp"

using namespace CryptoNote;

/*

My Notes

class TransfersSubscription

public
  TransfersSubscription()
  getSyncStart();
  onBlockchainDetach()
  onError()
  advanceHeight()
  getKeys()
  addTransaction()
  deleteUnconfirmedTransaction()
  markTransactionConfirmed()
  getAddress()
  getContainer()

private
  TransfersContainer transfers
  AccountSubscription subscription

*/

// constructor()
TEST(TransfersSubscription, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription(currency, subscription);
}

// getSyncStart()
TEST(TransfersSubscription, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  SynchronizationStart syncStart = transfersSubscription.getSyncStart();

  ASSERT_EQ(subscription.syncStart.timestamp, syncStart.timestamp);
  ASSERT_EQ(subscription.syncStart.height, syncStart.height);
}

// onBlockchainDetach()
TEST(TransfersSubscription, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  uint32_t height = 0;
  ASSERT_NO_THROW(transfersSubscription.onBlockchainDetach(height));
}

// onError()
TEST(TransfersSubscription, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  std::error_code errorCode;
  uint32_t height = 0;
  ASSERT_NO_THROW(transfersSubscription.onError(errorCode, height));

}

// advanceHeight()
TEST(TransfersSubscription, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  uint32_t height = 0;
  ASSERT_TRUE(transfersSubscription.advanceHeight(height));

  height = 10;
  ASSERT_TRUE(transfersSubscription.advanceHeight(height));
}

// getKeys()
TEST(TransfersSubscription, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  AccountKeys accountKeysRet = transfersSubscription.getKeys();

  ASSERT_TRUE(publicKeysEqual(accountKeys.address.viewPublicKey, accountKeysRet.address.viewPublicKey));
  ASSERT_TRUE(publicKeysEqual(accountKeys.address.spendPublicKey, accountKeysRet.address.spendPublicKey));
  ASSERT_TRUE(secretKeysEqual(accountKeys.viewSecretKey, accountKeysRet.viewSecretKey));
  ASSERT_TRUE(secretKeysEqual(accountKeys.spendSecretKey, accountKeysRet.spendSecretKey));
}

// addTransaction()
TEST(TransfersSubscription, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  TransactionBlockInfo blockInfo;

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

  ASSERT_TRUE(transfersSubscription.addTransaction(blockInfo, transactionImpl, transfers));
}

// deleteUnconfirmedTransaction()
TEST(TransfersSubscription, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  TransactionBlockInfo blockInfo;

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

  ASSERT_TRUE(transfersSubscription.addTransaction(blockInfo, transactionImpl, transfers));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_NO_THROW(transfersSubscription.deleteUnconfirmedTransaction(transactionHash));
}

// markTransactionConfirmed()
TEST(TransfersSubscription, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  TransactionBlockInfo blockInfo;

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

  ASSERT_TRUE(transfersSubscription.addTransaction(blockInfo, transactionImpl, transfers));

  Crypto::Hash transactionHash = getObjectHash(transaction);
  std::vector<uint32_t> globalIndexes = {0};
  ASSERT_NO_THROW(transfersSubscription.markTransactionConfirmed(blockInfo, transactionHash, globalIndexes));
}

// getAddress()
TEST(TransfersSubscription, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  AccountPublicAddress accountPublicAddressRet = transfersSubscription.getAddress();

  Crypto::Hash hash1 = getObjectHash(accountPublicAddressRet);
  Crypto::Hash hash2 = getObjectHash(accountKeys.address);

  ASSERT_TRUE(hashesEqual(hash1, hash2));
}

// getContainer()
TEST(TransfersSubscription, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  TransfersSubscription transfersSubscription(currency, subscription);

  ASSERT_NO_THROW(transfersSubscription.getContainer());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}