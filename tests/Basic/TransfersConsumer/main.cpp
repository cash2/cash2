// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "Transfers/TransfersConsumer.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "INode.h"
#include "Transfers/CommonTypes.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/Transaction.cpp"
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class TransfersConsumer
{
public
  TransfersConsumer()
  addSubscription()
  removeSubscription()
  getSubscription()
  getSubscriptions()
  initTransactionPool()
  getSyncStart()
  onBlockchainDetach()
  onNewBlocks()
  onPoolUpdated()
  getKnownPoolTxIds()
  addUnconfirmedTransaction()
  removeUnconfirmedTransaction()

private
  SynchronizationStart m_syncStart
  const Crypto::SecretKey m_viewSecret
  std::unordered_map<Crypto::PublicKey, std::unique_ptr<TransfersSubscription>> m_subscriptions
  std::unordered_set<Crypto::PublicKey> m_spendKeys
  std::unordered_set<Crypto::Hash> m_poolTxs
  INode& m_node
  const CryptoNote::Currency& m_currency
}

*/

class Node : public CryptoNote::INode
{
public:
  virtual bool addObserver(CryptoNote::INodeObserver* observer) override { return true; };
  virtual bool removeObserver(CryptoNote::INodeObserver* observer) override { return true; };

  virtual void init(const CryptoNote::INode::Callback& callback) override {callback(std::error_code());};
  virtual bool shutdown() override { return true; };

  virtual size_t getPeerCount() const override { return 0; };
  virtual uint32_t getLastLocalBlockHeight() const override { return 0; };
  virtual uint32_t getLastKnownBlockHeight() const override { return 0; };
  virtual uint32_t getLocalBlockCount() const override { return 0; };
  virtual uint32_t getKnownBlockCount() const override { return 0; };
  virtual uint64_t getLastLocalBlockTimestamp() const override { return 0; }

  virtual void getNewBlocks(std::vector<Crypto::Hash>&& knownBlockIds, std::vector<CryptoNote::block_complete_entry>& newBlocks, uint32_t& height, const Callback& callback) override { callback(std::error_code()); };

  virtual void relayTransaction(const CryptoNote::Transaction& transaction, const Callback& callback) override { callback(std::error_code()); };
  virtual void getRandomOutsByAmounts(std::vector<uint64_t>&& amounts, uint64_t outsCount, std::vector<CryptoNote::CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& result, const Callback& callback) override { callback(std::error_code()); };
  virtual void getTransactionOutsGlobalIndexes(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outsGlobalIndexes, const Callback& callback) override { callback(std::error_code()); };
  virtual void getPoolSymmetricDifference(std::vector<Crypto::Hash>&& known_pool_tx_ids, Crypto::Hash known_block_id, bool& is_bc_actual,
          std::vector<std::unique_ptr<CryptoNote::ITransactionReader>>& new_txs, std::vector<Crypto::Hash>& deleted_tx_ids, const Callback& callback) override {
    is_bc_actual = true; callback(std::error_code());
  };
  virtual void queryBlocks(std::vector<Crypto::Hash>&& knownBlockIds, uint64_t timestamp, std::vector<CryptoNote::BlockShortEntry>& newBlocks,
          uint32_t& startHeight, const Callback& callback) override { callback(std::error_code()); };

  virtual void getBlocks(const std::vector<uint32_t>& blockHeights, std::vector<std::vector<CryptoNote::BlockDetails>>& blocks, const Callback& callback) override { callback(std::error_code()); };
  virtual void getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<CryptoNote::BlockDetails>& blocks, const Callback& callback) override { callback(std::error_code()); };
  virtual void getBlocks(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<CryptoNote::BlockDetails>& blocks, uint32_t& blocksNumberWithinTimestamps, const Callback& callback) override { callback(std::error_code()); };
  virtual void getTransactions(const std::vector<Crypto::Hash>& transactionHashes, std::vector<CryptoNote::TransactionDetails>& transactions, const Callback& callback) override { callback(std::error_code()); };
  virtual void getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<CryptoNote::TransactionDetails>& transactions, const Callback& callback) override { callback(std::error_code()); };
  virtual void getPoolTransactions(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<CryptoNote::TransactionDetails>& transactions, uint64_t& transactionsNumberWithinTimestamps, const Callback& callback) override { callback(std::error_code()); };
  virtual void isSynchronized(bool& syncStatus, const Callback& callback) override { callback(std::error_code()); };
  virtual void getMultisignatureOutputByGlobalIndex(uint64_t amount, uint32_t gindex, CryptoNote::MultisignatureOutput& out, const Callback& callback) override { callback(std::error_code()); }

  void updateObservers();

  Tools::ObserverManager<CryptoNote::INodeObserver> observerManager;
};

// constructor()
TEST(TransfersConsumer, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer(currency, node, viewSecretKey);
}

// addSubscription()
TEST(TransfersConsumer, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  ASSERT_NO_THROW(transfersConsumer.addSubscription(subscription));
}

// removeSubscription()
TEST(TransfersConsumer, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  ASSERT_NO_THROW(transfersConsumer.addSubscription(subscription));

  ASSERT_TRUE(transfersConsumer.removeSubscription(accountKeys.address));
}

// getSubscription()
TEST(TransfersConsumer, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  AccountSubscription subscription;

  AccountKeys accountKeys;
  KeyPair spendKeyPair = generateKeyPair();
  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  subscription.keys = accountKeys;
  subscription.syncStart.timestamp = time(nullptr);
  subscription.syncStart.height = 0;
  subscription.transactionSpendableAge = 0;

  ITransfersSubscription& transfersSubscription = transfersConsumer.addSubscription(subscription);

  ITransfersSubscription* transfersSubscriptionPtr = transfersConsumer.getSubscription(accountKeys.address);

  ASSERT_EQ(transfersSubscriptionPtr, &transfersSubscription);
}

// getSubscriptions()
TEST(TransfersConsumer, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  // add subscription 1

  AccountSubscription subscription1;

  AccountKeys accountKeys1;
  KeyPair spendKeyPair1 = generateKeyPair();
  accountKeys1.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys1.address.spendPublicKey = spendKeyPair1.publicKey;
  accountKeys1.viewSecretKey = viewKeyPair.secretKey;
  accountKeys1.spendSecretKey = spendKeyPair1.secretKey;

  subscription1.keys = accountKeys1;
  subscription1.syncStart.timestamp = time(nullptr);
  subscription1.syncStart.height = 0;
  subscription1.transactionSpendableAge = 0;

  ASSERT_NO_THROW(transfersConsumer.addSubscription(subscription1));

  std::vector<AccountPublicAddress> subscriptions;
  transfersConsumer.getSubscriptions(subscriptions);
  ASSERT_EQ(1, subscriptions.size());
  subscriptions.clear();

  // add subscription 2

  AccountSubscription subscription2;

  AccountKeys accountKeys2;
  KeyPair spendKeyPair2 = generateKeyPair();
  accountKeys2.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys2.address.spendPublicKey = spendKeyPair2.publicKey;
  accountKeys2.viewSecretKey = viewKeyPair.secretKey;
  accountKeys2.spendSecretKey = spendKeyPair2.secretKey;

  subscription2.keys = accountKeys2;
  subscription2.syncStart.timestamp = time(nullptr);
  subscription2.syncStart.height = 0;
  subscription2.transactionSpendableAge = 0;

  ASSERT_NO_THROW(transfersConsumer.addSubscription(subscription2));

  transfersConsumer.getSubscriptions(subscriptions);
  ASSERT_EQ(2, subscriptions.size());
}

// initTransactionPool()
TEST(TransfersConsumer, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  std::unordered_set<Crypto::Hash> uncommitedTransactions;

  uncommitedTransactions.insert(getRandHash());
  uncommitedTransactions.insert(getRandHash());
  uncommitedTransactions.insert(getRandHash());

  transfersConsumer.initTransactionPool(uncommitedTransactions);
}

// getSyncStart()
TEST(TransfersConsumer, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  SynchronizationStart syncStart = transfersConsumer.getSyncStart();

  ASSERT_EQ(std::numeric_limits<uint64_t>::max(), syncStart.height);
}

// onBlockchainDetach()
TEST(TransfersConsumer, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  uint32_t height = 0;
  transfersConsumer.onBlockchainDetach(height);
}

// onNewBlocks()
TEST(TransfersConsumer, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  CompleteBlock completeBlocks;
  completeBlocks.blockHash = getRandHash();
  completeBlocks.blockHash = getRandHash();
  completeBlocks.blockHash = getRandHash();
  uint32_t startHeight = 0;
  uint32_t count = 3;
  ASSERT_TRUE(transfersConsumer.onNewBlocks(&completeBlocks, startHeight, count));
}

// onPoolUpdated()
TEST(TransfersConsumer, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  Transaction transaction = getRandTransaction();

  std::unique_ptr<ITransactionReader> prefix = createTransactionPrefix(transaction);
  std::vector<std::unique_ptr<ITransactionReader>> addedTransactions;
  addedTransactions.push_back(std::move(prefix));

  std::vector<Crypto::Hash> deletedTransactions;
  deletedTransactions.push_back(getRandHash());
  ASSERT_NO_THROW(transfersConsumer.onPoolUpdated(addedTransactions, deletedTransactions));
}

// getKnownPoolTxIds()
TEST(TransfersConsumer, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  Transaction transaction = getRandTransaction();
  Crypto::Hash transactionHash = getObjectHash(transaction);

  std::unique_ptr<ITransactionReader> prefix = createTransactionPrefix(transaction);
  std::vector<std::unique_ptr<ITransactionReader>> addedTransactions;
  addedTransactions.push_back(std::move(prefix));

  std::vector<Crypto::Hash> deletedTransactions;
  deletedTransactions.push_back(getRandHash());
  ASSERT_NO_THROW(transfersConsumer.onPoolUpdated(addedTransactions, deletedTransactions));

  std::unordered_set<Crypto::Hash> transactionHashes = transfersConsumer.getKnownPoolTxIds();

  ASSERT_EQ(1, transactionHashes.size());
  ASSERT_TRUE(transactionHashes.find(transactionHash) != transactionHashes.end());
}

// addUnconfirmedTransaction()
TEST(TransfersConsumer, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  Transaction transaction = getRandTransaction();
  TransactionImpl transactionImpl(transaction);
  transfersConsumer.addUnconfirmedTransaction(transactionImpl);
}

// removeUnconfirmedTransaction()
TEST(TransfersConsumer, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  KeyPair viewKeyPair = generateKeyPair();
  Crypto::SecretKey& viewSecretKey = viewKeyPair.secretKey;
  TransfersConsumer transfersConsumer(currency, node, viewSecretKey);

  Transaction transaction = getRandTransaction();
  TransactionImpl transactionImpl(transaction);
  transfersConsumer.addUnconfirmedTransaction(transactionImpl);

  Crypto::Hash transactionHash = getObjectHash(transaction);
  ASSERT_NO_THROW(transfersConsumer.removeUnconfirmedTransaction(transactionHash));
}






























int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}