// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "Transfers/TransfersSynchronizer.h"
#include "Transfers/BlockchainSynchronizer.h"
#include "Transfers/TransfersSubscription.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "INode.h"
// #include "CryptoNoteCore/Transaction.cpp"

using namespace CryptoNote;

/*

My Notes

class TransfersSyncronizer

public
  TransfersSyncronizer()
  ~TransfersSyncronizer()
  initTransactionPool()
  addSubscription()
  removeSubscription()
  getSubscriptions()
  getSubscription()
  getViewKeyKnownBlocks()
  subscribeConsumerNotifications()
  unsubscribeConsumerNotifications()
  save()
  load()

private
  typedef std::unordered_map<Crypto::PublicKey, std::unique_ptr<TransfersConsumer>> ConsumersContainer
  ConsumersContainer m_consumers
  typedef Tools::ObserverManager<ITransfersSynchronizerObserver> SubscribersNotifier
  typedef std::unordered_map<Crypto::PublicKey, std::unique_ptr<SubscribersNotifier>> SubscribersContainer
  SubscribersContainer m_subscribers
  IBlockchainSynchronizer& m_sync
  INode& m_node
  const CryptoNote::Currency& m_currency

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
  virtual void getRandomOutsByAmounts(std::vector<uint64_t>&& amounts, uint64_t outsCount, std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& result, const Callback& callback) override { callback(std::error_code()); };
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
TEST(TransfersSynchronizer, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer(currency, blockchainSynchronizer, node);
}

// initTransactionPool()
TEST(TransfersSynchronizer, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

  std::unordered_set<Crypto::Hash> uncommitedTransactions;

  Transaction transaction = getRandTransaction();
  Crypto::Hash transactionHash = getObjectHash(transaction);
  uncommitedTransactions.insert(transactionHash);

  ASSERT_NO_THROW(transfersSyncronizer.initTransactionPool(uncommitedTransactions));
}

// addSubscription()
TEST(TransfersSynchronizer, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ASSERT_NO_THROW(transfersSyncronizer.addSubscription(subscription));
}

// removeSubscription()
TEST(TransfersSynchronizer, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ASSERT_NO_THROW(transfersSyncronizer.addSubscription(subscription));

  ASSERT_TRUE(transfersSyncronizer.removeSubscription(accountKeys.address));
}

// getSubscriptions()
TEST(TransfersSynchronizer, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ASSERT_NO_THROW(transfersSyncronizer.addSubscription(subscription));

  std::vector<AccountPublicAddress> subscriptions;
  ASSERT_NO_THROW(transfersSyncronizer.getSubscriptions(subscriptions));

  ASSERT_EQ(1, subscriptions.size());

  ASSERT_EQ(accountKeys.address, subscriptions[0]);
}

// getSubscription()
TEST(TransfersSynchronizer, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ASSERT_NO_THROW(transfersSyncronizer.addSubscription(subscription));

  ASSERT_NO_THROW(transfersSyncronizer.getSubscription(accountKeys.address));
}

// getViewKeyKnownBlocks()
TEST(TransfersSynchronizer, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ASSERT_NO_THROW(transfersSyncronizer.addSubscription(subscription));

  std::vector<Crypto::Hash> blockHashes = transfersSyncronizer.getViewKeyKnownBlocks(viewKeyPair.publicKey);

  ASSERT_EQ(1, blockHashes.size());
}

// subscribeConsumerNotifications()
TEST(TransfersSynchronizer, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ITransfersSynchronizerObserver observer;
  ASSERT_NO_THROW(transfersSyncronizer.subscribeConsumerNotifications(viewKeyPair.publicKey, &observer));
}

// unsubscribeConsumerNotifications()
TEST(TransfersSynchronizer, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

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

  ITransfersSynchronizerObserver observer;
  ASSERT_NO_THROW(transfersSyncronizer.subscribeConsumerNotifications(viewKeyPair.publicKey, &observer));

  ASSERT_NO_THROW(transfersSyncronizer.unsubscribeConsumerNotifications(viewKeyPair.publicKey, &observer));
}

// save()
TEST(TransfersSynchronizer, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

  std::stringstream ss;
  ASSERT_NO_THROW(transfersSyncronizer.save(ss));
}

// load()
TEST(TransfersSynchronizer, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);
  TransfersSyncronizer transfersSyncronizer(currency, blockchainSynchronizer, node);

  std::stringstream ss;
  ASSERT_NO_THROW(transfersSyncronizer.save(ss));

  ASSERT_NO_THROW(transfersSyncronizer.load(ss));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}