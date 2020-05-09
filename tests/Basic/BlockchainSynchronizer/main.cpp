// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "Transfers/BlockchainSynchronizer.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNoteCore/Transaction.cpp"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class BlockchainSynchronizer
{
public
  BlockchainSynchronizer()
  ~BlockchainSynchronizer()
  addConsumer()
  removeConsumer()
  getConsumerState()
  getConsumerKnownBlocks()
  addUnconfirmedTransaction()
  removeUnconfirmedTransaction()
  start()
  stop()
  save()
  load()
  localBlockchainUpdated()
  lastKnownBlockHeightUpdated()
  poolChanged()

private
  typedef std::map<IBlockchainConsumer*, std::shared_ptr<SynchronizationState>> ConsumersMap
  ConsumersMap m_consumers
  INode& m_node
  const Crypto::Hash m_genesisBlockHash
  Crypto::Hash lastBlockId
  State m_currentState
  State m_futureState
  std::unique_ptr<std::thread> workingThread
  std::list<std::pair<const ITransactionReader*, std::promise<std::error_code>>> m_addTransactionTasks
  std::list<std::pair<const Crypto::Hash*, std::promise<void>>> m_removeTransactionTasks
  mutable std::mutex m_consumersMutex
  mutable std::mutex m_stateMutex
  std::condition_variable m_hasWork
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

class BlockchainConsumer : public IBlockchainConsumer
{
public:
  BlockchainConsumer(const Crypto::Hash& genesisBlockHash) {
    m_blockchain.push_back(genesisBlockHash);
  }

  void addPoolTransaction(const Crypto::Hash& hash) {
    m_pool.emplace(hash);
  }

  virtual SynchronizationStart getSyncStart() override {
    SynchronizationStart start = { 0, 0 };
    return start;
  }

  virtual void addObserver(IBlockchainConsumerObserver* observer) override {
  }

  virtual void removeObserver(IBlockchainConsumerObserver* observer) override {
  }

  virtual void onBlockchainDetach(uint32_t height) override {
    assert(height < m_blockchain.size());
    m_blockchain.resize(height);
  }

  virtual bool onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t count) override {
    while (count--) {
      m_blockchain.push_back(blocks->blockHash);
      ++blocks;
    }
    return true;
  }

  const std::vector<Crypto::Hash>& getBlockchain() const {
    return m_blockchain;
  }

  virtual const std::unordered_set<Crypto::Hash>& getKnownPoolTxIds() const override {
    return m_pool;
  }

  virtual std::error_code onPoolUpdated(const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions, const std::vector<Crypto::Hash>& deletedTransactions) override {
    for (const auto& tx: addedTransactions) {
      m_pool.emplace(tx->getTransactionHash());
    }

    for (auto& hash : deletedTransactions) {
      m_pool.erase(hash);
    }

    return std::error_code();
  }

  std::error_code addUnconfirmedTransaction(const ITransactionReader& /*transaction*/) override {
    throw std::runtime_error("Not implemented");
  }

  void removeUnconfirmedTransaction(const Crypto::Hash& /*transactionHash*/) override {
    throw std::runtime_error("Not implemented");
  }

private:
  std::unordered_set<Crypto::Hash> m_pool;
  std::vector<Crypto::Hash> m_blockchain;
};

// constructor()
TEST(BlockchainSynchronizer, 1)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer(node, genesisBlockHash);
}

// addConsumer()
TEST(BlockchainSynchronizer, 2)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);
}

// removeConsumer()
TEST(BlockchainSynchronizer, 3)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  ASSERT_TRUE(blockchainSynchronizer.removeConsumer(&consumer));
}

// getConsumerState()
TEST(BlockchainSynchronizer, 4)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  ASSERT_NO_THROW(blockchainSynchronizer.getConsumerState(&consumer));
}

// getConsumerKnownBlocks()
TEST(BlockchainSynchronizer, 5)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  std::vector<Crypto::Hash> blockHashes = blockchainSynchronizer.getConsumerKnownBlocks(consumer);

  ASSERT_EQ(1, blockHashes.size());
}

// addUnconfirmedTransaction()
TEST(BlockchainSynchronizer, 6)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // add consumer
  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  // start blockchain synchronizer
  blockchainSynchronizer.start();

  // add unconfirmed transaction
  Transaction transaction = getRandTransaction();
  TransactionImpl transactionImpl(transaction);
  ASSERT_NO_THROW(blockchainSynchronizer.addUnconfirmedTransaction(transactionImpl));
}

// removeUnconfirmedTransaction()
TEST(BlockchainSynchronizer, 7)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // add consumer
  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  // start blockchain synchronizer
  blockchainSynchronizer.start();

  // add unconfirmed transaction
  Transaction transaction = getRandTransaction();
  TransactionImpl transactionImpl(transaction);
  ASSERT_NO_THROW(blockchainSynchronizer.addUnconfirmedTransaction(transactionImpl));

  Crypto::Hash transactionHash = getObjectHash(transaction);

  ASSERT_NO_THROW(blockchainSynchronizer.removeUnconfirmedTransaction(transactionHash));
}

// start()
TEST(BlockchainSynchronizer, 8)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // add consumer
  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  // start blockchain synchronizer
  ASSERT_NO_THROW(blockchainSynchronizer.start());
}

// stop()
TEST(BlockchainSynchronizer, 9)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // add consumer
  BlockchainConsumer consumer(genesisBlockHash);
  blockchainSynchronizer.addConsumer(&consumer);

  // start blockchain synchronizer
  ASSERT_NO_THROW(blockchainSynchronizer.start());

  // stop blockchain synchronizer
  ASSERT_NO_THROW(blockchainSynchronizer.stop());
}

// save()
TEST(BlockchainSynchronizer, 10)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // save blockchain synchronizer
  std::stringstream ss;
  ASSERT_NO_THROW(blockchainSynchronizer.save(ss));
}

// load()
TEST(BlockchainSynchronizer, 11)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  // save blockchain synchronizer
  std::stringstream ss;
  ASSERT_NO_THROW(blockchainSynchronizer.save(ss));

  // load blockchain synchronizer
  blockchainSynchronizer.load(ss);
}

// localBlockchainUpdated()
TEST(BlockchainSynchronizer, 12)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  uint32_t height = getRandUint32_t();
  blockchainSynchronizer.localBlockchainUpdated(height);
}

// lastKnownBlockHeightUpdated()
TEST(BlockchainSynchronizer, 13)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  uint32_t height = getRandUint32_t();
  blockchainSynchronizer.lastKnownBlockHeightUpdated(height);
}

// poolChanged()
TEST(BlockchainSynchronizer, 14)
{
  Node node;
  Crypto::Hash genesisBlockHash = getRandHash();
  BlockchainSynchronizer blockchainSynchronizer(node, genesisBlockHash);

  ASSERT_NO_THROW(blockchainSynchronizer.poolChanged());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}