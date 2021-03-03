// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "BlockchainExplorer/BlockchainExplorer.h"
#include "Logging/ConsoleLogger.h"
#include "INode.h"
#include "CryptoNoteConfig.h"

using namespace CryptoNote;

/*

My Notes

class BlockchainExplorer
public
  BlockchainExplorer()
  ~BlockchainExplorer()
  addObserver()
  removeObserver()
  getBlocks()
  getBlocks()
  getBlocks()
  getBlockchainTop()
  getTransactions()
  getTransactionsByPaymentId()
  getPoolTransactions()
  getPoolState()
  getRewardBlocksWindow()
  getFullRewardMaxBlockSize()
  isSynchronized()
  init()
  shutdown()
  poolChanged()
  blockchainSynchronized()
  localBlockchainUpdated()

private
  enum State {
    NOT_INITIALIZED,
    INITIALIZED
  }
  BlockDetails knownBlockchainTop
  uint32_t knownBlockchainTopHeight
  std::unordered_set<Crypto::Hash> knownPoolState
  std::atomic<State> state
  std::atomic<bool> synchronized
  std::atomic<uint32_t> observersCounter
  Tools::ObserverManager<IBlockchainObserver> observerManager
  std::mutex mutex
  INode& node
  Logging::LoggerRef logger
  AsyncContextCounter asyncContextCounter
  PoolUpdateGuard poolUpdateGuard

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

  virtual void getBlocks(const std::vector<uint32_t>& blockHeights, std::vector<std::vector<CryptoNote::BlockDetails>>& blocks, const Callback& callback) override
  {
    for (int i = 0; i < blockHeights.size(); i++) {
      BlockDetails blockDetails = BlockDetails();
      blockDetails.height = blockHeights[i];
      blockDetails.isOrphaned = false;
      blockDetails.hash = getRandHash();
      std::vector<BlockDetails> blockDetailsVector;
      blockDetailsVector.push_back(blockDetails);
      blocks.push_back(blockDetailsVector);
    }

    callback(std::error_code());
  };
  virtual void getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<CryptoNote::BlockDetails>& blocks, const Callback& callback) override
  {
    for (int i = 0; i < blockHashes.size(); i++) {
      BlockDetails blockDetails = BlockDetails();
      blockDetails.height = blockHashes.size();
      blockDetails.isOrphaned = false;
      blockDetails.hash = blockHashes[i];
      blocks.push_back(blockDetails);
    }

    callback(std::error_code());
  };
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
TEST(BlockchainExplorer, 1)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer(node, logger);
}

// init()
TEST(BlockchainExplorer, 2)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());
}

// addObserver()
TEST(BlockchainExplorer, 3)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  IBlockchainObserver observer;
  ASSERT_TRUE(blockchainExplorer.addObserver(&observer));
}

// removeObserver()
TEST(BlockchainExplorer, 4)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  IBlockchainObserver observer;
  ASSERT_TRUE(blockchainExplorer.addObserver(&observer));

  ASSERT_TRUE(blockchainExplorer.removeObserver(&observer));
}

// getBlocks(blockHeights, blocks)
TEST(BlockchainExplorer, 5)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  std::vector<uint32_t> blockHeights = {0};
  std::vector<std::vector<BlockDetails>> blocks;
  ASSERT_TRUE(blockchainExplorer.getBlocks(blockHeights, blocks));
}


// getBlocks(blockHashes, blocks)
TEST(BlockchainExplorer, 6)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  std::vector<Crypto::Hash> blockHashes;
  blockHashes.push_back(getRandHash());
  blockHashes.push_back(getRandHash());
  blockHashes.push_back(getRandHash());

  std::vector<BlockDetails> blocks;

  ASSERT_TRUE(blockchainExplorer.getBlocks(blockHashes, blocks));

  ASSERT_EQ(3, blocks.size());
}

// getBlocks(timestampBegin, timestampEnd, blocksNumberLimit, blocks, blocksNumberWithinTimestamps)
TEST(BlockchainExplorer, 7)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint64_t timestampBegin = time(nullptr) - 10;
  uint64_t timestampEnd = time(nullptr) + 10;
  uint32_t blocksNumberLimit = 100; // this is a random number
  std::vector<BlockDetails> blocks;
  uint32_t blocksNumberWithinTimestamps;
  ASSERT_TRUE(blockchainExplorer.getBlocks(timestampBegin, timestampEnd, blocksNumberLimit, blocks, blocksNumberWithinTimestamps));
  ASSERT_EQ(0, blocks.size());
}

// getBlockchainTop()
TEST(BlockchainExplorer, 8)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  BlockDetails topBlock;
  ASSERT_TRUE(blockchainExplorer.getBlockchainTop(topBlock));
}

// getTransactions(transactionHashes, transactions)
TEST(BlockchainExplorer, 9)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  std::vector<Crypto::Hash> transactionHashes;
  transactionHashes.push_back(getRandHash());
  transactionHashes.push_back(getRandHash());
  transactionHashes.push_back(getRandHash());
  std::vector<TransactionDetails> transactions;
  ASSERT_TRUE(blockchainExplorer.getTransactions(transactionHashes, transactions));

  ASSERT_EQ(0, transactions.size());
}

// getTransactions()
TEST(BlockchainExplorer, 10)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  Crypto::Hash paymentId = getRandHash();
  std::vector<TransactionDetails> transactions;
  ASSERT_TRUE(blockchainExplorer.getTransactionsByPaymentId(paymentId, transactions));

  ASSERT_EQ(0, transactions.size());
}

// getPoolTransactions()
TEST(BlockchainExplorer, 11)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint64_t timestampBegin = time(nullptr) - 10;
  uint64_t timestampEnd = time(nullptr) + 10;
  uint32_t transactionsNumberLimit = 100; // this is a random number
  std::vector<TransactionDetails> transactions;
  uint64_t transactionsNumberWithinTimestamps;
  ASSERT_TRUE(blockchainExplorer.getPoolTransactions(timestampBegin, timestampEnd, transactionsNumberLimit, transactions, transactionsNumberWithinTimestamps));

  ASSERT_EQ(0, transactions.size());
  ASSERT_EQ(0, transactionsNumberWithinTimestamps);
}

// getPoolState()
TEST(BlockchainExplorer, 12)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  std::vector<Crypto::Hash> knownPoolTransactionHashes;
  knownPoolTransactionHashes.push_back(getRandHash());
  knownPoolTransactionHashes.push_back(getRandHash());
  knownPoolTransactionHashes.push_back(getRandHash());
  Crypto::Hash knownBlockchainTop = getRandHash();
  bool isBlockchainActual;
  std::vector<TransactionDetails> newTransactions;
  std::vector<Crypto::Hash> removedTransactions;
  ASSERT_TRUE(blockchainExplorer.getPoolState(knownPoolTransactionHashes, knownBlockchainTop, isBlockchainActual, newTransactions, removedTransactions));

  ASSERT_TRUE(isBlockchainActual);
  ASSERT_EQ(0, newTransactions.size());
  ASSERT_EQ(0, removedTransactions.size());
}

// getRewardBlocksWindow()
TEST(BlockchainExplorer, 13)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint64_t rewardBlocksWindow = blockchainExplorer.getRewardBlocksWindow();

  ASSERT_EQ(parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW, rewardBlocksWindow);
}

// getFullRewardMaxBlockSize()
TEST(BlockchainExplorer, 14)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint64_t fullRewardMaxBlockSize = blockchainExplorer.getFullRewardMaxBlockSize();

  ASSERT_EQ(parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE, fullRewardMaxBlockSize);
}

// isSynchronized()
TEST(BlockchainExplorer, 15)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  ASSERT_FALSE(blockchainExplorer.isSynchronized());
}

// shutdown()
TEST(BlockchainExplorer, 16)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());
  
  ASSERT_NO_THROW(blockchainExplorer.shutdown());
}

// poolChanged()
TEST(BlockchainExplorer, 17)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  ASSERT_NO_THROW(blockchainExplorer.poolChanged());
}

// blockchainSynchronized()
TEST(BlockchainExplorer, 18)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint32_t topHeight = 0;
  ASSERT_NO_THROW(blockchainExplorer.blockchainSynchronized(topHeight));
}

// localBlockchainUpdated()
TEST(BlockchainExplorer, 19)
{
  Node node;
  Logging::ConsoleLogger logger;
  BlockchainExplorer blockchainExplorer(node, logger);

  ASSERT_NO_THROW(blockchainExplorer.init());

  uint32_t height = 0;
  ASSERT_NO_THROW(blockchainExplorer.localBlockchainUpdated(height));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}