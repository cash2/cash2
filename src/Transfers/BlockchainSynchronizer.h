// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <condition_variable>
#include <mutex>
#include <atomic>
#include <future>

#include "IBlockchainSynchronizer.h"
#include "INode.h"
#include "IObservableImpl.h"
#include "IStreamSerializable.h"
#include "SynchronizationState.h"

namespace CryptoNote {

class BlockchainSynchronizer : public IObservableImpl<IBlockchainSynchronizerObserver, IBlockchainSynchronizer>, public INodeObserver {

public:

  BlockchainSynchronizer(INode& node, const Crypto::Hash& genesisBlockHash);
  ~BlockchainSynchronizer();

  virtual void addConsumer(IBlockchainConsumer* consumer) override;
  virtual std::future<std::error_code> addUnconfirmedTransaction(const ITransactionReader& transaction) override;
  virtual std::vector<Crypto::Hash> getConsumerKnownBlocks(IBlockchainConsumer& consumer) const override;
  virtual IStreamSerializable* getConsumerState(IBlockchainConsumer* consumer) const override;
  virtual void lastKnownBlockHeightUpdated(uint32_t height) override;
  virtual void load(std::istream& in) override;
  virtual void localBlockchainUpdated(uint32_t height) override;
  virtual void poolChanged() override;
  virtual bool removeConsumer(IBlockchainConsumer* consumer) override;
  virtual std::future<void> removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) override;
  virtual void save(std::ostream& os) override;
  virtual void start() override;
  virtual void stop() override;

private:

  struct GetBlocksResponse {
    uint32_t startHeight;
    std::vector<BlockShortEntry> newBlocks;
  };

  struct GetBlocksRequest {
    GetBlocksRequest() {
      syncStart.timestamp = 0;
      syncStart.height = 0;
    }
    SynchronizationStart syncStart;
    std::vector<Crypto::Hash> knownBlocks;
  };

  struct GetPoolResponse {
    bool isLastKnownBlockActual;
    std::vector<std::unique_ptr<ITransactionReader>> newTxs;
    std::vector<Crypto::Hash> deletedTxIds;
  };

  struct GetPoolRequest {
    std::vector<Crypto::Hash> knownTxIds;
    Crypto::Hash lastKnownBlock;
  };

  enum class State {
    idle = 0,           //DO
    poolSync = 1,       //NOT
    blockchainSync = 2, //REORDER
    stopped = 3         //!!!
  };

  enum class UpdateConsumersResult {
    nothingChanged = 0,
    addedNewBlocks = 1,
    errorOccurred = 2
  };

  void actualizeFutureState();
  std::error_code doAddUnconfirmedTransaction(const ITransactionReader& transaction);
  void doRemoveUnconfirmedTransaction(const Crypto::Hash& transactionHash);
  bool futureStateIsStopped() const;
  GetBlocksRequest getCommonHistory();
  SynchronizationState* getConsumerSynchronizationState(IBlockchainConsumer* consumer) const ;
  std::error_code getPoolSymmetricDifferenceSync(GetPoolRequest&& request, GetPoolResponse& response);
  void getPoolUnionAndIntersection(std::unordered_set<Crypto::Hash>& poolUnion, std::unordered_set<Crypto::Hash>& poolIntersection) const;
  void processBlocks(GetBlocksResponse& response);
  std::error_code processPoolTxs(GetPoolResponse& response);
  void startBlockchainSync();
  void startPoolSync();
  bool stateIsStopped() const;
  UpdateConsumersResult updateConsumers(const BlockchainInterval& interval, const std::vector<CompleteBlock>& blocks);
  void workingProcedure();

  std::list<std::pair<const ITransactionReader*, std::promise<std::error_code>>> m_addTransactionTasks;
  std::map<IBlockchainConsumer*, std::shared_ptr<SynchronizationState>> m_consumerSynchronizationStateMap;
  mutable std::mutex m_consumersMutex;
  State m_currentState;
  State m_futureState;
  const Crypto::Hash m_genesisBlockHash;
  std::condition_variable m_hasWork;
  Crypto::Hash m_lastBlockId;
  INode& m_node;
  std::list<std::pair<const Crypto::Hash*, std::promise<void>>> m_removeTransactionTasks;
  mutable std::mutex m_stateMutex;
  std::unique_ptr<std::thread> m_workingThreadPtr;
  
};

} // end namespace CryptoNote
