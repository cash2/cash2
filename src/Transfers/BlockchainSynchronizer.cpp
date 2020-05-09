// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <functional>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include "BlockchainSynchronizer.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionApi.h"

namespace CryptoNote {


// Public functions


BlockchainSynchronizer::BlockchainSynchronizer(INode& node, const Crypto::Hash& genesisBlockHash) :
  m_node(node),
  m_genesisBlockHash(genesisBlockHash),
  m_currentState(State::stopped),
  m_futureState(State::stopped) {
}

BlockchainSynchronizer::~BlockchainSynchronizer()
{
  stop();
}

void BlockchainSynchronizer::addConsumer(IBlockchainConsumer* consumer)
{
  assert(consumer != nullptr);
  assert(m_consumerSynchronizationStateMap.count(consumer) == 0);

  if (!(stateIsStopped() && futureStateIsStopped())) {
    throw std::runtime_error("Can't add consumer, because BlockchainSynchronizer isn't stopped");
  }

  m_consumerSynchronizationStateMap.insert(std::make_pair(consumer, std::make_shared<SynchronizationState>(m_genesisBlockHash)));
}

std::future<std::error_code> BlockchainSynchronizer::addUnconfirmedTransaction(const ITransactionReader& transaction)
{
  std::unique_lock<std::mutex> lock(m_stateMutex);

  if (m_currentState == State::stopped || m_futureState == State::stopped) {
    throw std::runtime_error("Can't add transaction, because BlockchainSynchronizer is stopped");
  }

  std::promise<std::error_code> promise;
  std::future<std::error_code> future = promise.get_future();
  m_addTransactionTasks.emplace_back(&transaction, std::move(promise));
  m_hasWork.notify_one();

  return future;
}

std::vector<Crypto::Hash> BlockchainSynchronizer::getConsumerKnownBlocks(IBlockchainConsumer& consumer) const
{
  std::unique_lock<std::mutex> lk(m_consumersMutex);

  SynchronizationState* state = getConsumerSynchronizationState(&consumer);
  if (state == nullptr) {
    throw std::invalid_argument("Consumer not found");
  }

  return state->getKnownBlockHashes();
}

IStreamSerializable* BlockchainSynchronizer::getConsumerState(IBlockchainConsumer* consumer) const
{
  std::unique_lock<std::mutex> lk(m_consumersMutex);
  return getConsumerSynchronizationState(consumer);
}

void BlockchainSynchronizer::lastKnownBlockHeightUpdated(uint32_t height)
{
  std::unique_lock<std::mutex> lk(m_stateMutex);
  if (State::blockchainSync > m_futureState) {
    m_futureState = State::blockchainSync;
    m_hasWork.notify_one();
  }
}

void BlockchainSynchronizer::load(std::istream& in)
{
  Crypto::Hash genesisBlockHash;
  in.read(reinterpret_cast<char*>(&genesisBlockHash), sizeof(genesisBlockHash));
  if (genesisBlockHash != m_genesisBlockHash) {
    throw std::runtime_error("Genesis block hash does not match stored state");
  }
}

void BlockchainSynchronizer::localBlockchainUpdated(uint32_t height)
{
  std::unique_lock<std::mutex> lk(m_stateMutex);
  if (State::blockchainSync > m_futureState) {
    m_futureState = State::blockchainSync;
    m_hasWork.notify_one();
  }
}

void BlockchainSynchronizer::poolChanged()
{
  std::unique_lock<std::mutex> lk(m_stateMutex);
  if (State::poolSync > m_futureState) {
    m_futureState = State::poolSync;
    m_hasWork.notify_one();
  }
}

bool BlockchainSynchronizer::removeConsumer(IBlockchainConsumer* consumer)
{
  assert(consumer != nullptr);

  if (!(stateIsStopped() && futureStateIsStopped())) {
    throw std::runtime_error("Can't remove consumer, because BlockchainSynchronizer isn't stopped");
  }

  return m_consumerSynchronizationStateMap.erase(consumer) > 0;
}

std::future<void> BlockchainSynchronizer::removeUnconfirmedTransaction(const Crypto::Hash& transactionHash)
{
  std::unique_lock<std::mutex> lock(m_stateMutex);

  if (m_currentState == State::stopped || m_futureState == State::stopped) {
    throw std::runtime_error("Can't remove transaction, because BlockchainSynchronizer is stopped");
  }

  std::promise<void> promise;
  auto future = promise.get_future();
  m_removeTransactionTasks.emplace_back(&transactionHash, std::move(promise));
  m_hasWork.notify_one();

  return future;
}

void BlockchainSynchronizer::save(std::ostream& os)
{
  os.write(reinterpret_cast<const char*>(&m_genesisBlockHash), sizeof(m_genesisBlockHash));
}

void BlockchainSynchronizer::start()
{

  if (m_consumerSynchronizationStateMap.empty())
  {
    throw std::runtime_error("Can't start, because BlockchainSynchronizer has no consumers");
  }

  {
    std::unique_lock<std::mutex> lk(m_stateMutex);

    if (m_currentState == State::stopped && m_futureState == State::stopped)
    {
      m_futureState = State::blockchainSync;
      m_hasWork.notify_one();
    }
    else
    {
      throw std::runtime_error("BlockchainSynchronizer already started");
    }
  }

  m_workingThreadPtr.reset(new std::thread([this] { workingProcedure(); }));
}

void BlockchainSynchronizer::stop()
{
  {
    std::unique_lock<std::mutex> lk(m_stateMutex);
    if (State::stopped > m_futureState) {
      m_futureState = State::stopped;
      m_hasWork.notify_one();
    }
  }

  // wait for previous processing to end
  if (m_workingThreadPtr.get() != nullptr && m_workingThreadPtr->joinable()) {
    m_workingThreadPtr->join();
  }

  m_workingThreadPtr.reset();
}


// Private functions


void BlockchainSynchronizer::actualizeFutureState()
{
  std::unique_lock<std::mutex> lk(m_stateMutex);

  if (m_currentState == State::stopped && m_futureState == State::blockchainSync) { // start()
    m_node.addObserver(this);
  }

  if (m_currentState != State::stopped && m_futureState == State::stopped) { // stop()
    m_node.removeObserver(this);
  }

  while (!m_removeTransactionTasks.empty()) {
    auto& task = m_removeTransactionTasks.front();
    const Crypto::Hash& transactionHash = *task.first;
    std::promise<void> detachedPromise = std::move(task.second);
    m_removeTransactionTasks.pop_front();

    try {
      doRemoveUnconfirmedTransaction(transactionHash);
      detachedPromise.set_value();
    } catch (...) {
      detachedPromise.set_exception(std::current_exception());
    }
  }

  while (!m_addTransactionTasks.empty()) {
    auto& task = m_addTransactionTasks.front();
    const ITransactionReader& transactionReader = *task.first;
    auto detachedPromise = std::move(task.second);
    m_addTransactionTasks.pop_front();

    try {
      std::error_code error = doAddUnconfirmedTransaction(transactionReader);
      detachedPromise.set_value(error);
    } catch (...) {
      detachedPromise.set_exception(std::current_exception());
    }
  }

  m_currentState = m_futureState;

  switch (m_futureState) {
  case State::stopped:
    break;
  case State::blockchainSync:
    m_futureState = State::poolSync;
    lk.unlock();
    startBlockchainSync();
    break;
  case State::poolSync:
    m_futureState = State::idle;
    lk.unlock();
    startPoolSync();
    break;
  case State::idle:
    m_hasWork.wait(lk, [this] {
      return m_futureState != State::idle || !m_removeTransactionTasks.empty() || !m_addTransactionTasks.empty();
    });
    lk.unlock();
    break;
  default:
    break;
  }
}

std::error_code BlockchainSynchronizer::doAddUnconfirmedTransaction(const ITransactionReader& transaction)
{
  std::unique_lock<std::mutex> lk(m_consumersMutex);

  std::error_code ec;
  auto addIt = m_consumerSynchronizationStateMap.begin();
  for (; addIt != m_consumerSynchronizationStateMap.end(); ++addIt) {
    ec = addIt->first->addUnconfirmedTransaction(transaction);
    if (ec) {
      break;
    }
  }

  if (ec) {
    Crypto::Hash transactionHash = transaction.getTransactionHash();
    for (auto rollbackIt = m_consumerSynchronizationStateMap.begin(); rollbackIt != addIt; ++rollbackIt) {
      rollbackIt->first->removeUnconfirmedTransaction(transactionHash);
    }
  }

  return ec;
}

void BlockchainSynchronizer::doRemoveUnconfirmedTransaction(const Crypto::Hash& transactionHash)
{
  std::unique_lock<std::mutex> lk(m_consumersMutex);

  for (auto& consumer : m_consumerSynchronizationStateMap) {
    consumer.first->removeUnconfirmedTransaction(transactionHash);
  }
}

BlockchainSynchronizer::GetBlocksRequest BlockchainSynchronizer::getCommonHistory()
{
  GetBlocksRequest request;
  std::unique_lock<std::mutex> lk(m_consumersMutex);
  if (m_consumerSynchronizationStateMap.empty()) {
    return request;
  }

  auto shortest = m_consumerSynchronizationStateMap.begin();
  auto syncStart = shortest->first->getSyncStart();
  auto it = shortest;
  ++it;
  for (; it != m_consumerSynchronizationStateMap.end(); ++it) {
    if (it->second->getHeight() < shortest->second->getHeight()) {
      shortest = it;
    }

    auto consumerStart = it->first->getSyncStart();
    syncStart.timestamp = std::min(syncStart.timestamp, consumerStart.timestamp);
    syncStart.height = std::min(syncStart.height, consumerStart.height);
  }

  request.knownBlocks = shortest->second->getShortHistory(m_node.getLastLocalBlockHeight());
  request.syncStart = syncStart;
  return request;
}

bool BlockchainSynchronizer::futureStateIsStopped() const
{
  std::unique_lock<std::mutex> lk(m_stateMutex);
  return m_futureState == State::stopped;
}

// pre: m_consumersMutex is locked
SynchronizationState* BlockchainSynchronizer::getConsumerSynchronizationState(IBlockchainConsumer* consumer) const
{
  assert(consumer != nullptr);

  if (!(stateIsStopped() && futureStateIsStopped())) {
    throw std::runtime_error("Can't get consumer state, because BlockchainSynchronizer isn't stopped");
  }

  auto it = m_consumerSynchronizationStateMap.find(consumer);
  if (it == m_consumerSynchronizationStateMap.end()) {
    return nullptr;
  }

  return it->second.get();
}

std::error_code BlockchainSynchronizer::getPoolSymmetricDifferenceSync(GetPoolRequest&& request, GetPoolResponse& response)
{
  auto promise = std::promise<std::error_code>();
  auto future = promise.get_future();

  m_node.getPoolSymmetricDifference(
    std::move(request.knownTxIds),
    std::move(request.lastKnownBlock),
    response.isLastKnownBlockActual,
    response.newTxs,
    response.deletedTxIds,
    [&promise](std::error_code ec) {
      auto detachedPromise = std::move(promise);
      detachedPromise.set_value(ec);
    });

  return future.get();
}

void BlockchainSynchronizer::getPoolUnionAndIntersection(std::unordered_set<Crypto::Hash>& poolUnion, std::unordered_set<Crypto::Hash>& poolIntersection) const
{
  std::unique_lock<std::mutex> lk(m_consumersMutex);

  auto itConsumers = m_consumerSynchronizationStateMap.begin();
  poolUnion = itConsumers->first->getKnownPoolTxIds();
  poolIntersection = itConsumers->first->getKnownPoolTxIds();
  ++itConsumers;

  for (; itConsumers != m_consumerSynchronizationStateMap.end(); ++itConsumers) {
    const std::unordered_set<Crypto::Hash>& consumerKnownIds = itConsumers->first->getKnownPoolTxIds();

    poolUnion.insert(consumerKnownIds.begin(), consumerKnownIds.end());

    for (auto itIntersection = poolIntersection.begin(); itIntersection != poolIntersection.end();) {
      if (consumerKnownIds.count(*itIntersection) == 0) {
        itIntersection = poolIntersection.erase(itIntersection);
      } else {
        ++itIntersection;
      }
    }
  }
}

void BlockchainSynchronizer::processBlocks(GetBlocksResponse& response)
{
  BlockchainInterval interval;
  interval.startHeight = response.startHeight;
  std::vector<CompleteBlock> completeBlocks;

  for (BlockShortEntry& newBlock : response.newBlocks) {
    if (futureStateIsStopped()) {
      break;
    }

    CompleteBlock completeBlock;
    completeBlock.blockHash = newBlock.blockHash;
    interval.blocks.push_back(completeBlock.blockHash);
    if (newBlock.hasBlock)
    {
      completeBlock.block = std::move(newBlock.block);
      completeBlock.transactions.push_back(createTransactionPrefix(completeBlock.block->baseTransaction));

      try
      {
        for (const TransactionShortInfo& txShortInfo : newBlock.txsShortInfo) {
          completeBlock.transactions.push_back(createTransactionPrefix(txShortInfo.txPrefix, reinterpret_cast<const Crypto::Hash&>(txShortInfo.txId)));
        }
      }
      catch (std::exception&)
      {
        {
          std::unique_lock<std::mutex> lk(m_stateMutex);

          if (m_futureState != State::stopped) {
            m_futureState = State::idle;
            m_hasWork.notify_one();
          }
        }

        m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, std::make_error_code(std::errc::invalid_argument));
        return;
      }
    }

    completeBlocks.push_back(std::move(completeBlock));
  }

  uint32_t processedBlockCount = response.startHeight + static_cast<uint32_t>(response.newBlocks.size());
  if (!futureStateIsStopped())
  {
    response.newBlocks.clear();
    std::unique_lock<std::mutex> lk(m_consumersMutex);
    auto result = updateConsumers(interval, completeBlocks);
    lk.unlock();

    switch (result) {
    case UpdateConsumersResult::errorOccurred:

      {
        std::unique_lock<std::mutex> lk(m_stateMutex);

        if (m_futureState != State::stopped) {
          m_futureState = State::idle;
          m_hasWork.notify_one();
          m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, std::make_error_code(std::errc::invalid_argument));
        }
      }

      break;

    case UpdateConsumersResult::nothingChanged:
      if (m_node.getLastKnownBlockHeight() != m_node.getLastLocalBlockHeight()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      } else {
        break;
      }

    case UpdateConsumersResult::addedNewBlocks:

      {
        std::unique_lock<std::mutex> lk(m_stateMutex);
        if (State::blockchainSync > m_futureState) {
          m_futureState = State::blockchainSync;
          m_hasWork.notify_one();
        }
      }

      m_observerManager.notify(
        &IBlockchainSynchronizerObserver::synchronizationProgressUpdated,
        processedBlockCount,
        std::max(m_node.getKnownBlockCount(), m_node.getLocalBlockCount()));
      break;
    }

    if (!completeBlocks.empty()) {
      m_lastBlockId = completeBlocks.back().blockHash;
    }
  }

  if (futureStateIsStopped()) { //Sic!
    m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, std::make_error_code(std::errc::interrupted));
  }
}

std::error_code BlockchainSynchronizer::processPoolTxs(GetPoolResponse& response)
{
  std::error_code error;
  {
    std::unique_lock<std::mutex> lk(m_consumersMutex);
    for (auto& consumer : m_consumerSynchronizationStateMap) {
      if (futureStateIsStopped()) { //if stop, return immediately, without notification
        return std::make_error_code(std::errc::interrupted);
      }

      error = consumer.first->onPoolUpdated(response.newTxs, response.deletedTxIds);
      if (error) {
        break;
      }
    }
  }

  return error;
}

void BlockchainSynchronizer::startBlockchainSync()
{
  GetBlocksResponse response;
  GetBlocksRequest request = getCommonHistory();

  try
  {
    if (!request.knownBlocks.empty())
    {
      std::promise<std::error_code> queryBlocksPromise = std::promise<std::error_code>();
      std::future<std::error_code> queryBlocksFuture = queryBlocksPromise.get_future();

      m_node.queryBlocks(
        std::move(request.knownBlocks),
        request.syncStart.timestamp,
        response.newBlocks,
        response.startHeight,
        [&queryBlocksPromise](std::error_code error) {
          std::promise<std::error_code> detachedPromise = std::move(queryBlocksPromise);
          detachedPromise.set_value(error);
        }
      );

      std::error_code error = queryBlocksFuture.get();

      if (error)
      {
        {
          std::unique_lock<std::mutex> lk(m_stateMutex);
          if (m_futureState != State::stopped) {
            m_futureState = State::idle;
            m_hasWork.notify_one();
          }
        }

        m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, error);
      }
      else
      {
        processBlocks(response);
      }
    }
  }
  catch (std::exception&)
  {
    {
      std::unique_lock<std::mutex> lk(m_stateMutex);

      if (m_futureState != State::stopped) {
        m_futureState = State::idle;
        m_hasWork.notify_one();
      }
    }

    m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, std::make_error_code(std::errc::invalid_argument));
  }
}

void BlockchainSynchronizer::startPoolSync()
{
  std::unordered_set<Crypto::Hash> unionPoolHistory;
  std::unordered_set<Crypto::Hash> intersectedPoolHistory;
  getPoolUnionAndIntersection(unionPoolHistory, intersectedPoolHistory);

  GetPoolRequest unionRequest;
  unionRequest.knownTxIds.assign(unionPoolHistory.begin(), unionPoolHistory.end());
  unionRequest.lastKnownBlock = m_lastBlockId;

  GetPoolResponse unionResponse;
  unionResponse.isLastKnownBlockActual = false;

  std::error_code ec = getPoolSymmetricDifferenceSync(std::move(unionRequest), unionResponse);

  if (ec) {
    {
      std::unique_lock<std::mutex> lk(m_stateMutex);
      if (m_futureState != State::stopped) {
        m_futureState = State::idle;
        m_hasWork.notify_one();
      }
    }

    m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, ec);
  } else { //get union ok
    if (!unionResponse.isLastKnownBlockActual) { //bc outdated
      {
        std::unique_lock<std::mutex> lk(m_stateMutex);
        if (State::blockchainSync > m_futureState) {
          m_futureState = State::blockchainSync;
          m_hasWork.notify_one();
        }
      }
    } else {
      if (unionPoolHistory == intersectedPoolHistory) { //usual case, start pool processing
        m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, processPoolTxs(unionResponse));
      } else {
        GetPoolRequest intersectionRequest;
        intersectionRequest.knownTxIds.assign(intersectedPoolHistory.begin(), intersectedPoolHistory.end());
        intersectionRequest.lastKnownBlock = m_lastBlockId;

        GetPoolResponse intersectionResponse;
        intersectionResponse.isLastKnownBlockActual = false;

        std::error_code ec2 = getPoolSymmetricDifferenceSync(std::move(intersectionRequest), intersectionResponse);

        if (ec2) {
          {
            std::unique_lock<std::mutex> lk(m_stateMutex);
            if (m_futureState != State::stopped) {
              m_futureState = State::idle;
              m_hasWork.notify_one();
            }
          }

          m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, ec2);
        } else { //get intersection ok
          if (!intersectionResponse.isLastKnownBlockActual) { //bc outdated
            {
              std::unique_lock<std::mutex> lk(m_stateMutex);
              if (State::blockchainSync > m_futureState) {
                m_futureState = State::blockchainSync;
                m_hasWork.notify_one();
              }
            }
          } else {
            intersectionResponse.deletedTxIds.assign(unionResponse.deletedTxIds.begin(), unionResponse.deletedTxIds.end());
            std::error_code ec3 = processPoolTxs(intersectionResponse);

            //notify about error, or success
            m_observerManager.notify(&IBlockchainSynchronizerObserver::synchronizationCompleted, ec3);
          }
        }
      }
    }
  }
}

bool BlockchainSynchronizer::stateIsStopped() const
{
  std::unique_lock<std::mutex> lk(m_stateMutex);
  return m_currentState == State::stopped;
}

// pre m_consumersMutex is locked
BlockchainSynchronizer::UpdateConsumersResult BlockchainSynchronizer::updateConsumers(const BlockchainInterval& interval, const std::vector<CompleteBlock>& blocks)
{
  bool smthChanged = false;

  for (auto& kv : m_consumerSynchronizationStateMap) {
    IBlockchainConsumer* consumerPtr = kv.first;
    const std::shared_ptr<SynchronizationState>& synchronizationStatePtr = kv.second;

    SynchronizationState::CheckResult result = synchronizationStatePtr->checkInterval(interval);

    if (result.detachRequired) {
      consumerPtr->onBlockchainDetach(result.detachHeight);
      synchronizationStatePtr->detach(result.detachHeight);
    }

    if (result.hasNewBlocks) {
      uint32_t startOffset = result.newBlockHeight - interval.startHeight;
      // update consumer
      if (consumerPtr->onNewBlocks(blocks.data() + startOffset, result.newBlockHeight, static_cast<uint32_t>(blocks.size()) - startOffset)) {
        // update state if consumer succeeded
        synchronizationStatePtr->addBlocks(interval.blocks.data() + startOffset, result.newBlockHeight, static_cast<uint32_t>(interval.blocks.size()) - startOffset);
        smthChanged = true;
      } else {
        return UpdateConsumersResult::errorOccurred;
      }
    }
  }

  return smthChanged ? UpdateConsumersResult::addedNewBlocks : UpdateConsumersResult::nothingChanged;
}

void BlockchainSynchronizer::workingProcedure()
{
  while (!futureStateIsStopped()) {
    actualizeFutureState();
  }

  actualizeFutureState();
}

} // end namespace CryptoNote
