// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <future>
#include <numeric>

#include "Common/BlockingQueue.h"
#include "Common/StringTools.h"
#include "CommonTypes.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "INode.h"
#include "IWallet.h"
#include "TransfersConsumer.h"

namespace {

using namespace CryptoNote;

void checkOutputKey(const Crypto::KeyDerivation& derivation, const Crypto::PublicKey& key, size_t keyIndex, size_t outputIndex, const std::unordered_set<Crypto::PublicKey>& spendKeys, std::unordered_map<Crypto::PublicKey, std::vector<uint32_t>>& outputs)
{

  Crypto::PublicKey spendPublicKey;
  underive_public_key(derivation, keyIndex, key, spendPublicKey);

  if (spendKeys.find(spendPublicKey) != spendKeys.end()) {
    outputs[spendPublicKey].push_back(static_cast<uint32_t>(outputIndex));
  }

}

void findMyOutputs(const ITransactionReader& transactionReader, const Crypto::SecretKey& viewSecretKey, const std::unordered_set<Crypto::PublicKey>& spendPublicKeys, std::unordered_map<Crypto::PublicKey, std::vector<uint32_t>>& outputs)
{
  Crypto::PublicKey transactionPublicKey = transactionReader.getTransactionPublicKey();
  Crypto::KeyDerivation derivation;

  if (!generate_key_derivation(transactionPublicKey, viewSecretKey, derivation)) {
    return;
  }

  size_t keyIndex = 0;
  size_t outputCount = transactionReader.getOutputCount();

  for (size_t i = 0; i < outputCount; ++i) {
    TransactionTypes::OutputType outputType = transactionReader.getOutputType(i);

    if (outputType == TransactionTypes::OutputType::Key)
    {
      uint64_t amountIgnore;
      KeyOutput keyOutput;
      transactionReader.getOutput(i, keyOutput, amountIgnore);
      checkOutputKey(derivation, keyOutput.key, keyIndex, i, spendPublicKeys, outputs);
      ++keyIndex;
    }
    else if (outputType == TransactionTypes::OutputType::Multisignature)
    {
      uint64_t amountIgnore;
      MultisignatureOutput out;
      transactionReader.getOutput(i, out, amountIgnore);
      for (const auto& key : out.keys) {
        checkOutputKey(derivation, key, i, i, spendPublicKeys, outputs);
        ++keyIndex;
      }
    }
  }
}

std::vector<Crypto::Hash> getBlockHashes(const CompleteBlock* blocks, size_t count)
{
  std::vector<Crypto::Hash> result;
  result.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    result.push_back(blocks[i].blockHash);
  }

  return result;
}

}

namespace CryptoNote {


// Public functions


TransfersConsumer::TransfersConsumer(const Currency& currency, INode& node, const Crypto::SecretKey& viewSecret) :
  m_node(node),
  m_viewPrivateKey(viewSecret),
  m_currency(currency) {
  updateSyncStart();
}

void TransfersConsumer::addPublicKeysSeen(const Crypto::Hash& transactionHash, const Crypto::PublicKey& outputKey) { // This function is for fixing the burning bug
  std::lock_guard<std::mutex> lk(m_seenMutex);
  m_transactionHashesSeen.insert(transactionHash);
  m_publicKeysSeen.insert(outputKey);
}

ITransfersSubscription& TransfersConsumer::addSubscription(const AccountSubscription& subscription) {
  if (subscription.keys.viewSecretKey != m_viewPrivateKey) {
    throw std::runtime_error("TransfersConsumer: view secret key mismatch");
  }

  std::unique_ptr<TransfersSubscription>& subscriptionPtr = m_spendPublicKeySubscriptions[subscription.keys.address.spendPublicKey];

  if (subscriptionPtr.get() == nullptr) {
    subscriptionPtr.reset(new TransfersSubscription(m_currency, subscription));
    m_spendPublicKeys.insert(subscription.keys.address.spendPublicKey);
    updateSyncStart();
  }

  return *subscriptionPtr;
}

std::error_code TransfersConsumer::addUnconfirmedTransaction(const ITransactionReader& transactionReader) {
  TransactionBlockInfo unconfirmedBlockInfo;
  unconfirmedBlockInfo.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
  unconfirmedBlockInfo.timestamp = 0;
  unconfirmedBlockInfo.transactionIndex = 0;

  return processTransaction(unconfirmedBlockInfo, transactionReader);
}

const std::unordered_set<Crypto::Hash>& TransfersConsumer::getKnownPoolTxIds() const {
  return m_mempoolTransactionHashes;
}

ITransfersSubscription* TransfersConsumer::getSubscription(const AccountPublicAddress& account) {
  auto it = m_spendPublicKeySubscriptions.find(account.spendPublicKey);
  return it == m_spendPublicKeySubscriptions.end() ? nullptr : it->second.get();
}

void TransfersConsumer::getSubscriptions(std::vector<AccountPublicAddress>& subscriptions) {
  for (const auto& kv : m_spendPublicKeySubscriptions) {
    subscriptions.push_back(kv.second->getAddress());
  }
}

SynchronizationStart TransfersConsumer::getSyncStart() {
  return m_synchronizationStart;
}

void TransfersConsumer::initTransactionPool(const std::unordered_set<Crypto::Hash>& uncommitedTransactions) {
  for (auto itSubscriptions = m_spendPublicKeySubscriptions.begin(); itSubscriptions != m_spendPublicKeySubscriptions.end(); ++itSubscriptions) {
    std::vector<Crypto::Hash> unconfirmedTransactions;
    itSubscriptions->second->getContainer().getUnconfirmedTransactions(unconfirmedTransactions);

    for (auto itTransactions = unconfirmedTransactions.begin(); itTransactions != unconfirmedTransactions.end(); ++itTransactions) {
      if (uncommitedTransactions.count(*itTransactions) == 0) {
        m_mempoolTransactionHashes.emplace(*itTransactions);
      }
    }
  }
}

void TransfersConsumer::onBlockchainDetach(uint32_t height) {
  m_observerManager.notify(&IBlockchainConsumerObserver::onBlockchainDetach, this, height);

  for (const auto& kv : m_spendPublicKeySubscriptions) {
    kv.second->onBlockchainDetach(height);
  }
}

bool TransfersConsumer::onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t numBlocks) {
  assert(blocks);
  assert(numBlocks > 0);

  struct Tx {
    TransactionBlockInfo blockInfo;
    const ITransactionReader* transactionReader;
  };

  struct PreprocessedTx : Tx, PreprocessInfo {};

  std::vector<PreprocessedTx> preprocessedTransactions;
  std::mutex preprocessedTransactionsMutex;

  size_t workers = std::thread::hardware_concurrency();
  if (workers == 0) {
    workers = 2;
  }

  BlockingQueue<Tx> inputQueue(workers * 2);

  std::atomic<bool> stopProcessing(false);

  std::future<void> pushingThread = std::async(std::launch::async, [&] {
    for( uint32_t i = 0; i < numBlocks && !stopProcessing; ++i) {
      const boost::optional<Block>& block = blocks[i].block;

      if (!block.is_initialized()) {
        continue;
      }

      // filter by syncStartTimestamp
      if (m_synchronizationStart.timestamp && m_synchronizationStart.timestamp > block->timestamp) {
        continue;
      }

      TransactionBlockInfo blockInfo;
      blockInfo.height = startHeight + i;
      blockInfo.timestamp = block->timestamp;
      blockInfo.transactionIndex = 0; // position in block

      for (const std::shared_ptr<ITransactionReader>& transactionReaderPtr : blocks[i].transactions) {
        Crypto::PublicKey transactionPublicKey = transactionReaderPtr->getTransactionPublicKey();
        if (transactionPublicKey == NULL_PUBLIC_KEY) {
          ++blockInfo.transactionIndex;
          continue;
        }

        Tx item = { blockInfo, transactionReaderPtr.get() };
        inputQueue.push(item);
        ++blockInfo.transactionIndex;
      }
    }

    inputQueue.close();
  });

  auto processingFunction = [&] {
    Tx item;
    std::error_code ec;
    while (!stopProcessing && inputQueue.pop(item)) {
      PreprocessedTx output;
      static_cast<Tx&>(output) = item;

      ec = preprocessOutputs(item.blockInfo, *item.transactionReader, output);
      if (ec) {
        stopProcessing = true;
        break;
      }

      std::lock_guard<std::mutex> lk(preprocessedTransactionsMutex);
      preprocessedTransactions.push_back(std::move(output));
    }
    return ec;
  };

  std::vector<std::future<std::error_code>> processingThreads;
  for (size_t i = 0; i < workers; ++i) {
    processingThreads.push_back(std::async(std::launch::async, processingFunction));
  }

  std::error_code processingError;
  for (auto& f : processingThreads) {
    try {
      std::error_code ec = f.get();
      if (!processingError && ec) {
        processingError = ec;
      }
    } catch (const std::system_error& e) {
      processingError = e.code();
    } catch (const std::exception&) {
      processingError = std::make_error_code(std::errc::operation_canceled);
    }
  }

  std::vector<Crypto::Hash> blockHashes = getBlockHashes(blocks, numBlocks);
  if (!processingError) {
    m_observerManager.notify(&IBlockchainConsumerObserver::onBlocksAdded, this, blockHashes);

    // sort by block height and transaction index in block
    std::sort(preprocessedTransactions.begin(), preprocessedTransactions.end(), [](const PreprocessedTx& a, const PreprocessedTx& b) {
      return std::tie(a.blockInfo.height, a.blockInfo.transactionIndex) < std::tie(b.blockInfo.height, b.blockInfo.transactionIndex);
    });

    for (const auto& tx : preprocessedTransactions) {
      processTransaction(tx.blockInfo, *tx.transactionReader, tx);
    }
  } else {
    forEachSubscription([&](TransfersSubscription& sub) {
      sub.onError(processingError, startHeight);
    });

    return false;
  }

  auto newHeight = startHeight + numBlocks - 1;
  forEachSubscription([newHeight](TransfersSubscription& sub) {
    sub.advanceHeight(newHeight);
  });

  return true;
}

std::error_code TransfersConsumer::onPoolUpdated(const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions, const std::vector<Crypto::Hash>& deletedTransactions) {
  TransactionBlockInfo unconfirmedBlockInfo;
  unconfirmedBlockInfo.timestamp = 0; 
  unconfirmedBlockInfo.height = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;

  std::error_code processingError;
  for (const std::unique_ptr<ITransactionReader>& transactionReaderPtr : addedTransactions) {
    m_mempoolTransactionHashes.emplace(transactionReaderPtr->getTransactionHash());
    processingError = processTransaction(unconfirmedBlockInfo, *transactionReaderPtr.get());
    if (processingError) {
      for (auto& sub : m_spendPublicKeySubscriptions) {
        sub.second->onError(processingError, WALLET_UNCONFIRMED_TRANSACTION_HEIGHT);
      }

      return processingError;
    }
  }
  
  for (const Crypto::Hash& deletedTxHash : deletedTransactions) {
    m_mempoolTransactionHashes.erase(deletedTxHash);

    m_observerManager.notify(&IBlockchainConsumerObserver::onTransactionDeleteBegin, this, deletedTxHash);
    for (auto& sub : m_spendPublicKeySubscriptions) {
      sub.second->deleteUnconfirmedTransaction(*reinterpret_cast<const Crypto::Hash*>(&deletedTxHash));
    }

    m_observerManager.notify(&IBlockchainConsumerObserver::onTransactionDeleteEnd, this, deletedTxHash);
  }

  return std::error_code();
}

bool TransfersConsumer::removeSubscription(const AccountPublicAddress& address) {
  m_spendPublicKeySubscriptions.erase(address.spendPublicKey);
  m_spendPublicKeys.erase(address.spendPublicKey);
  updateSyncStart();
  return m_spendPublicKeySubscriptions.empty();
}

void TransfersConsumer::removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) {
  m_observerManager.notify(&IBlockchainConsumerObserver::onTransactionDeleteBegin, this, transactionHash);
  for (auto& subscription : m_spendPublicKeySubscriptions) {
    subscription.second->deleteUnconfirmedTransaction(transactionHash);
  }
  m_observerManager.notify(&IBlockchainConsumerObserver::onTransactionDeleteEnd, this, transactionHash);
}


// Private functions


std::error_code TransfersConsumer::createTransfers(const AccountKeys& account, const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, const std::vector<uint32_t>& outputs, const std::vector<uint32_t>& globalIndexes, std::vector<TransactionOutputInformationIn>& transfers) {

  Crypto::PublicKey transactionPublicKey = transactionReader.getTransactionPublicKey();
  Crypto::Hash transactionHash = transactionReader.getTransactionHash();
  std::vector<Crypto::PublicKey> tempKeys;
  std::lock_guard<std::mutex> lk(m_seenMutex);

  for (auto i : outputs) {

    if (i >= transactionReader.getOutputCount()) {
      return std::make_error_code(std::errc::argument_out_of_domain);
    }

    TransactionTypes::OutputType outType = transactionReader.getOutputType(size_t(i));

    if (outType != TransactionTypes::OutputType::Key && outType != TransactionTypes::OutputType::Multisignature) {
      continue;
    }

    TransactionOutputInformationIn info;

    info.type = outType;
    info.transactionPublicKey = transactionPublicKey;
    info.outputInTransaction = i;
    info.globalOutputIndex = (blockInfo.height == WALLET_UNCONFIRMED_TRANSACTION_HEIGHT) ? UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX : globalIndexes[i];

    if (outType == TransactionTypes::OutputType::Key)
    {
      uint64_t amount;
      KeyOutput out;
      transactionReader.getOutput(i, out, amount);

      KeyPair in_ephemeral;
      generate_key_image_helper(account, transactionPublicKey, i, in_ephemeral, info.keyImage);

      assert(out.key == reinterpret_cast<const PublicKey&>(in_ephemeral.publicKey));

      std::unordered_set<Crypto::Hash>::iterator it = m_transactionHashesSeen.find(transactionHash);

      // Burning bug fix
      if (it == m_transactionHashesSeen.end()) {

        std::unordered_set<Crypto::PublicKey>::iterator key_it = m_publicKeysSeen.find(out.key);
        if (key_it != m_publicKeysSeen.end()) {
          // duplicate output key found
          return std::error_code();
        }
        if (std::find(tempKeys.begin(), tempKeys.end(), out.key) != tempKeys.end()) {
          // duplicate output key found
          return std::error_code();
        }
        tempKeys.push_back(out.key);
      }

      info.amount = amount;
      info.outputKey = out.key;

    }
    else if (outType == TransactionTypes::OutputType::Multisignature)
    {
      uint64_t amount;
      MultisignatureOutput out;
      transactionReader.getOutput(i, out, amount);

      for (const auto& key : out.keys) {
        std::unordered_set<Crypto::Hash>::iterator it = m_transactionHashesSeen.find(transactionHash);
        if (it == m_transactionHashesSeen.end()) {
          std::unordered_set<Crypto::PublicKey>::iterator key_it = m_publicKeysSeen.find(key);
          if (key_it != m_publicKeysSeen.end()) {
            return std::error_code();
          }
          if (std::find(tempKeys.begin(), tempKeys.end(), key) != tempKeys.end()) {
            return std::error_code();
          }
          tempKeys.push_back(key);
        }
      }
      info.amount = amount;
      info.requiredSignatures = out.requiredSignatureCount;
    }

    transfers.push_back(info);
  }

  m_transactionHashesSeen.emplace(transactionHash);
  std::copy(tempKeys.begin(), tempKeys.end(), std::inserter(m_publicKeysSeen, m_publicKeysSeen.end()));

  return std::error_code();
}

std::error_code TransfersConsumer::getTransactionOutputsGlobalIndexes(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outputGlobalIndexes) {  
  std::promise<std::error_code> promise;
  std::future<std::error_code> future = promise.get_future();

  INode::Callback callback = [&promise](std::error_code error) { 
    std::promise<std::error_code> p(std::move(promise));
    p.set_value(error);
  };

  outputGlobalIndexes.clear();
  m_node.getTransactionOutsGlobalIndexes(transactionHash, outputGlobalIndexes, callback);

  return future.get();
}

std::error_code TransfersConsumer::preprocessOutputs(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, PreprocessInfo& info) {
  
  std::unordered_map<Crypto::PublicKey, std::vector<uint32_t>> outputs;

  findMyOutputs(transactionReader, m_viewPrivateKey, m_spendPublicKeys, outputs);

  if (outputs.empty()) {
    return std::error_code();
  }

  std::error_code errorCode;
  auto transactionHash = transactionReader.getTransactionHash();
  if (blockInfo.height != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT) {
    errorCode = getTransactionOutputsGlobalIndexes(reinterpret_cast<const Crypto::Hash&>(transactionHash), info.globalIndexes);
    if (errorCode) {
      return errorCode;
    }
  }

  for (const auto& kv : outputs) {
    auto it = m_spendPublicKeySubscriptions.find(kv.first);
    if (it != m_spendPublicKeySubscriptions.end()) {
      auto& transfers = info.outputs[kv.first];
      errorCode = TransfersConsumer::createTransfers(it->second->getKeys(), blockInfo, transactionReader, kv.second, info.globalIndexes, transfers);
      if (errorCode) {
        return errorCode;
      }
    }
  }

  return std::error_code();
}

void TransfersConsumer::processOutputs(const TransactionBlockInfo& blockInfo, TransfersSubscription& subscription, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers, const std::vector<uint32_t>& globalIndexes, bool& contains, bool& updated) {

  TransactionInformation subscriptionTxInfo;
  contains = subscription.getContainer().getTransactionInformation(transactionReader.getTransactionHash(), subscriptionTxInfo);
  updated = false;

  if (contains) {
    if (subscriptionTxInfo.blockHeight == WALLET_UNCONFIRMED_TRANSACTION_HEIGHT && blockInfo.height != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT) {
      // pool->blockchain
      subscription.markTransactionConfirmed(blockInfo, transactionReader.getTransactionHash(), globalIndexes);
      updated = true;
    } else {
      assert(subscriptionTxInfo.blockHeight == blockInfo.height);
    }
  } else {
    updated = subscription.addTransaction(blockInfo, transactionReader, transfers);
    contains = updated;
  }
}

std::error_code TransfersConsumer::processTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader) {
  PreprocessInfo info;
  auto ec = preprocessOutputs(blockInfo, transactionReader, info);
  if (ec) {
    return ec;
  }

  processTransaction(blockInfo, transactionReader, info);
  return std::error_code();
}

void TransfersConsumer::processTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& tx, const PreprocessInfo& info) {
  std::vector<TransactionOutputInformationIn> emptyOutputs;
  std::vector<ITransfersContainer*> transactionContainers;
  bool someContainerUpdated = false;
  for (auto& kv : m_spendPublicKeySubscriptions) {
    auto it = info.outputs.find(kv.first);
    auto& subscriptionOutputs = (it == info.outputs.end()) ? emptyOutputs : it->second;

    bool containerContainsTx;
    bool containerUpdated;
    processOutputs(blockInfo, *kv.second, tx, subscriptionOutputs, info.globalIndexes, containerContainsTx, containerUpdated);
    someContainerUpdated = someContainerUpdated || containerUpdated;
    if (containerContainsTx) {
      transactionContainers.emplace_back(&kv.second->getContainer());
    }
  }

  if (someContainerUpdated) {
    m_observerManager.notify(&IBlockchainConsumerObserver::onTransactionUpdated, this, tx.getTransactionHash(), transactionContainers);
  }
}

void TransfersConsumer::updateSyncStart() {
  SynchronizationStart syncStart;

  syncStart.height =   std::numeric_limits<uint64_t>::max();
  syncStart.timestamp = std::numeric_limits<uint64_t>::max();

  for (const auto& spendPublicKeySubscription : m_spendPublicKeySubscriptions) {
    SynchronizationStart subSyncStart = spendPublicKeySubscription.second->getSyncStart();
    syncStart.height = std::min(syncStart.height, subSyncStart.height);
    syncStart.timestamp = std::min(syncStart.timestamp, subSyncStart.timestamp);
  }

  m_synchronizationStart = syncStart;
}

}