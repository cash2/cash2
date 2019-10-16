// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <unordered_set>

#include "crypto/crypto.h"
#include "IBlockchainSynchronizer.h"
#include "ITransfersSynchronizer.h"
#include "TransfersSubscription.h"
#include "TypeHelpers.h"
#include "INode.h"
#include "IObservableImpl.h"

namespace CryptoNote {

class TransfersConsumer: public IObservableImpl<IBlockchainConsumerObserver, IBlockchainConsumer> {

public:

  TransfersConsumer(const CryptoNote::Currency& currency, INode& node, const Crypto::SecretKey& viewSecret);
  void addPublicKeysSeen(const Crypto::Hash& transactionHash, const Crypto::PublicKey& outputKey);
  ITransfersSubscription& addSubscription(const AccountSubscription& subscription);
  virtual std::error_code addUnconfirmedTransaction(const ITransactionReader& transactionReader) override;
  virtual const std::unordered_set<Crypto::Hash>& getKnownPoolTxIds() const override;
  ITransfersSubscription* getSubscription(const AccountPublicAddress& account);
  void getSubscriptions(std::vector<AccountPublicAddress>& subscriptions);
  virtual SynchronizationStart getSyncStart() override;
  void initTransactionPool(const std::unordered_set<Crypto::Hash>& uncommitedTransactions);
  virtual void onBlockchainDetach(uint32_t height) override;
  virtual bool onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t numBlocks) override;
  virtual std::error_code onPoolUpdated(const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions, const std::vector<Crypto::Hash>& deletedTransactions) override;
  bool removeSubscription(const AccountPublicAddress& address);
  virtual void removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) override;
  
private:

  template <typename F>
  void forEachSubscription(F action) {
    for (const auto& kv : m_spendPublicKeySubscriptions) {
      action(*kv.second);
    }
  }

  struct PreprocessInfo {
    std::unordered_map<Crypto::PublicKey, std::vector<TransactionOutputInformationIn>> outputs;
    std::vector<uint32_t> globalIndexes;
  };

  std::error_code createTransfers(const AccountKeys& account, const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, const std::vector<uint32_t>& outputs, const std::vector<uint32_t>& globalIdxs, std::vector<TransactionOutputInformationIn>& transfers);
  std::error_code getTransactionOutputsGlobalIndexes(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outsGlobalIndexes);
  std::error_code preprocessOutputs(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, PreprocessInfo& info);
  void processOutputs(const TransactionBlockInfo& blockInfo, TransfersSubscription& subscription, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& outputs, const std::vector<uint32_t>& globalIdxs, bool& contains, bool& updated);
  std::error_code processTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader);
  void processTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, const PreprocessInfo& info);
  void updateSyncStart();

  const CryptoNote::Currency& m_currency;
  std::unordered_set<Crypto::Hash> m_mempoolTransactionHashes;
  INode& m_node;
  std::unordered_set<Crypto::PublicKey> m_publicKeysSeen;
  std::mutex m_seenMutex;
  std::unordered_set<Crypto::PublicKey> m_spendPublicKeys;
  std::unordered_map<Crypto::PublicKey, std::unique_ptr<TransfersSubscription>> m_spendPublicKeySubscriptions; // map { spend public key -> subscription }
  SynchronizationStart m_synchronizationStart;
  std::unordered_set<Crypto::Hash> m_transactionHashesSeen;
  const Crypto::SecretKey m_viewPrivateKey;
  
};

}