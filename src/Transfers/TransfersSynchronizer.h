// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <unordered_map>
#include <memory>
#include <cstring>

#include "Common/ObserverManager.h"
#include "CryptoNoteCore/Currency.h"
#include "IBlockchainSynchronizer.h"
#include "INode.h"
#include "ITransfersSynchronizer.h"
#include "TransfersConsumer.h"
#include "TypeHelpers.h"

namespace CryptoNote {
 
class TransfersSyncronizer : public ITransfersSynchronizer, public IBlockchainConsumerObserver {

public:

  TransfersSyncronizer(const Currency& currency, IBlockchainSynchronizer& blockchainSynchronizer, INode& node);
  virtual ~TransfersSyncronizer();
  void addPublicKeysSeen(const AccountPublicAddress& account, const Crypto::Hash& transactionHash, const Crypto::PublicKey& outputKey); // This function is for fixing the burning bug
  virtual ITransfersSubscription& addSubscription(const AccountSubscription& subscription) override;
  virtual ITransfersSubscription* getSubscription(const AccountPublicAddress& account) override;
  virtual void getSubscriptions(std::vector<AccountPublicAddress>& subscriptions) override;
  virtual std::vector<Crypto::Hash> getViewKeyKnownBlocks(const Crypto::PublicKey& viewPublicKey) override;
  void initTransactionPool(const std::unordered_set<Crypto::Hash>& uncommitedTransactions);
  virtual void load(std::istream& inputStream) override;
  virtual bool removeSubscription(const AccountPublicAddress& account) override;
  virtual void save(std::ostream& outputStream) override;
  void subscribeConsumerNotifications(const Crypto::PublicKey& viewPublicKey, ITransfersSynchronizerObserver* observer);
  void unsubscribeConsumerNotifications(const Crypto::PublicKey& viewPublicKey, ITransfersSynchronizerObserver* observer);

private:

  typedef Tools::ObserverManager<ITransfersSynchronizerObserver> SubscribersNotifier;
  typedef std::unordered_map<Crypto::PublicKey, std::unique_ptr<SubscribersNotifier>> SubscribersMap;
  typedef std::unordered_map<Crypto::PublicKey, std::unique_ptr<TransfersConsumer>> ViewPublicKeyConsumersMap; // map { view public key -> consumer }

  SubscribersMap::const_iterator findSubscriberForConsumer(IBlockchainConsumer* consumerPtr) const;
  virtual void onBlockchainDetach(IBlockchainConsumer* consumer, uint32_t blockIndex) override;
  virtual void onBlocksAdded(IBlockchainConsumer* consumer, const std::vector<Crypto::Hash>& blockHashes) override;
  virtual void onTransactionDeleteBegin(IBlockchainConsumer* consumer, Crypto::Hash transactionHash) override;
  virtual void onTransactionDeleteEnd(IBlockchainConsumer* consumer, Crypto::Hash transactionHash) override;
  virtual void onTransactionUpdated(IBlockchainConsumer* consumer, const Crypto::Hash& transactionHash, const std::vector<ITransfersContainer*>& containers) override;
  
  ViewPublicKeyConsumersMap m_viewPublicKeyConsumersMap;
  SubscribersMap m_subscribersMap;
  IBlockchainSynchronizer& m_blockchainSynchronizer;
  INode& m_node;
  const Currency& m_currency;
 
};

}