// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "TransfersConsumer.h"
#include "TransfersSynchronizer.h"

namespace
{

std::string getObjectState(CryptoNote::IStreamSerializable& obj)
{
  std::stringstream stream;
  obj.save(stream);
  return stream.str();
}

void setObjectState(CryptoNote::IStreamSerializable& obj, const std::string& state)
{
  std::stringstream stream(state);
  obj.load(stream);
}

}


namespace CryptoNote {


// Public functions


const uint32_t TRANSFERS_STORAGE_ARCHIVE_VERSION = 0;

TransfersSyncronizer::TransfersSyncronizer(const Currency& currency, IBlockchainSynchronizer& blockchainSynchronizer, INode& node) :
  m_currency(currency),
  m_blockchainSynchronizer(blockchainSynchronizer),
  m_node(node) {
}

TransfersSyncronizer::~TransfersSyncronizer()
{
  m_blockchainSynchronizer.stop();
  for (const auto& kv : m_viewPublicKeyConsumersMap) {
    m_blockchainSynchronizer.removeConsumer(kv.second.get());
  }
}

void TransfersSyncronizer::addPublicKeysSeen(const AccountPublicAddress& account, const Crypto::Hash& transactionHash, const Crypto::PublicKey& outputKey) // This function is for fixing the burning bug
{
  auto it = m_viewPublicKeyConsumersMap.find(account.viewPublicKey);
  if (it != m_viewPublicKeyConsumersMap.end()) {
     it->second->addPublicKeysSeen(transactionHash, outputKey);
  }
}

ITransfersSubscription& TransfersSyncronizer::addSubscription(const AccountSubscription& subscription)
{
  auto it = m_viewPublicKeyConsumersMap.find(subscription.keys.address.viewPublicKey);

  if (it == m_viewPublicKeyConsumersMap.end()) {
    std::unique_ptr<TransfersConsumer> transfersConsumerPtr(new TransfersConsumer(m_currency, m_node, subscription.keys.viewSecretKey));

    m_blockchainSynchronizer.addConsumer(transfersConsumerPtr.get());
    transfersConsumerPtr->addObserver(this);
    it = m_viewPublicKeyConsumersMap.insert(std::make_pair(subscription.keys.address.viewPublicKey, std::move(transfersConsumerPtr))).first;
  }
    
  return it->second->addSubscription(subscription);
}

ITransfersSubscription* TransfersSyncronizer::getSubscription(const AccountPublicAddress& account)
{
  auto it = m_viewPublicKeyConsumersMap.find(account.viewPublicKey);
  return (it == m_viewPublicKeyConsumersMap.end()) ? nullptr : it->second->getSubscription(account);
}

void TransfersSyncronizer::getSubscriptions(std::vector<AccountPublicAddress>& subscriptions)
{
  for (const auto& kv : m_viewPublicKeyConsumersMap) {
    kv.second->getSubscriptions(subscriptions);
  }
}

std::vector<Crypto::Hash> TransfersSyncronizer::getViewKeyKnownBlocks(const Crypto::PublicKey& publicViewKey)
{
  auto it = m_viewPublicKeyConsumersMap.find(publicViewKey);
  if (it == m_viewPublicKeyConsumersMap.end()) {
    throw std::invalid_argument("Consumer not found");
  }

  return m_blockchainSynchronizer.getConsumerKnownBlocks(*it->second);
}

void TransfersSyncronizer::initTransactionPool(const std::unordered_set<Crypto::Hash>& uncommitedTransactions)
{
  for (auto it = m_viewPublicKeyConsumersMap.begin(); it != m_viewPublicKeyConsumersMap.end(); ++it) {
    it->second->initTransactionPool(uncommitedTransactions);
  }
}

void TransfersSyncronizer::load(std::istream& inputStream)
{
  m_blockchainSynchronizer.load(inputStream);

  Common::StdInputStream stdInputStream(inputStream);
  BinaryInputStreamSerializer deserializer(stdInputStream);
  uint32_t version = 0;

  deserializer(version, "version");

  if (version > TRANSFERS_STORAGE_ARCHIVE_VERSION) {
    throw std::runtime_error("TransfersSyncronizer version mismatch");
  }

  struct ConsumerState {
    Crypto::PublicKey viewPublicKey;
    std::string state;
    std::vector<std::pair<AccountPublicAddress, std::string>> subscriptionStates;
  };

  std::vector<ConsumerState> updatedStates;

  try {
    size_t subscriptionCount = 0;
    deserializer.beginArray(subscriptionCount, "consumers");

    while (subscriptionCount--) {
      deserializer.beginObject("");
      Crypto::PublicKey viewPublicKey;
      deserializer(viewPublicKey, "view_key");

      std::string blob;
      deserializer(blob, "state");

      auto it = m_viewPublicKeyConsumersMap.find(viewPublicKey);
      if (it != m_viewPublicKeyConsumersMap.end()) {
        auto consumerState = m_blockchainSynchronizer.getConsumerState(it->second.get());
        assert(consumerState);

        {
          // store previous state
          auto prevConsumerState = getObjectState(*consumerState);
          // load consumer state
          setObjectState(*consumerState, blob);
          updatedStates.push_back(ConsumerState{ viewPublicKey, std::move(prevConsumerState) });
        }

        // load subscriptions
        size_t subCount = 0;
        deserializer.beginArray(subCount, "subscriptions");

        while (subCount--) {
          deserializer.beginObject("");

          AccountPublicAddress acc;
          std::string state;

          deserializer(acc, "address");
          deserializer(state, "state");

          auto sub = it->second->getSubscription(acc);

          if (sub != nullptr) {
            auto prevState = getObjectState(sub->getContainer());
            setObjectState(sub->getContainer(), state);
            updatedStates.back().subscriptionStates.push_back(std::make_pair(acc, prevState));
          }

          deserializer.endObject();
        }
        deserializer.endArray();
      }
    }

    deserializer.endObject();
    deserializer.endArray();

  } catch (...) {
    // rollback state
    for (const auto& consumerState : updatedStates) {
      auto consumer = m_viewPublicKeyConsumersMap.find(consumerState.viewPublicKey)->second.get();
      setObjectState(*m_blockchainSynchronizer.getConsumerState(consumer), consumerState.state);
      for (const auto& sub : consumerState.subscriptionStates) {
        setObjectState(consumer->getSubscription(sub.first)->getContainer(), sub.second);
      }
    }
    throw;
  }

}

bool TransfersSyncronizer::removeSubscription(const AccountPublicAddress& account)
{
  auto it = m_viewPublicKeyConsumersMap.find(account.viewPublicKey);
  if (it == m_viewPublicKeyConsumersMap.end())
  {
    return false;
  }

  TransfersConsumer* transfersConsumerPtr = it->second.get();

  if (transfersConsumerPtr->removeSubscription(account)) {
    m_blockchainSynchronizer.removeConsumer(transfersConsumerPtr);
    m_viewPublicKeyConsumersMap.erase(it);

    m_subscribersMap.erase(account.viewPublicKey);
  }

  return true;
}

void TransfersSyncronizer::save(std::ostream& outputStream)
{
  m_blockchainSynchronizer.save(outputStream);

  Common::StdOutputStream stream(outputStream);
  BinaryOutputStreamSerializer serializer(stream);
  serializer(const_cast<uint32_t&>(TRANSFERS_STORAGE_ARCHIVE_VERSION), "version");

  size_t subscriptionCount = m_viewPublicKeyConsumersMap.size();

  serializer.beginArray(subscriptionCount, "consumers");

  for (const auto& viewPublicKeyConsumer : m_viewPublicKeyConsumersMap) {
    serializer.beginObject("");

    serializer(const_cast<Crypto::PublicKey&>(viewPublicKeyConsumer.first), "view_key");

    // synchronization state
    std::stringstream consumerState;

    TransfersConsumer* transfersConsumerPtr = viewPublicKeyConsumer.second.get();

    m_blockchainSynchronizer.getConsumerState(transfersConsumerPtr)->save(consumerState);

    std::string blob = consumerState.str();
    serializer(blob, "state");
    
    std::vector<AccountPublicAddress> subscriptions;
    viewPublicKeyConsumer.second->getSubscriptions(subscriptions);
    size_t subscriptionsCount = subscriptions.size();

    serializer.beginArray(subscriptionsCount, "subscriptions");

    for (AccountPublicAddress& address : subscriptions) {
      ITransfersSubscription* subscriptionPtr = viewPublicKeyConsumer.second->getSubscription(address);
      if (subscriptionPtr != nullptr) {
        serializer.beginObject("");

        std::stringstream subscriptionState;
        assert(subscriptionPtr);
        subscriptionPtr->getContainer().save(subscriptionState);
        // store data block
        std::string blob = subscriptionState.str();
        serializer(address, "address");
        serializer(blob, "state");

        serializer.endObject();
      }
    }

    serializer.endArray();
    serializer.endObject();
  }
}

void TransfersSyncronizer::subscribeConsumerNotifications(const Crypto::PublicKey& viewPublicKey, ITransfersSynchronizerObserver* observer)
{
  auto it = m_subscribersMap.find(viewPublicKey);
  if (it != m_subscribersMap.end()) {
    it->second->add(observer);
    return;
  }

  auto insertedIt = m_subscribersMap.emplace(viewPublicKey, std::unique_ptr<SubscribersNotifier>(new SubscribersNotifier())).first;
  insertedIt->second->add(observer);
}

void TransfersSyncronizer::unsubscribeConsumerNotifications(const Crypto::PublicKey& viewPublicKey, ITransfersSynchronizerObserver* observer)
{
  m_subscribersMap.at(viewPublicKey)->remove(observer);
}


// Private functions


TransfersSyncronizer::SubscribersMap::const_iterator TransfersSyncronizer::findSubscriberForConsumer(IBlockchainConsumer* consumer) const
{
  Crypto::PublicKey viewPublicKey;
  if (findViewKeyForConsumer(consumer, viewPublicKey)) {
    auto it = m_subscribersMap.find(viewPublicKey);
    if (it != m_subscribersMap.end()) {
      return it;
    }
  }

  return m_subscribersMap.end();
}

bool TransfersSyncronizer::findViewKeyForConsumer(IBlockchainConsumer* consumer, Crypto::PublicKey& viewPublicKey) const
{
  //since we have only couple of consumers linear complexity is fine
  auto it = std::find_if(m_viewPublicKeyConsumersMap.begin(), m_viewPublicKeyConsumersMap.end(), [consumer] (const ViewPublicKeyConsumersMap::value_type& subscription) {
    return subscription.second.get() == consumer;
  });

  if (it == m_viewPublicKeyConsumersMap.end()) {
    return false;
  }

  viewPublicKey = it->first;
  return true;
}

void TransfersSyncronizer::onBlockchainDetach(IBlockchainConsumer* consumer, uint32_t blockIndex)
{
  auto it = findSubscriberForConsumer(consumer);
  if (it != m_subscribersMap.end()) {
    it->second->notify(&ITransfersSynchronizerObserver::onBlockchainDetach, it->first, blockIndex);
  }
}

void TransfersSyncronizer::onBlocksAdded(IBlockchainConsumer* consumer, const std::vector<Crypto::Hash>& blockHashes)
{
  auto it = findSubscriberForConsumer(consumer);
  if (it != m_subscribersMap.end()) {
    it->second->notify(&ITransfersSynchronizerObserver::onBlocksAdded, it->first, blockHashes);
  }
}

void TransfersSyncronizer::onTransactionDeleteBegin(IBlockchainConsumer* consumer, Crypto::Hash transactionHash)
{
  auto it = findSubscriberForConsumer(consumer);
  if (it != m_subscribersMap.end()) {
    it->second->notify(&ITransfersSynchronizerObserver::onTransactionDeleteBegin, it->first, transactionHash);
  }
}

void TransfersSyncronizer::onTransactionDeleteEnd(IBlockchainConsumer* consumer, Crypto::Hash transactionHash)
{
  auto it = findSubscriberForConsumer(consumer);
  if (it != m_subscribersMap.end()) {
    it->second->notify(&ITransfersSynchronizerObserver::onTransactionDeleteEnd, it->first, transactionHash);
  }
}

void TransfersSyncronizer::onTransactionUpdated(IBlockchainConsumer* consumer, const Crypto::Hash& transactionHash, const std::vector<ITransfersContainer*>& containers)
{

  auto it = findSubscriberForConsumer(consumer);
  if (it != m_subscribersMap.end()) {
    it->second->notify(&ITransfersSynchronizerObserver::onTransactionUpdated, it->first, transactionHash, containers);
  }
}

}