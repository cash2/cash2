// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "IWalletLegacy.h"
#include "TransfersSubscription.h"

using namespace Crypto;

namespace CryptoNote {

TransfersSubscription::TransfersSubscription(const CryptoNote::Currency& currency, const AccountSubscription& subscription) :
  m_accountSubscription(subscription),
  m_transfersContainer(currency, subscription.transactionSpendableAge) {
}

bool TransfersSubscription::advanceHeight(uint32_t blockchainHeight)
{
  return m_transfersContainer.advanceHeight(blockchainHeight);
}

bool TransfersSubscription::addTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfersList)
{
  bool added = m_transfersContainer.addTransaction(blockInfo, transactionReader, transfersList);
  
  if (added) {
    m_observerManager.notify(&ITransfersObserver::onTransactionUpdated, this, transactionReader.getTransactionHash());
  }

  return added;
}

void TransfersSubscription::deleteUnconfirmedTransaction(const Hash& transactionHash)
{
  if (m_transfersContainer.deleteUnconfirmedTransaction(transactionHash)) {
    m_observerManager.notify(&ITransfersObserver::onTransactionDeleted, this, transactionHash);
  }
}

AccountPublicAddress TransfersSubscription::getAddress()
{
  return m_accountSubscription.keys.address;
}

ITransfersContainer& TransfersSubscription::getContainer()
{
  return m_transfersContainer;
}

const AccountKeys& TransfersSubscription::getKeys() const
{
  return m_accountSubscription.keys;
}

SynchronizationStart TransfersSubscription::getSyncStart()
{
  return m_accountSubscription.syncStart;
}

void TransfersSubscription::markTransactionConfirmed(const TransactionBlockInfo& block, const Hash& transactionHash, const std::vector<uint32_t>& globalIndexes)
{
  m_transfersContainer.markTransactionConfirmed(block, transactionHash, globalIndexes);
  m_observerManager.notify(&ITransfersObserver::onTransactionUpdated, this, transactionHash);
}

void TransfersSubscription::onBlockchainDetach(uint32_t height)
{
  std::vector<Hash> deletedTransactions = m_transfersContainer.detach(height);
  for (auto& hash : deletedTransactions) {
    m_observerManager.notify(&ITransfersObserver::onTransactionDeleted, this, hash);
  }
}

void TransfersSubscription::onError(const std::error_code& ec, uint32_t height)
{
  if (height != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    m_transfersContainer.detach(height);
  }

  m_observerManager.notify(&ITransfersObserver::onError, this, height, ec);
}

}
