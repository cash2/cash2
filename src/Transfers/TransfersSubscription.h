// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "IObservableImpl.h"
#include "ITransfersSynchronizer.h"
#include "TransfersContainer.h"

namespace CryptoNote {

class TransfersSubscription : public IObservableImpl < ITransfersObserver, ITransfersSubscription > {

public:

  TransfersSubscription(const CryptoNote::Currency& currency, const AccountSubscription& subscription);
  bool advanceHeight(uint32_t blockchainHeight);
  bool addTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers);
  void deleteUnconfirmedTransaction(const Crypto::Hash& transactionHash);
  virtual AccountPublicAddress getAddress() override;
  virtual ITransfersContainer& getContainer() override;
  const AccountKeys& getKeys() const;
  SynchronizationStart getSyncStart();
  void markTransactionConfirmed(const TransactionBlockInfo& block, const Crypto::Hash& transactionHash, const std::vector<uint32_t>& globalIndexes);
  void onBlockchainDetach(uint32_t height);
  void onError(const std::error_code& ec, uint32_t height);

private:

  AccountSubscription m_accountSubscription;
  TransfersContainer m_transfersContainer;

};

} // end namespace CryptoNote
