// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "crypto/hash.h"
#include "ITransfersContainer.h"
#include "IWalletLegacy.h"
#include "Serialization/ISerializer.h"
#include "WalletLegacy/WalletLegacyEvent.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"

namespace CryptoNote {

class WalletLegacyCache
{
public:
  explicit WalletLegacyCache(uint64_t mempoolTxLiveTime = 60 * 60 * 24);
  size_t addNewTransaction(uint64_t amount, uint64_t fee, const std::string& extra, const std::vector<WalletLegacyTransfer>& transfers, uint64_t unlockTime);
  std::vector<size_t> deleteOutdatedTransactions();
  bool deserialize(ISerializer& deserializer);
  WalletLegacyTransaction& getTransaction(size_t transactionIndex);
  bool getTransaction(size_t transactionIndex, WalletLegacyTransaction& transaction) const;
  size_t getTransactionCount() const;
  size_t getTransactionIndex(const Crypto::Hash& transactionHash);                                                              
  size_t getTransactionIndex(size_t transferIndex) const;
  WalletLegacyTransfer& getTransfer(size_t transferIndex);
  bool getTransfer(size_t transferIndex, WalletLegacyTransfer& transfer) const;
  size_t getTransferCount() const;
  bool isUsed(const TransactionOutputInformation& out) const;
  std::shared_ptr<WalletLegacyEvent> onTransactionDeleted(const Crypto::Hash& transactionHash);
  std::shared_ptr<WalletLegacyEvent> onTransactionUpdated(const TransactionInformation& txInfo, int64_t txBalance);
  void reset();
  bool serialize(ISerializer& serializer);
  uint64_t unconfirmedTransactionsAmount() const;
  uint64_t unconfrimedOutsAmount() const;
  void updateTransaction(size_t transactionIndex, const Transaction& tx, uint64_t amount, const std::list<TransactionOutputInformation>& usedOutputs, const Crypto::SecretKey& tx_key);
  void updateTransactionSendingState(size_t transactionIndex, std::error_code ec);
    
private:
  void getValidTransactionsAndTransfers(std::vector<WalletLegacyTransaction>& transactions, std::vector<WalletLegacyTransfer>& transfers);
  void updateUnconfirmedTransactions();

  std::vector<WalletLegacyTransaction> m_walletLegacyTransactions;
  std::vector<WalletLegacyTransfer> m_walletLegacyTransfers;
  WalletUnconfirmedTransactions m_unconfirmedTransactions;
};

} //namespace CryptoNote
