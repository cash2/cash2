// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/functional/hash.hpp>
#include <time.h>
#include <unordered_map>
#include <unordered_set>

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "ITransfersContainer.h"
#include "IWalletLegacy.h"
#include "Serialization/ISerializer.h"
#include "crypto/crypto.h"

namespace CryptoNote {

typedef std::pair<Crypto::PublicKey, size_t> TransactionOutputId; // { transactionPublicKey, outputInTransaction }

}

namespace std {

template<> 
struct hash<CryptoNote::TransactionOutputId> {
  size_t operator()(const CryptoNote::TransactionOutputId &_v) const {    
    return hash<Crypto::PublicKey>()(_v.first) ^ _v.second;
  } 
}; 

}

namespace CryptoNote {


struct UnconfirmedTransferDetails {

  UnconfirmedTransferDetails() :
    amount(0),
    sentTime(0),
    transactionIndex(WALLET_LEGACY_INVALID_TRANSACTION_INDEX) {
  }

  uint64_t amount;
  uint64_t outsAmount;
  Crypto::SecretKey secretKey;
  time_t sentTime;
  Transaction transaction;
  size_t transactionIndex;
  std::vector<TransactionOutputId> usedTransactionOutputIds;
};

class WalletUnconfirmedTransactions
{

public:
  explicit WalletUnconfirmedTransactions(uint64_t uncofirmedTransactionsLiveTime);
  void add(const Transaction& tx, size_t transactionIndex, uint64_t amount, const std::list<TransactionOutputInformation>& usedTransactionOutputs, const Crypto::SecretKey& tx_key);
  void erase(const Crypto::Hash& hash);
  uint64_t getTotalUnconfirmedOutsAmount() const;
  uint64_t getTotalUnconfirmedTransactionsAmount() const;
  bool getTransactionIndexFromHash(const Crypto::Hash& transactionHash, size_t& transactionIndex) const;
  bool isUsed(const TransactionOutputInformation& output) const;
  void reset();
  bool serialize(ISerializer& serializer);
  void updateTransactionId(const Crypto::Hash& hash, size_t transactionIndex);
  std::vector<size_t> deleteOutdatedTransactions();

private:
  uint64_t m_uncofirmedTransactionsLiveTime;
  std::unordered_map<Crypto::Hash, UnconfirmedTransferDetails, boost::hash<Crypto::Hash>> m_unconfirmedTransferDetailsContainer; // map key is the transaction hash
  std::unordered_set<TransactionOutputId> m_usedTransactionOutputIdsContainer;

};

} // end namespace CryptoNote
