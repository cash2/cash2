// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "IWalletLegacy.h"
#include "ITransfersContainer.h"

#include <unordered_map>
#include <unordered_set>
#include <time.h>
#include <boost/functional/hash.hpp>

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {
class ISerializer;

typedef std::pair<Crypto::PublicKey, size_t> TransactionOutputId;
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
    amount(0), sentTime(0), transactionIndex(WALLET_LEGACY_INVALID_TRANSACTION_INDEX) {}

  Transaction tx;
  uint64_t amount;
  uint64_t outsAmount;
  time_t sentTime;
  size_t transactionIndex;
  std::vector<TransactionOutputId> usedOutputs;
  Crypto::SecretKey secretKey;                            
};

class WalletUnconfirmedTransactions
{
public:

  explicit WalletUnconfirmedTransactions(uint64_t uncofirmedTransactionsLiveTime);

  bool serialize(ISerializer& s);

  bool findTransactionId(const Crypto::Hash& hash, size_t& transactionIndex);
  void erase(const Crypto::Hash& hash);
  void add(const Transaction& tx, size_t transactionIndex, 
    uint64_t amount, const std::list<TransactionOutputInformation>& usedOutputs, const Crypto::SecretKey& tx_key);
  void updateTransactionId(const Crypto::Hash& hash, size_t transactionIndex);

  uint64_t countUnconfirmedOutsAmount() const;
  uint64_t countUnconfirmedTransactionsAmount() const;
  bool isUsed(const TransactionOutputInformation& out) const;
  void reset();

  std::vector<size_t> deleteOutdatedTransactions();

private:

  void collectUsedOutputs();
  void deleteUsedOutputs(const std::vector<TransactionOutputId>& usedOutputs);

  typedef std::unordered_map<Crypto::Hash, UnconfirmedTransferDetails, boost::hash<Crypto::Hash>> UnconfirmedTxsContainer;
  typedef std::unordered_set<TransactionOutputId> UsedOutputsContainer;

  UnconfirmedTxsContainer m_unconfirmedTxs;
  UsedOutputsContainer m_usedOutputs;
  uint64_t m_uncofirmedTransactionsLiveTime;
};

} // namespace CryptoNote
