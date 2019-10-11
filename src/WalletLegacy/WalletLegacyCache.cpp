// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include "IWalletLegacy.h"
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "Wallet/WalletErrors.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletLegacy/WalletLegacyCache.h"
#include "WalletLegacy/WalletUtils.h"

namespace CryptoNote {


// Public functions


WalletLegacyCache::WalletLegacyCache(uint64_t mempoolTxLiveTime) : m_unconfirmedTransactions(mempoolTxLiveTime) {
}

size_t WalletLegacyCache::addNewTransaction(uint64_t amount, uint64_t fee, const std::string& extra, const std::vector<WalletLegacyTransfer>& transfers, uint64_t unlockTime)
{
  
  m_walletLegacyTransfers.insert(m_walletLegacyTransfers.end(), transfers.begin(), transfers.end());

  WalletLegacyTransaction transaction;

  transaction.firstTransferIndex =  m_walletLegacyTransfers.size() - transfers.size();
  transaction.transferCount = transfers.size();
  transaction.totalAmount = -static_cast<int64_t>(amount);
  transaction.fee = fee;
  transaction.sentTime = time(nullptr);
  transaction.isCoinbase = false;
  transaction.timestamp = 0;
  transaction.extra = extra;
  transaction.blockIndex = WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT;
  transaction.state = WalletLegacyTransactionState::Sending;
  transaction.unlockTime = unlockTime;
  transaction.secretKey = NULL_SECRET_KEY;

  m_walletLegacyTransactions.emplace_back(std::move(transaction));

  return m_walletLegacyTransactions.size() - 1;
}

std::vector<size_t> WalletLegacyCache::deleteOutdatedTransactions()
{
  std::vector<size_t> deletedTransactions = m_unconfirmedTransactions.deleteOutdatedTransactions();

  for (size_t transactionIndex: deletedTransactions) {
    assert(transactionIndex < m_walletLegacyTransactions.size());
    m_walletLegacyTransactions[transactionIndex].state = WalletLegacyTransactionState::Deleted;
  }

  return deletedTransactions;
}

bool WalletLegacyCache::deserialize(ISerializer& deserializer)
{
  if (deserializer.type() == ISerializer::INPUT) {
    deserializer(m_walletLegacyTransactions, "transactions");
    deserializer(m_walletLegacyTransfers, "transfers");
    deserializer(m_unconfirmedTransactions, "unconfirmed");

    updateUnconfirmedTransactions();
    deleteOutdatedTransactions();
  }

  return true;
}

size_t WalletLegacyCache::findTransactionByHash(const Crypto::Hash& hash)
{
  for (size_t transactionIndex = 0; transactionIndex < m_walletLegacyTransactions.size(); transactionIndex++)
  {
    if (m_walletLegacyTransactions[transactionIndex].hash == hash)
    {
      return transactionIndex;
    }
  }

  return WALLET_LEGACY_INVALID_TRANSACTION_INDEX;
}

size_t WalletLegacyCache::findTransactionByTransferId(size_t transferIndex) const
{
  size_t transactionIndex;
  for (transactionIndex = 0; transactionIndex < m_walletLegacyTransactions.size(); transactionIndex++)
  {
    const WalletLegacyTransaction& transaction = m_walletLegacyTransactions[transactionIndex];

    if (transaction.firstTransferIndex != WALLET_LEGACY_INVALID_TRANSFER_INDEX &&
        transaction.transferCount != 0 &&
        transferIndex >= transaction.firstTransferIndex &&
        transferIndex < (transaction.firstTransferIndex + transaction.transferCount))
    {
      return transactionIndex;
    }
  }

  return WALLET_LEGACY_INVALID_TRANSACTION_INDEX;
}

WalletLegacyTransaction& WalletLegacyCache::getTransaction(size_t transactionIndex) // function throws an exception if transactionIndex is outside bounds of vector
{
  return m_walletLegacyTransactions.at(transactionIndex); // Returns a reference to the element at position n in the vector.
}

bool WalletLegacyCache::getTransaction(size_t transactionIndex, WalletLegacyTransaction& transaction) const
{
  if (transactionIndex >= m_walletLegacyTransactions.size())
  {
    return false;
  }

  transaction = m_walletLegacyTransactions[transactionIndex];

  return true;
}

size_t WalletLegacyCache::getTransactionCount() const
{
  return m_walletLegacyTransactions.size();
}

WalletLegacyTransfer& WalletLegacyCache::getTransfer(size_t transferIndex) // function throws an exception if transferIndex is outside bounds of vector
{
  return m_walletLegacyTransfers.at(transferIndex); // Returns a reference to the element at position n in the vector.
}
  
bool WalletLegacyCache::getTransfer(size_t transferIndex, WalletLegacyTransfer& transfer) const
{
  if (transferIndex >= m_walletLegacyTransfers.size())
  {
    return false;
  }

  transfer = m_walletLegacyTransfers[transferIndex];

  return true;
}

size_t WalletLegacyCache::getTransferCount() const
{
  return m_walletLegacyTransfers.size();
}

bool WalletLegacyCache::isUsed(const TransactionOutputInformation& out) const
{
  return m_unconfirmedTransactions.isUsed(out);
}

std::shared_ptr<WalletLegacyEvent> WalletLegacyCache::onTransactionDeleted(const Crypto::Hash& transactionHash)
{
  size_t transactionIndex = WALLET_LEGACY_INVALID_TRANSACTION_INDEX;
  if (m_unconfirmedTransactions.findTransactionId(transactionHash, transactionIndex)) {
    m_unconfirmedTransactions.erase(transactionHash);
    assert(false); // What does this line do? Does it just crash the SimpleWallet program?
  } else {
    transactionIndex = findTransactionByHash(transactionHash);
  }

  std::shared_ptr<WalletLegacyEvent> event;
  if (transactionIndex != WALLET_LEGACY_INVALID_TRANSACTION_INDEX) {
    WalletLegacyTransaction& transaction = getTransaction(transactionIndex);
    transaction.blockIndex = WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT;
    transaction.timestamp = 0;
    transaction.state = WalletLegacyTransactionState::Deleted;

    event = std::make_shared<WalletTransactionUpdatedEvent>(transactionIndex);
  } else {
    assert(false); // What does this line do? Does it just crash the SimpleWallet program?
  }

  return event;
}

std::shared_ptr<WalletLegacyEvent> WalletLegacyCache::onTransactionUpdated(const TransactionInformation& txInfo, int64_t balance)
{
  std::shared_ptr<WalletLegacyEvent> event;

  size_t transactionIndex = WALLET_LEGACY_INVALID_TRANSACTION_INDEX;

  if (m_unconfirmedTransactions.findTransactionId(txInfo.transactionHash, transactionIndex))
  {
    m_unconfirmedTransactions.erase(txInfo.transactionHash);
  }
  else
  {
    transactionIndex = findTransactionByHash(txInfo.transactionHash);
  }

  bool isCoinbase = txInfo.totalAmountIn == 0;

  if (transactionIndex == WALLET_LEGACY_INVALID_TRANSACTION_INDEX)
  {
    WalletLegacyTransaction transaction;
    transaction.firstTransferIndex = WALLET_LEGACY_INVALID_TRANSFER_INDEX;
    transaction.transferCount = 0;
    transaction.totalAmount = balance;
    transaction.fee = isCoinbase ? 0 : txInfo.totalAmountIn - txInfo.totalAmountOut;
    transaction.sentTime = 0;
    transaction.hash = txInfo.transactionHash;
    transaction.blockIndex = txInfo.blockHeight;
    transaction.isCoinbase = isCoinbase;
    transaction.timestamp = txInfo.timestamp;
    transaction.extra.assign(txInfo.extra.begin(), txInfo.extra.end());
    transaction.state = WalletLegacyTransactionState::Active;
    transaction.unlockTime = txInfo.unlockTime;
    transaction.secretKey = NULL_SECRET_KEY;

    m_walletLegacyTransactions.emplace_back(std::move(transaction));
    transactionIndex = m_walletLegacyTransactions.size() - 1;

    event = std::make_shared<WalletExternalTransactionCreatedEvent>(transactionIndex);
  }
  else
  {
    WalletLegacyTransaction& transactionRef = getTransaction(transactionIndex);
    transactionRef.blockIndex = txInfo.blockHeight;
    transactionRef.timestamp = txInfo.timestamp;
    transactionRef.state = WalletLegacyTransactionState::Active;

    event = std::make_shared<WalletTransactionUpdatedEvent>(transactionIndex);
  }

  return event;
}

void WalletLegacyCache::reset()
{
  m_walletLegacyTransactions.clear();
  m_walletLegacyTransfers.clear();
  m_unconfirmedTransactions.reset();
}

bool WalletLegacyCache::serialize(ISerializer& s)
{
  if (s.type() == ISerializer::INPUT) {
    s(m_walletLegacyTransactions, "transactions");
    s(m_walletLegacyTransfers, "transfers");
    s(m_unconfirmedTransactions, "unconfirmed");

    updateUnconfirmedTransactions();
    deleteOutdatedTransactions();
  } else {
    std::vector<WalletLegacyTransaction> txsToSave;
    std::vector<WalletLegacyTransfer> transfersToSave;

    getValidTransactionsAndTransfers(txsToSave, transfersToSave);
    s(txsToSave, "transactions");
    s(transfersToSave, "transfers");
    s(m_unconfirmedTransactions, "unconfirmed");
  }

  return true;
}

uint64_t WalletLegacyCache::unconfirmedTransactionsAmount() const
{
  return m_unconfirmedTransactions.countUnconfirmedTransactionsAmount();
}

uint64_t WalletLegacyCache::unconfrimedOutsAmount() const
{
  return m_unconfirmedTransactions.countUnconfirmedOutsAmount();
}

void WalletLegacyCache::updateTransaction(size_t transactionIndex, const Transaction& transaction, uint64_t amount, const std::list<TransactionOutputInformation>& usedOutputs, const Crypto::SecretKey& transactionPrivateKey)
{
  // update extra field from created transaction
  WalletLegacyTransaction& transactionRef = m_walletLegacyTransactions.at(transactionIndex);
  transactionRef.extra.assign(transaction.extra.begin(), transaction.extra.end());
  transactionRef.secretKey = transactionPrivateKey;                                                                              
  m_unconfirmedTransactions.add(transaction, transactionIndex, amount, usedOutputs, transactionPrivateKey);
}

void WalletLegacyCache::updateTransactionSendingState(size_t transactionIndex, std::error_code ec)
{
  WalletLegacyTransaction& transactionRef = m_walletLegacyTransactions.at(transactionIndex);
  if (ec) {
    transactionRef.state = ec.value() == error::TX_CANCELLED ? WalletLegacyTransactionState::Cancelled : WalletLegacyTransactionState::Failed;
    m_unconfirmedTransactions.erase(transactionRef.hash);
  } else {
    transactionRef.sentTime = time(nullptr);
    transactionRef.state = WalletLegacyTransactionState::Active;
  }
}


// Private functions


void WalletLegacyCache::getValidTransactionsAndTransfers(std::vector<WalletLegacyTransaction>& transactions, std::vector<WalletLegacyTransfer>& transfers)
{
  size_t offset = 0;

  for (size_t transactionIndex = 0; transactionIndex < m_walletLegacyTransactions.size(); ++transactionIndex)
  {
    WalletLegacyTransactionState transactionState = m_walletLegacyTransactions[transactionIndex].state;

    if (transactionState != WalletLegacyTransactionState::Cancelled &&
      transactionState != WalletLegacyTransactionState::Failed)
    {
      transactions.push_back(m_walletLegacyTransactions[transactionIndex]);

      WalletLegacyTransaction& transactionRef = transactions.back();

      if (transactionRef.firstTransferIndex != WALLET_LEGACY_INVALID_TRANSFER_INDEX) {
        std::vector<WalletLegacyTransfer>::const_iterator first = m_walletLegacyTransfers.begin() + transactionRef.firstTransferIndex;
        std::vector<WalletLegacyTransfer>::const_iterator last = first + transactionRef.transferCount;

        transactionRef.firstTransferIndex -= offset;

        transfers.insert(transfers.end(), first, last);
      }
    }
    else
    {
      const WalletLegacyTransaction& transaction = m_walletLegacyTransactions[transactionIndex];

      if (transaction.firstTransferIndex != WALLET_LEGACY_INVALID_TRANSFER_INDEX)
      {
        offset += transaction.transferCount;
      }
    }
  }
}

void WalletLegacyCache::updateUnconfirmedTransactions()
{
  for (size_t transactionIndex = 0; transactionIndex < m_walletLegacyTransactions.size(); ++transactionIndex) {
    if (m_walletLegacyTransactions[transactionIndex].blockIndex == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
      m_unconfirmedTransactions.updateTransactionId(m_walletLegacyTransactions[transactionIndex].hash, transactionIndex);
    }
  }
}

} //namespace CryptoNote
