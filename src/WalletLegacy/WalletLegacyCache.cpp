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

TransactionId WalletLegacyCache::addNewTransaction(uint64_t amount, uint64_t fee, const std::string& extra, const std::vector<WalletLegacyTransfer>& transfers, uint64_t unlockTime)
{
  
  m_walletLegacyTransfers.insert(m_walletLegacyTransfers.end(), transfers.begin(), transfers.end());

  WalletLegacyTransaction transaction;

  transaction.firstTransferId =  m_walletLegacyTransfers.size() - transfers.size();
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

std::vector<TransactionId> WalletLegacyCache::deleteOutdatedTransactions()
{
  std::vector<TransactionId> deletedTransactions = m_unconfirmedTransactions.deleteOutdatedTransactions();

  for (TransactionId transactionId: deletedTransactions) {
    assert(transactionId < m_walletLegacyTransactions.size());
    m_walletLegacyTransactions[transactionId].state = WalletLegacyTransactionState::Deleted;
  }

  return deletedTransactions;
}

bool WalletLegacyCache::deserialize(CryptoNote::ISerializer& deserializer)
{
  if (deserializer.type() == CryptoNote::ISerializer::INPUT) {
    deserializer(m_walletLegacyTransactions, "transactions");
    deserializer(m_walletLegacyTransfers, "transfers");
    deserializer(m_unconfirmedTransactions, "unconfirmed");

    updateUnconfirmedTransactions();
    deleteOutdatedTransactions();
  }

  return true;
}

TransactionId WalletLegacyCache::findTransactionByHash(const Crypto::Hash& hash)
{
  for (TransactionId transactionId = 0; transactionId < m_walletLegacyTransactions.size(); transactionId++)
  {
    if (m_walletLegacyTransactions[transactionId].hash == hash)
    {
      return transactionId;
    }
  }

  return CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID;
}

TransactionId WalletLegacyCache::findTransactionByTransferId(TransferId transferId) const
{
  TransactionId transactionId;
  for (transactionId = 0; transactionId < m_walletLegacyTransactions.size(); transactionId++)
  {
    const WalletLegacyTransaction& transaction = m_walletLegacyTransactions[transactionId];

    if (transaction.firstTransferId != WALLET_LEGACY_INVALID_TRANSFER_ID &&
        transaction.transferCount != 0 &&
        transferId >= transaction.firstTransferId &&
        transferId < (transaction.firstTransferId + transaction.transferCount))
    {
      return transactionId;
    }
  }

  return WALLET_LEGACY_INVALID_TRANSACTION_ID;
}

WalletLegacyTransaction& WalletLegacyCache::getTransaction(TransactionId transactionId) // function throws an exception if transactionId is outside bounds of vector
{
  return m_walletLegacyTransactions.at(transactionId); // Returns a reference to the element at position n in the vector.
}

bool WalletLegacyCache::getTransaction(TransactionId transactionId, WalletLegacyTransaction& transaction) const
{
  if (transactionId >= m_walletLegacyTransactions.size())
  {
    return false;
  }

  transaction = m_walletLegacyTransactions[transactionId];

  return true;
}

size_t WalletLegacyCache::getTransactionCount() const
{
  return m_walletLegacyTransactions.size();
}

WalletLegacyTransfer& WalletLegacyCache::getTransfer(TransferId transferId) // function throws an exception if transferId is outside bounds of vector
{
  return m_walletLegacyTransfers.at(transferId); // Returns a reference to the element at position n in the vector.
}
  
bool WalletLegacyCache::getTransfer(TransferId transferId, WalletLegacyTransfer& transfer) const
{
  if (transferId >= m_walletLegacyTransfers.size())
  {
    return false;
  }

  transfer = m_walletLegacyTransfers[transferId];

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
  TransactionId transactionId = CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID;
  if (m_unconfirmedTransactions.findTransactionId(transactionHash, transactionId)) {
    m_unconfirmedTransactions.erase(transactionHash);
    assert(false); // What does this line do? Does it just crash the SimpleWallet program?
  } else {
    transactionId = findTransactionByHash(transactionHash);
  }

  std::shared_ptr<WalletLegacyEvent> event;
  if (transactionId != CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID) {
    WalletLegacyTransaction& transaction = getTransaction(transactionId);
    transaction.blockIndex = WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT;
    transaction.timestamp = 0;
    transaction.state = WalletLegacyTransactionState::Deleted;

    event = std::make_shared<WalletTransactionUpdatedEvent>(transactionId);
  } else {
    assert(false); // What does this line do? Does it just crash the SimpleWallet program?
  }

  return event;
}

std::shared_ptr<WalletLegacyEvent> WalletLegacyCache::onTransactionUpdated(const TransactionInformation& txInfo, int64_t balance)
{
  std::shared_ptr<WalletLegacyEvent> event;

  TransactionId transactionId = CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID;

  if (m_unconfirmedTransactions.findTransactionId(txInfo.transactionHash, transactionId))
  {
    m_unconfirmedTransactions.erase(txInfo.transactionHash);
  }
  else
  {
    transactionId = findTransactionByHash(txInfo.transactionHash);
  }

  bool isCoinbase = txInfo.totalAmountIn == 0;

  if (transactionId == CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID)
  {
    WalletLegacyTransaction transaction;
    transaction.firstTransferId = WALLET_LEGACY_INVALID_TRANSFER_ID;
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
    transactionId = m_walletLegacyTransactions.size() - 1;

    event = std::make_shared<WalletExternalTransactionCreatedEvent>(transactionId);
  }
  else
  {
    WalletLegacyTransaction& transactionRef = getTransaction(transactionId);
    transactionRef.blockIndex = txInfo.blockHeight;
    transactionRef.timestamp = txInfo.timestamp;
    transactionRef.state = WalletLegacyTransactionState::Active;

    event = std::make_shared<WalletTransactionUpdatedEvent>(transactionId);
  }

  return event;
}

void WalletLegacyCache::reset()
{
  m_walletLegacyTransactions.clear();
  m_walletLegacyTransfers.clear();
  m_unconfirmedTransactions.reset();
}

bool WalletLegacyCache::serialize(CryptoNote::ISerializer& s)
{
  if (s.type() == CryptoNote::ISerializer::INPUT) {
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

void WalletLegacyCache::updateTransaction(TransactionId transactionId, const CryptoNote::Transaction& transaction, uint64_t amount, const std::list<TransactionOutputInformation>& usedOutputs, const Crypto::SecretKey& transactionPrivateKey)
{
  // update extra field from created transaction
  WalletLegacyTransaction& transactionRef = m_walletLegacyTransactions.at(transactionId);
  transactionRef.extra.assign(transaction.extra.begin(), transaction.extra.end());
  transactionRef.secretKey = transactionPrivateKey;                                                                              
  m_unconfirmedTransactions.add(transaction, transactionId, amount, usedOutputs, transactionPrivateKey);
}

void WalletLegacyCache::updateTransactionSendingState(TransactionId transactionId, std::error_code ec)
{
  WalletLegacyTransaction& transactionRef = m_walletLegacyTransactions.at(transactionId);
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

  for (TransactionId transactionId = 0; transactionId < m_walletLegacyTransactions.size(); ++transactionId)
  {
    WalletLegacyTransactionState transactionState = m_walletLegacyTransactions[transactionId].state;

    if (transactionState != WalletLegacyTransactionState::Cancelled &&
      transactionState != WalletLegacyTransactionState::Failed)
    {
      transactions.push_back(m_walletLegacyTransactions[transactionId]);

      WalletLegacyTransaction& transactionRef = transactions.back();

      if (transactionRef.firstTransferId != WALLET_LEGACY_INVALID_TRANSFER_ID) {
        std::vector<WalletLegacyTransfer>::const_iterator first = m_walletLegacyTransfers.begin() + transactionRef.firstTransferId;
        std::vector<WalletLegacyTransfer>::const_iterator last = first + transactionRef.transferCount;

        transactionRef.firstTransferId -= offset;

        transfers.insert(transfers.end(), first, last);
      }
    }
    else
    {
      const WalletLegacyTransaction& transaction = m_walletLegacyTransactions[transactionId];

      if (transaction.firstTransferId != WALLET_LEGACY_INVALID_TRANSFER_ID)
      {
        offset += transaction.transferCount;
      }
    }
  }
}

void WalletLegacyCache::updateUnconfirmedTransactions()
{
  for (TransactionId transactionId = 0; transactionId < m_walletLegacyTransactions.size(); ++transactionId) {
    if (m_walletLegacyTransactions[transactionId].blockIndex == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
      m_unconfirmedTransactions.updateTransactionId(m_walletLegacyTransactions[transactionId].hash, transactionId);
    }
  }
}

} //namespace CryptoNote
