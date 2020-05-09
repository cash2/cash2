// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletUnconfirmedTransactions.h"

namespace CryptoNote {


// Public functions


WalletUnconfirmedTransactions::WalletUnconfirmedTransactions(uint64_t uncofirmedTransactionsLiveTime):
  m_uncofirmedTransactionsLiveTime(uncofirmedTransactionsLiveTime) {

}

void WalletUnconfirmedTransactions::add(const Transaction& transaction, size_t transactionIndex, uint64_t amount, const std::list<TransactionOutputInformation>& usedTransactionOutputs, const Crypto::SecretKey& transactionPrivateKey) {

  Crypto::Hash transactionHash = getObjectHash(transaction);
  UnconfirmedTransferDetails& unconfirmedTransferDetailsRef = m_unconfirmedTransferDetailsContainer[transactionHash];

  unconfirmedTransferDetailsRef.amount = amount;
  unconfirmedTransferDetailsRef.sentTime = time(nullptr);
  unconfirmedTransferDetailsRef.transaction = transaction;
  unconfirmedTransferDetailsRef.transactionIndex = transactionIndex;
  unconfirmedTransferDetailsRef.secretKey = transactionPrivateKey;                       

  uint64_t transactionOutputsAmount = 0;
  // process used outputs
  unconfirmedTransferDetailsRef.usedTransactionOutputIds.reserve(usedTransactionOutputs.size());
  for (const TransactionOutputInformation& transactionOutput : usedTransactionOutputs) {
    TransactionOutputId transactionOutputId = std::make_pair(transactionOutput.transactionPublicKey, transactionOutput.outputInTransaction);
    unconfirmedTransferDetailsRef.usedTransactionOutputIds.push_back(transactionOutputId);
    m_usedTransactionOutputIdsContainer.insert(transactionOutputId);
    transactionOutputsAmount += transactionOutput.amount;
  }

  unconfirmedTransferDetailsRef.outsAmount = transactionOutputsAmount;
}

void WalletUnconfirmedTransactions::erase(const Crypto::Hash& hash) {
  auto it = m_unconfirmedTransferDetailsContainer.find(hash);
  if (it == m_unconfirmedTransferDetailsContainer.end()) {
    return;
  }

  for (const auto& output: it->second.usedTransactionOutputIds) {
    m_usedTransactionOutputIdsContainer.erase(output);
  }

  m_unconfirmedTransferDetailsContainer.erase(it);
}

uint64_t WalletUnconfirmedTransactions::getTotalUnconfirmedOutsAmount() const {
  
  uint64_t amount = 0;

  for (const auto& unconfirmedTransferDetails: m_unconfirmedTransferDetailsContainer)
  {
    amount += unconfirmedTransferDetails.second.outsAmount;
  }

  return amount;
}

uint64_t WalletUnconfirmedTransactions::getTotalUnconfirmedTransactionsAmount() const {
  uint64_t amount = 0;

  for (const auto& unconfirmedTransferDetails: m_unconfirmedTransferDetailsContainer)
  {
    amount += unconfirmedTransferDetails.second.amount;
  }

  return amount;
}

bool WalletUnconfirmedTransactions::getTransactionIndexFromHash(const Crypto::Hash& transactionHash, size_t& transactionIndex) const {
  auto it = m_unconfirmedTransferDetailsContainer.find(transactionHash);

  if (it == m_unconfirmedTransferDetailsContainer.end()) {
    return false;
  }

  transactionIndex = it->second.transactionIndex;

  return true;
}

bool WalletUnconfirmedTransactions::isUsed(const TransactionOutputInformation& output) const {
  TransactionOutputId transactionOutputId = std::make_pair(output.transactionPublicKey, output.outputInTransaction);
  return m_usedTransactionOutputIdsContainer.find(transactionOutputId) != m_usedTransactionOutputIdsContainer.end();
}

void WalletUnconfirmedTransactions::reset() {
  m_unconfirmedTransferDetailsContainer.clear();
  m_usedTransactionOutputIdsContainer.clear();
}

bool WalletUnconfirmedTransactions::serialize(ISerializer& serializer) {

  serializer(m_unconfirmedTransferDetailsContainer, "transactions");

  if (serializer.type() == ISerializer::INPUT) {
    // get used outputs from m_unconfirmedTransferDetailsContainer and put them in m_usedTransactionOutputIdsContainer
    std::unordered_set<TransactionOutputId> usedTransactionOutputIdsContainer;

    for (const auto& unconfirmedTransferDetails : m_unconfirmedTransferDetailsContainer) {
      usedTransactionOutputIdsContainer.insert(unconfirmedTransferDetails.second.usedTransactionOutputIds.begin(), unconfirmedTransferDetails.second.usedTransactionOutputIds.end());
    }

    m_usedTransactionOutputIdsContainer = std::move(usedTransactionOutputIdsContainer);
  }

  return true;
}

void WalletUnconfirmedTransactions::updateTransactionId(const Crypto::Hash& transactionHash, size_t transactionIndex)
{
  auto it = m_unconfirmedTransferDetailsContainer.find(transactionHash);
  if (it != m_unconfirmedTransferDetailsContainer.end())
  {
    it->second.transactionIndex = transactionIndex;
  }
}

std::vector<size_t> WalletUnconfirmedTransactions::deleteOutdatedTransactions()
{
  std::vector<size_t> deletedTransactions;

  uint64_t now = static_cast<uint64_t>(time(nullptr));

  assert(now >= m_uncofirmedTransactionsLiveTime);

  for (const auto& unconfirmedTransferDetails : m_unconfirmedTransferDetailsContainer)
  {
    if (static_cast<uint64_t>(unconfirmedTransferDetails.second.sentTime) <= now - m_uncofirmedTransactionsLiveTime)
    {
      for (const TransactionOutputId& usedTransactionOutputId : unconfirmedTransferDetails.second.usedTransactionOutputIds)
      {
        m_usedTransactionOutputIdsContainer.erase(usedTransactionOutputId);
      }

      deletedTransactions.push_back(unconfirmedTransferDetails.second.transactionIndex);

      m_unconfirmedTransferDetailsContainer.erase(unconfirmedTransferDetails.first);
    }
  }

  return deletedTransactions;

}

} // end namespace CryptoNote
