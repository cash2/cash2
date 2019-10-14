// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include "crypto/crypto.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/Currency.h"
#include "ITransaction.h"
#include "ITransfersContainer.h"
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"

namespace CryptoNote {

struct TransactionOutputInformationIn;

class SpentOutputDescriptor {
public:
  SpentOutputDescriptor();
  SpentOutputDescriptor(const TransactionOutputInformationIn& transactionInfo);
  SpentOutputDescriptor(const Crypto::KeyImage* keyImage);
  SpentOutputDescriptor(uint64_t amount, uint32_t globalOutputIndex);

  void assign(const Crypto::KeyImage* keyImage);
  void assign(uint64_t amount, uint32_t globalOutputIndex);
  size_t hash() const;
  bool isValid() const;
  bool operator==(const SpentOutputDescriptor& other) const;

private:
  TransactionTypes::OutputType m_type;
  union {
    const Crypto::KeyImage* m_keyImage;
    struct {
      uint64_t m_amount;
      uint32_t m_globalOutputIndex;
    };
  };
};

struct SpentOutputDescriptorHasher {
  size_t operator()(const SpentOutputDescriptor& descriptor) const {
    return descriptor.hash();
  }
};

struct TransactionOutputInformationIn : public TransactionOutputInformation {
  Crypto::KeyImage keyImage;  //!< \attention Used only for TransactionTypes::OutputType::Key
};

struct TransactionOutputInformationEx : public TransactionOutputInformationIn {
  uint64_t unlockTime;
  uint32_t blockHeight;
  uint32_t transactionIndex;
  bool visible;

  SpentOutputDescriptor getSpentOutputDescriptor() const { return SpentOutputDescriptor(*this); }
  const Crypto::Hash& getTransactionHash() const { return transactionHash; }

  void serialize(CryptoNote::ISerializer& s) {
    s(reinterpret_cast<uint8_t&>(type), "type");
    s(amount, "");
    serializeGlobalOutputIndex(s, globalOutputIndex, "");
    s(outputInTransaction, "");
    s(transactionPublicKey, "");
    s(keyImage, "");
    s(unlockTime, "");
    serializeBlockHeight(s, blockHeight, "");
    s(transactionIndex, "");
    s(transactionHash, "");
    s(visible, "");

    if (type == TransactionTypes::OutputType::Key)
    {
      s(outputKey, "");
    }
    else if (type == TransactionTypes::OutputType::Multisignature)
    {
      s(requiredSignatures, "");
    }
  }

};

struct TransactionBlockInfo {
  uint32_t height;
  uint64_t timestamp;
  uint32_t transactionIndex;

  void serialize(ISerializer& s) {
    serializeBlockHeight(s, height, "height");
    s(timestamp, "timestamp");
    s(transactionIndex, "transactionIndex");
  }
};

struct SpentTransactionOutput : TransactionOutputInformationEx {
  TransactionBlockInfo spendingBlock;
  Crypto::Hash spendingTransactionHash;
  uint32_t inputInTransaction;

  const Crypto::Hash& getSpendingTransactionHash() const {
    return spendingTransactionHash;
  }

  void serialize(ISerializer& s) {
    TransactionOutputInformationEx::serialize(s);
    s(spendingBlock, "spendingBlock");
    s(spendingTransactionHash, "spendingTransactionHash");
    s(inputInTransaction, "inputInTransaction");
  }
};

enum class KeyImageState {
  Unconfirmed,
  Confirmed,
  Spent
};

struct KeyOutputInfo {
  KeyImageState state;
  size_t count;
};

class TransfersContainer : public ITransfersContainer {

public:

  TransfersContainer(const CryptoNote::Currency& currency, size_t transactionSpendableAge);

  bool addTransaction(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers);
  bool advanceHeight(uint32_t height);
  virtual uint64_t balance(uint32_t flags) const override;
  bool deleteUnconfirmedTransaction(const Crypto::Hash& transactionHash);
  std::vector<Crypto::Hash> detach(uint32_t height);
  virtual void getOutputs(std::vector<TransactionOutputInformation>& transfers, uint32_t flags) const override;
  virtual std::vector<TransactionSpentOutputInformation> getSpentOutputs() const override;
  virtual bool getTransactionInformation(const Crypto::Hash& transactionHash, TransactionInformation& info, uint64_t* amountIn = nullptr, uint64_t* amountOut = nullptr) const override;
  virtual std::vector<TransactionOutputInformation> getTransactionInputs(const Crypto::Hash& transactionHash, uint32_t flags) const override; // only type flags are feasible for this function
  virtual std::vector<TransactionOutputInformation> getTransactionOutputs(const Crypto::Hash& transactionHash, uint32_t flags) const override;
  virtual void getUnconfirmedTransactions(std::vector<Crypto::Hash>& transactionHashes) const override;
  virtual void load(std::istream& in) override;
  bool markTransactionConfirmed(const TransactionBlockInfo& block, const Crypto::Hash& transactionHash, const std::vector<uint32_t>& globalIndexes);
  virtual void save(std::ostream& os) override;
  virtual size_t transactionsCount() const override;
  virtual size_t transfersCount() const override;

private:
  struct ContainingTransactionIndex { };
  struct SpendingTransactionIndex { };
  struct SpentOutputDescriptorIndex { };

  typedef
  boost::multi_index_container
  <
    TransactionInformation,
    boost::multi_index::indexed_by
    <
      boost::multi_index::hashed_unique<BOOST_MULTI_INDEX_MEMBER(TransactionInformation, Crypto::Hash, transactionHash)>,
      boost::multi_index::ordered_non_unique < BOOST_MULTI_INDEX_MEMBER(TransactionInformation, uint32_t, blockHeight) >
    >
  > TransactionMultiIndex;

  typedef
  boost::multi_index_container
  <
    TransactionOutputInformationEx,
    boost::multi_index::indexed_by
    <
      boost::multi_index::hashed_non_unique
      <
        boost::multi_index::tag<SpentOutputDescriptorIndex>,
        boost::multi_index::const_mem_fun
        <
          TransactionOutputInformationEx,
          SpentOutputDescriptor,
          &TransactionOutputInformationEx::getSpentOutputDescriptor
        >,
        SpentOutputDescriptorHasher
      >,
      boost::multi_index::hashed_non_unique
      <
        boost::multi_index::tag<ContainingTransactionIndex>,
        boost::multi_index::const_mem_fun
        <
          TransactionOutputInformationEx,
          const Crypto::Hash&,
          &TransactionOutputInformationEx::getTransactionHash
        >
      >
    >
  > UnconfirmedTransfersMultiIndex;

  typedef
  boost::multi_index_container
  <
    TransactionOutputInformationEx,
    boost::multi_index::indexed_by
    <
      boost::multi_index::hashed_non_unique
      <
        boost::multi_index::tag<SpentOutputDescriptorIndex>,
        boost::multi_index::const_mem_fun
        <
          TransactionOutputInformationEx,
          SpentOutputDescriptor,
          &TransactionOutputInformationEx::getSpentOutputDescriptor
        >,
        SpentOutputDescriptorHasher
      >,
      boost::multi_index::hashed_non_unique
      <
        boost::multi_index::tag<ContainingTransactionIndex>,
        boost::multi_index::const_mem_fun
        <
          TransactionOutputInformationEx,
          const Crypto::Hash&,
          &TransactionOutputInformationEx::getTransactionHash
        >
      >
    >
  > AvailableTransfersMultiIndex;

  typedef boost::multi_index_container
  <
    SpentTransactionOutput,
    boost::multi_index::indexed_by
    <
      boost::multi_index::hashed_unique
      <
        boost::multi_index::tag<SpentOutputDescriptorIndex>,
        boost::multi_index::const_mem_fun<
          TransactionOutputInformationEx,
          SpentOutputDescriptor,
          &TransactionOutputInformationEx::getSpentOutputDescriptor>,
        SpentOutputDescriptorHasher
      >,
      boost::multi_index::hashed_non_unique
      <
        boost::multi_index::tag<ContainingTransactionIndex>,
        boost::multi_index::const_mem_fun<
          TransactionOutputInformationEx,
          const Crypto::Hash&,
          &SpentTransactionOutput::getTransactionHash>
      >,
      boost::multi_index::hashed_non_unique <
        boost::multi_index::tag<SpendingTransactionIndex>,
        boost::multi_index::const_mem_fun <
          SpentTransactionOutput,
          const Crypto::Hash&,
          &SpentTransactionOutput::getSpendingTransactionHash>
      >
    >
  > SpentTransfersMultiIndex;

  void addTransaction(const TransactionBlockInfo& block, const ITransactionReader& transactionReader);
  bool addTransactionInputs(const TransactionBlockInfo& block, const ITransactionReader& transactionReader);
  bool addTransactionOutputs(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers);
  void copyToSpent(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, size_t inputIndex, const TransactionOutputInformationEx& output);
  void deleteTransactionTransfers(const Crypto::Hash& transactionHash);
  bool isIncluded(const TransactionOutputInformationEx& info, uint32_t flags) const;
  static bool isIncluded(TransactionTypes::OutputType type, uint32_t state, uint32_t flags);
  bool isSpendTimeUnlocked(uint64_t unlockTime) const;
  void updateTransfersVisibility(const Crypto::KeyImage& keyImage);

  AvailableTransfersMultiIndex m_availableTransfers;
  const CryptoNote::Currency& m_currency;
  uint32_t m_currentHeight; // current height is needed to check if a transfer is unlocked
  mutable std::mutex m_mutex;
  SpentTransfersMultiIndex m_spentTransfers;
  TransactionMultiIndex m_transactions;
  size_t m_transactionSpendableAge;
  UnconfirmedTransfersMultiIndex m_unconfirmedTransfers;

};

} // end namespace CryptoNote
