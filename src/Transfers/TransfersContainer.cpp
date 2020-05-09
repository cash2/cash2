// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "IWalletLegacy.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "TransfersContainer.h"

namespace CryptoNote {


// Public functions


void serialize(TransactionInformation& transactionInformation, CryptoNote::ISerializer& serializer)
{
  serializer(transactionInformation.transactionHash, "");
  serializer(transactionInformation.publicKey, "");
  serializeBlockHeight(serializer, transactionInformation.blockHeight, "");
  serializer(transactionInformation.timestamp, "");
  serializer(transactionInformation.unlockTime, "");
  serializer(transactionInformation.totalAmountIn, "");
  serializer(transactionInformation.totalAmountOut, "");
  serializer(transactionInformation.extra, "");
  serializer(transactionInformation.paymentId, "");
}

const uint32_t TRANSFERS_CONTAINER_STORAGE_VERSION = 0;

namespace
{
  template<typename TIterator>
  class TransferIteratorList {
  public:
    TransferIteratorList(const TIterator& begin, const TIterator& end) : m_end(end) {
      for (auto it = begin; it != end; ++it) {
        m_list.emplace_back(it);
      }
    }

    TransferIteratorList(TransferIteratorList<TIterator>&& other) {
      m_list = std::move(other.m_list);
      m_end = std::move(other.m_end);
    }

    TransferIteratorList& operator=(TransferIteratorList<TIterator>&& other) {
      m_list = std::move(other.m_list);
      m_end = std::move(other.m_end);
      return *this;
    }

    void sort() {
      std::sort(m_list.begin(), m_list.end(), &TransferIteratorList::lessTIterator);
    }

    TIterator findFirstByAmount(uint64_t amount) const {
      auto listIt = std::find_if(m_list.begin(), m_list.end(), [amount](const TIterator& it) {
        return it->amount == amount;
      });
      return listIt == m_list.end() ? m_end : *listIt;
    }

    TIterator minElement() const {
      auto listIt = std::min_element(m_list.begin(), m_list.end(), &TransferIteratorList::lessTIterator);
      return listIt == m_list.end() ? m_end : *listIt;
    }

  private:
    static bool lessTIterator(const TIterator& it1, const TIterator& it2) {
      return
        (it1->blockHeight < it2->blockHeight) ||
        (it1->blockHeight == it2->blockHeight && it1->transactionIndex < it2->transactionIndex);
    }

    std::vector<TIterator> m_list;
    TIterator m_end;
  };

  template<typename TIterator>
  TransferIteratorList<TIterator> createTransferIteratorList(const std::pair<TIterator, TIterator>& itPair) {
    return TransferIteratorList<TIterator>(itPair.first, itPair.second);
  }
}

SpentOutputDescriptor::SpentOutputDescriptor() : m_type(TransactionTypes::OutputType::Invalid) {
}

SpentOutputDescriptor::SpentOutputDescriptor(const TransactionOutputInformationIn& transactionInfo) :
  m_type(transactionInfo.type),
  m_amount(0),
  m_globalOutputIndex(0)
{

  if (m_type == TransactionTypes::OutputType::Key) {
    m_keyImage = &transactionInfo.keyImage;
  } else if (m_type == TransactionTypes::OutputType::Multisignature) {
    m_amount = transactionInfo.amount;
    m_globalOutputIndex = transactionInfo.globalOutputIndex;
  } else {
    assert(false);
  }

}

SpentOutputDescriptor::SpentOutputDescriptor(const Crypto::KeyImage* keyImage)
{
  assign(keyImage);
}

SpentOutputDescriptor::SpentOutputDescriptor(uint64_t amount, uint32_t globalOutputIndex)
{
  assign(amount, globalOutputIndex);
}

void SpentOutputDescriptor::assign(const Crypto::KeyImage* keyImage)
{
  m_type = TransactionTypes::OutputType::Key;
  m_keyImage = keyImage;
}

void SpentOutputDescriptor::assign(uint64_t amount, uint32_t globalOutputIndex)
{
  m_type = TransactionTypes::OutputType::Multisignature;
  m_amount = amount;
  m_globalOutputIndex = globalOutputIndex;
}

size_t SpentOutputDescriptor::hash() const
{
  if (m_type == TransactionTypes::OutputType::Key) {
    static_assert(sizeof(size_t) < sizeof(*m_keyImage), "sizeof(size_t) < sizeof(*m_keyImage)");
    return *reinterpret_cast<const size_t*>(m_keyImage->data);
  } else if (m_type == TransactionTypes::OutputType::Multisignature) {
    size_t hashValue = boost::hash_value(m_amount);
    boost::hash_combine(hashValue, m_globalOutputIndex);
    return hashValue;
  } else {
    assert(false);
    return 0;
  }
}

bool SpentOutputDescriptor::isValid() const
{
  return m_type != TransactionTypes::OutputType::Invalid;
}

bool SpentOutputDescriptor::operator==(const SpentOutputDescriptor& other) const
{
  if (m_type == TransactionTypes::OutputType::Key) {
    return other.m_type == m_type && *other.m_keyImage == *m_keyImage;
  } else if (m_type == TransactionTypes::OutputType::Multisignature) {
    return other.m_type == m_type && other.m_amount == m_amount && other.m_globalOutputIndex == m_globalOutputIndex;
  } else {
    assert(false);
    return false;
  }
}

TransfersContainer::TransfersContainer(const Currency& currency, size_t transactionSpendableAge) :
  m_currentHeight(0),
  m_currency(currency),
  m_transactionSpendableAge(transactionSpendableAge) {
}

bool TransfersContainer::addTransaction(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (block.height < m_currentHeight) {
    throw std::invalid_argument("Cannot add transaction from block < m_currentHeight");
  }

  if (m_transactions.count(transactionReader.getTransactionHash()) > 0) {
    throw std::invalid_argument("Transaction is already added");
  }

  bool addedOutputs = addTransactionOutputs(block, transactionReader, transfers);
  bool addedInputs = addTransactionInputs(block, transactionReader);
  bool added = addedOutputs || addedInputs;

  if (added) {
    addTransaction(block, transactionReader);
  }

  if (block.height != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    m_currentHeight = block.height;
  }

  return added;
}

bool TransfersContainer::advanceHeight(uint32_t height)
{
  std::lock_guard<std::mutex> lk(m_mutex);

  if (m_currentHeight <= height) {
    m_currentHeight = height;
    return true;
  }

  return false;
}

uint64_t TransfersContainer::balance(uint32_t flags) const
{
  std::lock_guard<std::mutex> lk(m_mutex);
  uint64_t amount = 0;

  for (const auto& t : m_availableTransfers) {
    if (t.visible && isIncluded(t, flags)) {
      amount += t.amount;
    }
  }

  if ((flags & IncludeStateLocked) != 0) {
    for (const auto& t : m_unconfirmedTransfers) {
      if (t.visible && isIncluded(t.type, IncludeStateLocked, flags)) {
        amount += t.amount;
      }
    }
  }

  return amount;
}

bool TransfersContainer::deleteUnconfirmedTransaction(const Crypto::Hash& transactionHash)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  auto it = m_transactions.find(transactionHash);
  if (it == m_transactions.end()) {
    return false;
  } else if (it->blockHeight != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    return false;
  } else {
    deleteTransactionTransfers(it->transactionHash);
    m_transactions.erase(it);
    return true;
  }
}

std::vector<Crypto::Hash> TransfersContainer::detach(uint32_t height)
{
  // This method expects that WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT is a big positive number
  assert(height < WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT);

  std::lock_guard<std::mutex> lk(m_mutex);

  std::vector<Crypto::Hash> deletedTransactions;
  auto& spendingTransactionIndex = m_spentTransfers.get<SpendingTransactionIndex>();
  auto& blockHeightIndex = m_transactions.get<1>();
  auto it = blockHeightIndex.end();
  while (it != blockHeightIndex.begin()) {
    --it;

    bool doDelete = false;
    if (it->blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
      auto range = spendingTransactionIndex.equal_range(it->transactionHash);
      for (auto spentTransferIt = range.first; spentTransferIt != range.second; ++spentTransferIt) {
        if (spentTransferIt->blockHeight >= height) {
          doDelete = true;
          break;
        }
      }
    } else if (it->blockHeight >= height) {
      doDelete = true;
    } else {
      break;
    }

    if (doDelete) {
      deleteTransactionTransfers(it->transactionHash);
      deletedTransactions.emplace_back(it->transactionHash);
      it = blockHeightIndex.erase(it);
    }
  }

  // TODO: notification on detach
  m_currentHeight = height == 0 ? 0 : height - 1;

  return deletedTransactions;
}

void TransfersContainer::getOutputs(std::vector<TransactionOutputInformation>& transfers, uint32_t flags) const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  for (const auto& t : m_availableTransfers) {
    if (t.visible && isIncluded(t, flags)) {
      transfers.push_back(t);
    }
  }

  if ((flags & IncludeStateLocked) != 0) {
    for (const auto& t : m_unconfirmedTransfers) {
      if (t.visible && isIncluded(t.type, IncludeStateLocked, flags)) {
        transfers.push_back(t);
      }
    }
  }
}

std::vector<TransactionSpentOutputInformation> TransfersContainer::getSpentOutputs() const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  std::vector<TransactionSpentOutputInformation> spentOutputs;

  spentOutputs.reserve(m_spentTransfers.size());

  for (const auto& spentOutputInfo : m_spentTransfers) {
    TransactionSpentOutputInformation spentOutput;
    static_cast<TransactionOutputInformation&>(spentOutput) = spentOutputInfo;

    spentOutput.spendingBlockHeight = spentOutputInfo.spendingBlock.height;
    spentOutput.timestamp = spentOutputInfo.spendingBlock.timestamp;
    spentOutput.spendingTransactionHash = spentOutputInfo.spendingTransactionHash;
    spentOutput.keyImage = spentOutputInfo.keyImage;
    spentOutput.inputInTransaction = spentOutputInfo.inputInTransaction;

    spentOutputs.push_back(spentOutput);
  }

  return spentOutputs;
}

bool TransfersContainer::getTransactionInformation(const Crypto::Hash& transactionHash, TransactionInformation& info, uint64_t* amountIn, uint64_t* amountOut) const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  auto it = m_transactions.find(transactionHash);
  if (it == m_transactions.end()) {
    return false;
  }

  info = *it;

  if (amountOut != nullptr) {
    *amountOut = 0;

    if (info.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT)
    {
      // transaction is unconfirmed

      auto unconfirmedOutputsRange = m_unconfirmedTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
      for (auto it = unconfirmedOutputsRange.first; it != unconfirmedOutputsRange.second; ++it) {
        *amountOut += it->amount;
      }
    }
    else
    {
      // transaction is either available or spent
 
      auto availableOutputsRange = m_availableTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
      for (auto it = availableOutputsRange.first; it != availableOutputsRange.second; ++it) {
        *amountOut += it->amount;
      }

      auto spentOutputsRange = m_spentTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
      for (auto it = spentOutputsRange.first; it != spentOutputsRange.second; ++it) {
        *amountOut += it->amount;
      }
    }
  }

  if (amountIn != nullptr) {
    *amountIn = 0;
    auto rangeInputs = m_spentTransfers.get<SpendingTransactionIndex>().equal_range(transactionHash);
    for (auto it = rangeInputs.first; it != rangeInputs.second; ++it) {
      *amountIn += it->amount;
    }
  }

  return true;
}

std::vector<TransactionOutputInformation> TransfersContainer::getTransactionInputs(const Crypto::Hash& transactionHash, uint32_t flags) const
{
  //only type flags are feasible
  assert((flags & IncludeStateAll) == 0);
  flags |= IncludeStateUnlocked;

  std::lock_guard<std::mutex> lk(m_mutex);

  std::vector<TransactionOutputInformation> result;
  auto transactionInputsRange = m_spentTransfers.get<SpendingTransactionIndex>().equal_range(transactionHash);
  for (auto it = transactionInputsRange.first; it != transactionInputsRange.second; ++it) {
    if (isIncluded(it->type, IncludeStateUnlocked, flags)) {
      result.push_back(*it);
    }
  }

  return result;
}

std::vector<TransactionOutputInformation> TransfersContainer::getTransactionOutputs(const Crypto::Hash& transactionHash, uint32_t flags) const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  std::vector<TransactionOutputInformation> result;

  // available transfers
  auto availableRange = m_availableTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
  for (auto i = availableRange.first; i != availableRange.second; ++i) {
    const auto& t = *i;
    if (isIncluded(t, flags)) {
      result.push_back(t);
    }
  }

  // unconfirmed transfers
  if ((flags & IncludeStateLocked) != 0) {
    auto unconfirmedRange = m_unconfirmedTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
    for (auto i = unconfirmedRange.first; i != unconfirmedRange.second; ++i) {
      if (isIncluded(i->type, IncludeStateLocked, flags)) {
        result.push_back(*i);
      }
    }
  }

  // spent transfers
  if ((flags & IncludeStateSpent) != 0) {
    auto spentRange = m_spentTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
    for (auto i = spentRange.first; i != spentRange.second; ++i) {
      if (isIncluded(i->type, IncludeStateAll, flags)) {
        result.push_back(*i);
      }
    }
  }

  return result;
}

void TransfersContainer::getUnconfirmedTransactions(std::vector<Crypto::Hash>& transactionHashes) const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  transactionHashes.clear();

  for (auto& element : m_transactions) {
    if (element.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
      transactionHashes.push_back(*reinterpret_cast<const Crypto::Hash*>(&element.transactionHash));
    }
  }
}

void TransfersContainer::load(std::istream& in) // take information from disk and put it into memory
{
  std::lock_guard<std::mutex> lk(m_mutex);

  Common::StdInputStream stream(in);
  CryptoNote::BinaryInputStreamSerializer s(stream);

  uint32_t version = 0;
  s(version, "version");

  if (version > TRANSFERS_CONTAINER_STORAGE_VERSION) {
    throw std::runtime_error("Unsupported transfers storage version");
  }

  uint32_t currentHeight = 0;
  TransactionMultiIndex transactions;
  UnconfirmedTransfersMultiIndex unconfirmedTransfers;
  AvailableTransfersMultiIndex availableTransfers;
  SpentTransfersMultiIndex spentTransfers;

  s(currentHeight, "height");
  readSequence<TransactionInformation>(std::inserter(transactions, transactions.end()), "transactions", s);
  readSequence<TransactionOutputInformationEx>(std::inserter(unconfirmedTransfers, unconfirmedTransfers.end()), "unconfirmedTransfers", s);
  readSequence<TransactionOutputInformationEx>(std::inserter(availableTransfers, availableTransfers.end()), "availableTransfers", s);
  readSequence<SpentTransactionOutput>(std::inserter(spentTransfers, spentTransfers.end()), "spentTransfers", s);

  m_currentHeight = currentHeight;
  m_transactions = std::move(transactions);
  m_unconfirmedTransfers = std::move(unconfirmedTransfers);
  m_availableTransfers = std::move(availableTransfers);
  m_spentTransfers = std::move(spentTransfers);
}

bool TransfersContainer::markTransactionConfirmed(const TransactionBlockInfo& block, const Crypto::Hash& transactionHash, const std::vector<uint32_t>& globalIndexes)
{
  if (block.height == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    throw std::invalid_argument("Block height equals WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT");
  }

  std::unique_lock<std::mutex> lock(m_mutex);

  auto transactionIt = m_transactions.find(transactionHash);
  if (transactionIt == m_transactions.end()) {
    return false;
  }

  if (transactionIt->blockHeight != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    return false;
  }

  TransactionInformation transactionInfo = *transactionIt;
  transactionInfo.blockHeight = block.height;
  transactionInfo.timestamp = block.timestamp;
  m_transactions.replace(transactionIt, transactionInfo); // update the block height and timestamp in m_transactions

  auto availableRange = m_unconfirmedTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
  for (auto transferIt = availableRange.first; transferIt != availableRange.second; ) {
    auto transfer = *transferIt;
    assert(transfer.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT);
    assert(transfer.globalOutputIndex == UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX);
    if (transfer.outputInTransaction >= globalIndexes.size()) {
      throw std::invalid_argument("Not enough elements in globalIndexes");
    }

    transfer.blockHeight = block.height;
    transfer.transactionIndex = block.transactionIndex;
    transfer.globalOutputIndex = globalIndexes[transfer.outputInTransaction];

    if (transfer.type == TransactionTypes::OutputType::Multisignature) {
      SpentOutputDescriptor descriptor(transfer);
      if (m_availableTransfers.get<SpentOutputDescriptorIndex>().count(descriptor) > 0 ||
          m_spentTransfers.get<SpentOutputDescriptorIndex>().count(descriptor) > 0) {
        // This exception breaks TransfersContainer consistency
        throw std::runtime_error("Transfer already exists");
      }
    }

    // add transfer to m_availableTransfers
    auto result = m_availableTransfers.emplace(std::move(transfer));
    (void)result; // Disable unused warning
    bool inserted = result.second;
    assert(inserted);

    // remove transfer from m_unconfirmedTransfers
    transferIt = m_unconfirmedTransfers.get<ContainingTransactionIndex>().erase(transferIt);

    if (transfer.type == TransactionTypes::OutputType::Key) {
      updateTransfersVisibility(transfer.keyImage);
    }
  }

  auto& spendingTransactionIndex = m_spentTransfers.get<SpendingTransactionIndex>();
  auto spentRange = spendingTransactionIndex.equal_range(transactionHash);
  for (auto transferIt = spentRange.first; transferIt != spentRange.second; ++transferIt) {
    auto transfer = *transferIt;
    assert(transfer.spendingBlock.height == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT);

    transfer.spendingBlock = block;
    spendingTransactionIndex.replace(transferIt, transfer);
  }

  return true;
}

void TransfersContainer::save(std::ostream& os)
{
  std::lock_guard<std::mutex> lk(m_mutex);
  Common::StdOutputStream stream(os);
  CryptoNote::BinaryOutputStreamSerializer s(stream);

  s(const_cast<uint32_t&>(TRANSFERS_CONTAINER_STORAGE_VERSION), "version");

  s(m_currentHeight, "height");
  writeSequence<TransactionInformation>(m_transactions.begin(), m_transactions.end(), "transactions", s);
  writeSequence<TransactionOutputInformationEx>(m_unconfirmedTransfers.begin(), m_unconfirmedTransfers.end(), "unconfirmedTransfers", s);
  writeSequence<TransactionOutputInformationEx>(m_availableTransfers.begin(), m_availableTransfers.end(), "availableTransfers", s);
  writeSequence<SpentTransactionOutput>(m_spentTransfers.begin(), m_spentTransfers.end(), "spentTransfers", s);
}

size_t TransfersContainer::transactionsCount() const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  return m_transactions.size();
}

size_t TransfersContainer::transfersCount() const
{
  std::lock_guard<std::mutex> lk(m_mutex);

  return m_unconfirmedTransfers.size() + m_availableTransfers.size() + m_spentTransfers.size();
}


// Private functions


void TransfersContainer::addTransaction(const TransactionBlockInfo& block, const ITransactionReader& transactionReader) // pre m_mutex is locked.
{
  TransactionInformation txInfo;
  txInfo.blockHeight = block.height;
  txInfo.timestamp = block.timestamp;
  txInfo.transactionHash = transactionReader.getTransactionHash();
  txInfo.unlockTime = transactionReader.getUnlockTime();
  txInfo.publicKey = transactionReader.getTransactionPublicKey();
  txInfo.totalAmountIn = transactionReader.getInputTotalAmount();
  txInfo.totalAmountOut = transactionReader.getOutputTotalAmount();
  txInfo.extra = transactionReader.getExtra();

  if (!transactionReader.getPaymentId(txInfo.paymentId)) {
    txInfo.paymentId = NULL_HASH;
  }

  auto result = m_transactions.emplace(std::move(txInfo));
  (void)result; // Disable unused warning
  bool inserted = result.second;
  assert(inserted);
}

bool TransfersContainer::addTransactionInputs(const TransactionBlockInfo& block, const ITransactionReader& transactionReader) // pre m_mutex is locked.
{
  bool inputsAdded = false;

  for (size_t i = 0; i < transactionReader.getInputCount(); ++i)
  {
    TransactionTypes::InputType inputType = transactionReader.getInputType(i);

    if (inputType == TransactionTypes::InputType::Key) {
      KeyInput input;
      transactionReader.getInput(i, input);

      // check if key image has already been used
      SpentOutputDescriptor descriptor(&input.keyImage);
      auto spentRange = m_spentTransfers.get<SpentOutputDescriptorIndex>().equal_range(descriptor);
      if (std::distance(spentRange.first, spentRange.second) > 0) {
        throw std::runtime_error("Spending already spent transfer");
      }

      // check if available transfers contains the key image
      auto availableRange = m_availableTransfers.get<SpentOutputDescriptorIndex>().equal_range(descriptor);
      size_t availableCount = std::distance(availableRange.first, availableRange.second);

      // check if unconfirmed transfers contains the key image
      auto unconfirmedRange = m_unconfirmedTransfers.get<SpentOutputDescriptorIndex>().equal_range(descriptor);
      size_t unconfirmedCount = std::distance(unconfirmedRange.first, unconfirmedRange.second);

      if (availableCount == 0) {
        if (unconfirmedCount > 0) {
          throw std::runtime_error("Spending unconfirmed transfer");
        } else {
          // This input doesn't spend any transfer from this container
          continue;
        }
      }

      auto& outputDescriptorIndex = m_availableTransfers.get<SpentOutputDescriptorIndex>();
      auto availableOutputsRange = outputDescriptorIndex.equal_range(SpentOutputDescriptor(&input.keyImage));

      auto iteratorList = createTransferIteratorList(availableOutputsRange);
      iteratorList.sort();
      auto spendingTransferIt = iteratorList.findFirstByAmount(input.amount);

      if (spendingTransferIt == availableOutputsRange.second) {
        throw std::runtime_error("Input has invalid amount, corresponding output isn't found");
      }

      assert(spendingTransferIt->keyImage == input.keyImage);
      copyToSpent(block, transactionReader, i, *spendingTransferIt);
      // erase from available outputs
      outputDescriptorIndex.erase(spendingTransferIt);
      updateTransfersVisibility(input.keyImage);

      inputsAdded = true;
    }
    else if (inputType == TransactionTypes::InputType::Multisignature)
    {
      MultisignatureInput input;
      transactionReader.getInput(i, input);

      auto& outputDescriptorIndex = m_availableTransfers.get<SpentOutputDescriptorIndex>();
      auto availableOutputIt = outputDescriptorIndex.find(SpentOutputDescriptor(input.amount, input.outputIndex));
      if (availableOutputIt != outputDescriptorIndex.end()) {
        copyToSpent(block, transactionReader, i, *availableOutputIt);
        // erase from available outputs
        outputDescriptorIndex.erase(availableOutputIt);

        inputsAdded = true;
      }
    }
    else
    {
      assert(inputType == TransactionTypes::InputType::Generating);
    }
  }

  return inputsAdded;
}

bool TransfersContainer::addTransactionOutputs(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, const std::vector<TransactionOutputInformationIn>& transfers)  // pre m_mutex is locked.
{
  bool outputsAdded = false;

  Crypto::Hash transactionHash = transactionReader.getTransactionHash();
  bool transactionIsUnconfimed = false;

  if (block.height == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT)
  {
    transactionIsUnconfimed = true;
  }

  for (const TransactionOutputInformationIn& transfer : transfers)
  {
    assert(transfer.outputInTransaction < transactionReader.getOutputCount());
    assert(transfer.type == transactionReader.getOutputType(transfer.outputInTransaction));
    assert(transfer.amount > 0);

    bool transferIsUnconfirmed = false;
    if (transfer.globalOutputIndex == UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX)
    {
      transferIsUnconfirmed = true;
    }

    if (transactionIsUnconfimed != transferIsUnconfirmed) {
      throw std::invalid_argument("Bad transfer's globalOutputIndex");
    }

    TransactionOutputInformationEx info;
    static_cast<TransactionOutputInformationIn&>(info) = transfer;
    info.blockHeight = block.height;
    info.transactionIndex = block.transactionIndex;
    info.unlockTime = transactionReader.getUnlockTime();
    info.transactionHash = transactionHash;
    info.visible = true;

    if (transferIsUnconfirmed)
    {
      auto result = m_unconfirmedTransfers.emplace(std::move(info));
      (void)result; // Disable unused warning
      bool inserted = result.second;
      assert(inserted);
    }
    else
    {
      if (info.type == TransactionTypes::OutputType::Key)
      {
        bool duplicate = false;
        SpentOutputDescriptor descriptor(transfer);

        // check if transfer was already added to m_availableTransfers
        auto availableRange = m_availableTransfers.get<SpentOutputDescriptorIndex>().equal_range(descriptor);
        for (auto it = availableRange.first; !duplicate && it != availableRange.second; ++it) {
          if (it->transactionHash == info.transactionHash && it->outputInTransaction == info.outputInTransaction) {
            duplicate = true;
          }
        }

        // check if transfer was already added to m_spentTransfers
        auto spentRange = m_spentTransfers.get<SpentOutputDescriptorIndex>().equal_range(descriptor);
        for (auto it = spentRange.first; !duplicate && it != spentRange.second; ++it) {
          if (it->transactionHash == info.transactionHash && it->outputInTransaction == info.outputInTransaction) {
            duplicate = true;
          }
        }

        if (duplicate) {
          std::string message = "Failed to add transaction output: key output already exists";
          throw std::runtime_error(message);
        }
      }
      else if (info.type == TransactionTypes::OutputType::Multisignature)
      {
        SpentOutputDescriptor descriptor(transfer);
        if (m_availableTransfers.get<SpentOutputDescriptorIndex>().count(descriptor) > 0 ||
            m_spentTransfers.get<SpentOutputDescriptorIndex>().count(descriptor) > 0) {
          throw std::runtime_error("Transfer already exists");
        }
      }

      auto result = m_availableTransfers.emplace(std::move(info));
      (void)result; // Disable unused warning
      bool inserted = result.second;
      assert(inserted);
    }

    if (info.type == TransactionTypes::OutputType::Key) {
      updateTransfersVisibility(info.keyImage);
    }

    outputsAdded = true;
  }

  return outputsAdded;
}

void TransfersContainer::copyToSpent(const TransactionBlockInfo& block, const ITransactionReader& transactionReader, size_t inputIndex, const TransactionOutputInformationEx& output) // pre m_mutex is locked.
{
  assert(output.blockHeight != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT);
  assert(output.globalOutputIndex != UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX);

  SpentTransactionOutput spentOutput;
  static_cast<TransactionOutputInformationEx&>(spentOutput) = output;
  spentOutput.spendingBlock = block;
  spentOutput.spendingTransactionHash = transactionReader.getTransactionHash();
  spentOutput.inputInTransaction = static_cast<uint32_t>(inputIndex);
  auto result = m_spentTransfers.emplace(std::move(spentOutput));
  (void)result; // Disable unused warning
  bool inserted = result.second;
  assert(inserted);
}

void TransfersContainer::deleteTransactionTransfers(const Crypto::Hash& transactionHash) // pre m_mutex is locked.
{

  // erase transfers from m_spentTransfers
  auto& spendingTransactionIndex = m_spentTransfers.get<SpendingTransactionIndex>();
  auto spentTransfersRange = spendingTransactionIndex.equal_range(transactionHash);
  for (auto it = spentTransfersRange.first; it != spentTransfersRange.second;) {
    assert(it->blockHeight != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT);
    assert(it->globalOutputIndex != UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX);

    auto result = m_availableTransfers.emplace(static_cast<const TransactionOutputInformationEx&>(*it));
    assert(result.second);
    it = spendingTransactionIndex.erase(it);

    if (result.first->type == TransactionTypes::OutputType::Key) {
      updateTransfersVisibility(result.first->keyImage);
    }
  }

  // erase transfers from m_unconfirmedTransfers
  auto unconfirmedTransfersRange = m_unconfirmedTransfers.get<ContainingTransactionIndex>().equal_range(transactionHash);
  for (auto it = unconfirmedTransfersRange.first; it != unconfirmedTransfersRange.second;) {
    if (it->type == TransactionTypes::OutputType::Key) {
      Crypto::KeyImage keyImage = it->keyImage;
      it = m_unconfirmedTransfers.get<ContainingTransactionIndex>().erase(it);
      updateTransfersVisibility(keyImage);
    } else {
      it = m_unconfirmedTransfers.get<ContainingTransactionIndex>().erase(it);
    }
  }

  // erase transfers from m_availableTransfers
  auto& transactionTransfersIndex = m_availableTransfers.get<ContainingTransactionIndex>();
  auto transactionTransfersRange = transactionTransfersIndex.equal_range(transactionHash);
  for (auto it = transactionTransfersRange.first; it != transactionTransfersRange.second;) {
    if (it->type == TransactionTypes::OutputType::Key) {
      Crypto::KeyImage keyImage = it->keyImage;
      it = transactionTransfersIndex.erase(it);
      updateTransfersVisibility(keyImage);
    }
    else
    {
      it = transactionTransfersIndex.erase(it);
    }
  }
}

bool TransfersContainer::isIncluded(const TransactionOutputInformationEx& info, uint32_t flags) const
{
  uint32_t state;
  if (info.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT || !isSpendTimeUnlocked(info.unlockTime)) {
    state = IncludeStateLocked;
  } else if (m_currentHeight < info.blockHeight + m_transactionSpendableAge) {
    state = IncludeStateSoftLocked;
  } else {
    state = IncludeStateUnlocked;
  }

  return isIncluded(info.type, state, flags);
}

bool TransfersContainer::isIncluded(TransactionTypes::OutputType type, uint32_t state, uint32_t flags)
{
  return
    // filter by type
    (
    ((flags & IncludeTypeKey) != 0            && type == TransactionTypes::OutputType::Key) ||
    ((flags & IncludeTypeMultisignature) != 0 && type == TransactionTypes::OutputType::Multisignature)
    )
    &&
    // filter by state
    ((flags & state) != 0);
}

bool TransfersContainer::isSpendTimeUnlocked(uint64_t unlockTime) const
{
  if (unlockTime < m_currency.maxBlockHeight()) {
    // interpret as block index
    return m_currentHeight + m_currency.lockedTxAllowedDeltaBlocks() >= unlockTime;
  } else {
    //interpret as time
    uint64_t current_time = static_cast<uint64_t>(time(NULL));
    return current_time + m_currency.lockedTxAllowedDeltaSeconds() >= unlockTime;
  }

  return false;
}

namespace
{
  template<typename C, typename T>
  void updateVisibility(C& collection, const T& range, bool visible) {
    for (auto it = range.first; it != range.second; ++it) {
      auto updated = *it;
      updated.visible = visible;
      collection.replace(it, updated);
    }
  }
}

void TransfersContainer::updateTransfersVisibility(const Crypto::KeyImage& keyImage) // pre m_mutex is locked.
{
  auto& unconfirmedIndex = m_unconfirmedTransfers.get<SpentOutputDescriptorIndex>();
  auto& availableIndex = m_availableTransfers.get<SpentOutputDescriptorIndex>();
  auto& spentIndex = m_spentTransfers.get<SpentOutputDescriptorIndex>();

  SpentOutputDescriptor descriptor(&keyImage);
  auto unconfirmedRange = unconfirmedIndex.equal_range(descriptor);
  auto availableRange = availableIndex.equal_range(descriptor);
  auto spentRange = spentIndex.equal_range(descriptor);

  size_t unconfirmedCount = std::distance(unconfirmedRange.first, unconfirmedRange.second);
  size_t availableCount = std::distance(availableRange.first, availableRange.second);
  size_t spentCount = std::distance(spentRange.first, spentRange.second);

  assert(spentCount == 0 || spentCount == 1);

  if (spentCount > 0) {
    updateVisibility(unconfirmedIndex, unconfirmedRange, false);
    updateVisibility(availableIndex, availableRange, false);
    updateVisibility(spentIndex, spentRange, true);
  } else if (availableCount > 0) {
    updateVisibility(unconfirmedIndex, unconfirmedRange, false);
    updateVisibility(availableIndex, availableRange, false);

    auto iteratorList = createTransferIteratorList(availableRange);
    auto earliestTransferIt = iteratorList.minElement();
    assert(earliestTransferIt != availableRange.second);

    auto earliestTransfer = *earliestTransferIt;
    earliestTransfer.visible = true;
    availableIndex.replace(earliestTransferIt, earliestTransfer);
  } else {
    updateVisibility(unconfirmedIndex, unconfirmedRange, unconfirmedCount == 1);
  }
}

} // end namespace CryptoNote
