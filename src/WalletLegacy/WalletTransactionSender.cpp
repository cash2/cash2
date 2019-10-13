// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random>

#include "crypto/crypto.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "WalletLegacy/WalletTransactionSender.h"
#include "WalletLegacy/WalletUtils.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "Logging/LoggerGroup.h"

namespace CryptoNote {

namespace {

std::shared_ptr<WalletLegacyEvent> makeCompleteEvent(WalletLegacyCache& transactionCache, size_t transactionIndex, std::error_code ec)
{
  transactionCache.updateTransactionSendingState(transactionIndex, ec);
  return std::make_shared<WalletSendTransactionCompletedEvent>(transactionIndex, ec);
}

} // end anonymous namespace


// Public functions


WalletTransactionSender::WalletTransactionSender(const Currency& currency, WalletLegacyCache& walletLegacyCache, AccountKeys keys, ITransfersContainer& transfersContainer) :
  m_currency(currency),
  m_walletLegacyCache(walletLegacyCache),
  m_isStoping(false),
  m_keys(keys),
  m_transfersContainer(transfersContainer),
  m_upperTransactionSizeLimit(m_currency.blockGrantedFullRewardZone() * 2 - m_currency.minerTxBlobReservedSize()) {}

std::shared_ptr<WalletRequest> WalletTransactionSender::makeSendRequest(size_t& transactionIndex, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp)
{

  if (transfers.empty())
  {
    throw std::system_error(make_error_code(error::ZERO_DESTINATION));
  }

  validateTransfersAddresses(transfers);
  uint64_t totalAmount = fee;

  for (const WalletLegacyTransfer& transfer: transfers) {

    if (transfer.amount == 0)
    {
      throw std::system_error(make_error_code(error::ZERO_DESTINATION));
    }

    if (transfer.amount < 0)
    {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT));
    }

    totalAmount += transfer.amount;

    if (static_cast<int64_t>(totalAmount) < transfer.amount)
    {
      throw std::system_error(make_error_code(error::SUM_OVERFLOW));
    }
  }

  std::shared_ptr<SendTransactionContext> context = std::make_shared<SendTransactionContext>();

  context->foundMoney = selectTransfersToSend(totalAmount, 0 == mixIn, context->dustPolicy.dustThreshold, context->selectedTransfers);

  if (context->foundMoney < totalAmount)
  {
    throw std::system_error(make_error_code(error::WRONG_AMOUNT));
  }

  transactionIndex = m_walletLegacyCache.addNewTransaction(totalAmount, fee, extra, transfers, unlockTimestamp);
  context->transactionIndex = transactionIndex;
  context->mixIn = mixIn;

  if(context->mixIn) {
    std::shared_ptr<WalletRequest> request = makeGetRandomOutsRequest(context);
    return request;
  }

  return doSendTransaction(context, events);
}

void WalletTransactionSender::stop()
{
  m_isStoping = true;
}


// Private functions


std::shared_ptr<WalletRequest> WalletTransactionSender::doSendTransaction(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events)
{
  if (m_isStoping) {
    events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, make_error_code(error::TX_CANCELLED)));
    return std::shared_ptr<WalletRequest>();
  }

  try
  {
    WalletLegacyTransaction& walletLegacyTransaction = m_walletLegacyCache.getTransaction(context->transactionIndex);

    std::vector<TransactionSourceEntry> sources;
    prepareInputs(context->selectedTransfers, context->outs, sources, context->mixIn);

    TransactionDestinationEntry changeDestinations;
    changeDestinations.amount = 0;
    uint64_t totalAmount = -walletLegacyTransaction.totalAmount;

    if (totalAmount < context->foundMoney) {
      changeDestinations.addr = m_keys.address;
      changeDestinations.amount = context->foundMoney - totalAmount;
    }

    std::vector<TransactionDestinationEntry> destinations;
    splitDestinations(walletLegacyTransaction.firstTransferIndex, walletLegacyTransaction.transferCount, changeDestinations, context->dustPolicy, destinations);

    Transaction transaction;
    std::vector<uint8_t> extraVector(walletLegacyTransaction.extra.begin(), walletLegacyTransaction.extra.end());
    Logging::LoggerGroup logIgnore;

    if(!constructTransaction(m_keys, sources, destinations, extraVector, transaction, walletLegacyTransaction.unlockTime, context->tx_key, logIgnore))
    {
      throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR));
    }

    if(getObjectBinarySize(transaction) >= m_upperTransactionSizeLimit)
    {
      throw std::system_error(make_error_code(error::TRANSACTION_SIZE_TOO_BIG));
    }

    getObjectHash(transaction, walletLegacyTransaction.hash);

    m_walletLegacyCache.updateTransaction(context->transactionIndex, transaction, totalAmount, context->selectedTransfers, context->tx_key);

    notifyBalanceChanged(events);
   
    return std::make_shared<WalletRelayTransactionRequest>(transaction, std::bind(&WalletTransactionSender::relayTransactionCallback, this, context,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
  }
  catch(std::system_error& ec) {
    events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, ec.code()));
  }
  catch(std::exception&) {
    events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, make_error_code(error::INTERNAL_WALLET_ERROR)));
  }

  return std::shared_ptr<WalletRequest>();
}

std::shared_ptr<WalletRequest> WalletTransactionSender::makeGetRandomOutsRequest(std::shared_ptr<SendTransactionContext> context)
{
  uint64_t outputsCount = context->mixIn + 1;// add one to make possible (if need) to skip real output key
  std::vector<uint64_t> amounts;

  for (const TransactionOutputInformation& transactionOutput : context->selectedTransfers) {
    amounts.push_back(transactionOutput.amount);
  }

  return std::make_shared<WalletGetRandomOutsByAmountsRequest>(amounts, outputsCount, context, std::bind(&WalletTransactionSender::sendTransactionRandomOutsByAmount,
      this, context, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
}

void WalletTransactionSender::digitSplitStrategy(size_t firstTransferIndex, size_t transfersCount, const TransactionDestinationEntry& change_dst, uint64_t dust_threshold, std::vector<TransactionDestinationEntry>& splitted_dsts, uint64_t& dust)
{
  splitted_dsts.clear();
  dust = 0;

  for (size_t idx = firstTransferIndex; idx < firstTransferIndex + transfersCount; ++idx) {
    WalletLegacyTransfer& de = m_walletLegacyCache.getTransfer(idx);

    AccountPublicAddress addr;
    if (!m_currency.parseAccountAddressString(de.address, addr)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }

    decompose_amount_into_digits(de.amount, dust_threshold,
      [&](uint64_t chunk) { splitted_dsts.push_back(TransactionDestinationEntry(chunk, addr)); },
      [&](uint64_t a_dust) { splitted_dsts.push_back(TransactionDestinationEntry(a_dust, addr)); });
  }

  decompose_amount_into_digits(change_dst.amount, dust_threshold,
    [&](uint64_t chunk) { splitted_dsts.push_back(TransactionDestinationEntry(chunk, change_dst.addr)); },
    [&](uint64_t a_dust) { dust = a_dust; } );
}

void WalletTransactionSender::notifyBalanceChanged(std::deque<std::shared_ptr<WalletLegacyEvent>>& events)
{
  uint64_t unconfirmedOutsAmount = m_walletLegacyCache.unconfrimedOutsAmount();
  uint64_t change = unconfirmedOutsAmount - m_walletLegacyCache.unconfirmedTransactionsAmount();

  uint64_t actualBalance = m_transfersContainer.balance(ITransfersContainer::IncludeKeyUnlocked) - unconfirmedOutsAmount;
  uint64_t pendingBalance = m_transfersContainer.balance(ITransfersContainer::IncludeKeyNotUnlocked) + change;

  events.push_back(std::make_shared<WalletActualBalanceUpdatedEvent>(actualBalance));
  events.push_back(std::make_shared<WalletPendingBalanceUpdatedEvent>(pendingBalance));
}

void WalletTransactionSender::prepareInputs(const std::list<TransactionOutputInformation>& selectedTransfers, std::vector<CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& randomOutputs, std::vector<TransactionSourceEntry>& sources, uint64_t mixIn)
{

  size_t i = 0;

  for (const TransactionOutputInformation& transactionOutput: selectedTransfers) {
    sources.resize(sources.size() + 1);
    TransactionSourceEntry& source = sources.back();

    source.amount = transactionOutput.amount;

    if(randomOutputs.size()) {
      std::sort(randomOutputs[i].outs.begin(), randomOutputs[i].outs.end(),
        [](const CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& a, const CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& b){return a.global_amount_index < b.global_amount_index;});
      for (auto& daemon_oe: randomOutputs[i].outs) {
        if(transactionOutput.globalOutputIndex == daemon_oe.global_amount_index)
          continue;
        TransactionSourceEntry::OutputEntry oe;
        oe.first = static_cast<uint32_t>(daemon_oe.global_amount_index);
        oe.second = daemon_oe.out_key;
        source.outputs.push_back(oe);
        if(source.outputs.size() >= mixIn)
          break;
      }
    }

    //paste real transaction to the random index
    auto it_to_insert = std::find_if(source.outputs.begin(), source.outputs.end(), [&](const TransactionSourceEntry::OutputEntry& a) { return a.first >= transactionOutput.globalOutputIndex; });

    TransactionSourceEntry::OutputEntry real_oe;
    real_oe.first = transactionOutput.globalOutputIndex;
    real_oe.second = transactionOutput.outputKey;

    auto interted_it = source.outputs.insert(it_to_insert, real_oe);

    source.realTransactionPublicKey = transactionOutput.transactionPublicKey;
    source.realOutput = interted_it - source.outputs.begin();
    source.realOutputIndexInTransaction = transactionOutput.outputInTransaction;
    ++i;
  }
}

void WalletTransactionSender::relayTransactionCallback(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, boost::optional<std::shared_ptr<WalletRequest> >& nextRequest, std::error_code ec)
{
  if (m_isStoping) {
    return;
  }

  events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, ec));
}

namespace
{

template<typename URNG, typename T>
T popRandomValue(URNG& randomGenerator, std::vector<T>& vec) {
  assert(!vec.empty());

  if (vec.empty()) {
    return T();
  }

  std::uniform_int_distribution<size_t> distribution(0, vec.size() - 1);
  size_t idx = distribution(randomGenerator);

  T res = vec[idx];
  if (idx + 1 != vec.size()) {
    vec[idx] = vec.back();
  }
  vec.resize(vec.size() - 1);

  return res;
}

}

uint64_t WalletTransactionSender::selectTransfersToSend(uint64_t neededMoney, bool addDust, uint64_t dust, std::list<TransactionOutputInformation>& selectedTransfers)
{

  std::vector<size_t> unusedTransfers;
  std::vector<size_t> unusedDust;

  std::vector<TransactionOutputInformation> outputs;
  m_transfersContainer.getOutputs(outputs, ITransfersContainer::IncludeKeyUnlocked);

  for (size_t i = 0; i < outputs.size(); ++i) {
    const auto& out = outputs[i];
    if (!m_walletLegacyCache.isUsed(out)) {
      if (dust < out.amount)
        unusedTransfers.push_back(i);
      else
        unusedDust.push_back(i);
    }
  }

  std::default_random_engine randomGenerator(Crypto::rand<std::default_random_engine::result_type>());
  bool selectOneDust = addDust && !unusedDust.empty();
  uint64_t foundMoney = 0;

  while (foundMoney < neededMoney && (!unusedTransfers.empty() || !unusedDust.empty())) {
    size_t idx;
    if (selectOneDust) {
      idx = popRandomValue(randomGenerator, unusedDust);
      selectOneDust = false;
    } else {
      idx = !unusedTransfers.empty() ? popRandomValue(randomGenerator, unusedTransfers) : popRandomValue(randomGenerator, unusedDust);
    }

    selectedTransfers.push_back(outputs[idx]);
    foundMoney += outputs[idx].amount;
  }

  return foundMoney;

}

void WalletTransactionSender::sendTransactionRandomOutsByAmount(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, boost::optional<std::shared_ptr<WalletRequest> >& nextRequest, std::error_code ec)
{
  if (m_isStoping) {
    ec = make_error_code(error::TX_CANCELLED);
  }

  if (ec) {
    events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, ec));
    return;
  }

  for (const CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& out : context->outs)
  {
    if (out.outs.size() < context->mixIn) // check if there exists enough decoy outputs to be used, if not, then the mixin count is too high
    {
      events.push_back(makeCompleteEvent(m_walletLegacyCache, context->transactionIndex, make_error_code(error::MIXIN_COUNT_TOO_BIG)));
      return;
    }
  }

  std::shared_ptr<WalletRequest> request = doSendTransaction(context, events);
  if (request)
  {
    nextRequest = request;
  }
}

void WalletTransactionSender::splitDestinations(size_t firstTransferIndex, size_t transfersCount, const TransactionDestinationEntry& changeDts, const TxDustPolicy& dustPolicy, std::vector<TransactionDestinationEntry>& splitDestinations)
{
  uint64_t dust = 0;

  digitSplitStrategy(firstTransferIndex, transfersCount, changeDts, dustPolicy.dustThreshold, splitDestinations, dust);

  throwIf(dustPolicy.dustThreshold < dust, error::INTERNAL_WALLET_ERROR);
  if (0 != dust && !dustPolicy.addToFee) {
    splitDestinations.push_back(TransactionDestinationEntry(dust, dustPolicy.addrForDust));
  }
}

void WalletTransactionSender::validateTransfersAddresses(const std::vector<WalletLegacyTransfer>& transfers)
{
  for (const WalletLegacyTransfer& tr : transfers) {
    if (!validateDestinationAddress(tr.address)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }
  }
}

bool WalletTransactionSender::validateDestinationAddress(const std::string& address)
{
  AccountPublicAddress ignore;
  return m_currency.parseAccountAddressString(address, ignore);
}


} /* namespace CryptoNote */
