// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Currency.h"
#include "INode.h"
#include "ITransfersContainer.h"
#include "WalletLegacy/WalletLegacyCache.h"
#include "WalletLegacy/WalletRequest.h"
#include "WalletLegacy/WalletSendTransactionContext.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"

namespace CryptoNote {

class WalletTransactionSender
{

public:

  WalletTransactionSender(const Currency& currency, WalletLegacyCache& walletLegacyCache, AccountKeys keys, ITransfersContainer& transfersContainer);
  std::shared_ptr<WalletRequest> makeSendRequest(size_t& transactionIndex, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra = "", uint64_t mixIn = 0, uint64_t unlockTimestamp = 0);
  void stop();

private:

  std::shared_ptr<WalletRequest> doSendTransaction(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events);
  std::shared_ptr<WalletRequest> makeGetRandomOutsRequest(std::shared_ptr<SendTransactionContext> context);
  void digitSplitStrategy(size_t firstTransferIndex, size_t transfersCount, const TransactionDestinationEntry& change_dst, uint64_t dust_threshold, std::vector<TransactionDestinationEntry>& splitted_dsts, uint64_t& dust);
  void notifyBalanceChanged(std::deque<std::shared_ptr<WalletLegacyEvent>>& events);
  void prepareInputs(const std::list<TransactionOutputInformation>& selectedTransfers, std::vector<CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& randomOutputs, std::vector<TransactionSourceEntry>& sources, uint64_t mixIn);
  void relayTransactionCallback(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, boost::optional<std::shared_ptr<WalletRequest> >& nextRequest, std::error_code ec);
  uint64_t selectTransfersToSend(uint64_t neededMoney, bool addDust, uint64_t dust, std::list<TransactionOutputInformation>& selectedTransfers);
  void sendTransactionRandomOutsByAmount(std::shared_ptr<SendTransactionContext> context, std::deque<std::shared_ptr<WalletLegacyEvent>>& events, boost::optional<std::shared_ptr<WalletRequest> >& nextRequest, std::error_code ec);
  void splitDestinations(size_t firstTransferIndex, size_t transfersCount, const TransactionDestinationEntry& changeDts, const TxDustPolicy& dustPolicy, std::vector<TransactionDestinationEntry>& splittedDests);
  void validateTransfersAddresses(const std::vector<WalletLegacyTransfer>& transfers);
  bool validateDestinationAddress(const std::string& address);
  
  const Currency& m_currency;
  bool m_isStoping;
  AccountKeys m_keys;
  ITransfersContainer& m_transfersContainer;
  uint64_t m_upperTransactionSizeLimit;
  WalletLegacyCache& m_walletLegacyCache;

};

} /* namespace CryptoNote */
