// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <fstream>
#include <memory>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/hashed_index.hpp>

#include "CryptoNoteCore/Currency.h"
#include "INode.h"
#include "IWallet.h"
#include "Logging/LoggerRef.h"
#include "WalletdRpcRequestResponseObjects.h"
#include "System/ContextGroup.h"
#include "System/Dispatcher.h"
#include "System/Event.h"

namespace PaymentService {

struct WalletConfiguration {
  std::string walletFile;
  std::string walletPassword;
  std::string walletSpendPrivateKey;
  std::string walletViewPrivateKey;
};

void generateNewWallet(const CryptoNote::Currency &currency, const WalletConfiguration &config, Logging::ILogger &logger, System::Dispatcher& dispatcher);

class WalletHelper {

public:

  WalletHelper(const CryptoNote::Currency& currency, System::Dispatcher& dispatcher, CryptoNote::INode& node, CryptoNote::IWallet& wallet, const WalletConfiguration& config, Logging::ILogger& logger);
  virtual ~WalletHelper();
  std::error_code createAddress(std::string& address);
  std::error_code createAddress(const std::string& spendPrivateKeyStr, std::string& address);
  std::error_code createDelayedTransaction(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, std::string& transactionHash);
  std::error_code createTrackingAddress(const std::string& spendPublicKeyStr, std::string& address);
  std::error_code deleteAddress(const std::string& address);
  std::error_code deleteDelayedTransaction(const std::string& transactionHashStr);
  std::error_code getAddresses(std::vector<std::string>& addresses);
  std::error_code getAddressesCount(size_t& addressesCount);
  std::error_code getBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedBalance);
  std::error_code getBalance(uint64_t& availableBalance, uint64_t& lockedBalance);
  std::error_code getBlockHashes(uint32_t firstBlockIndex, uint32_t blockCount, std::vector<std::string>& blockHashStrings);
  std::error_code getDelayedTransactionHashes(std::vector<std::string>& transactionHashStrings);
  std::error_code getSpendPrivateKey(const std::string& address, std::string& spendPrivateKeyStr);
  std::error_code getSpendPrivateKeys(std::vector<std::string>& spendPrivateKeyStrings);
  std::error_code getStatus(uint32_t& blockCount, uint32_t& knownBlockCount, std::string& lastBlockHash, uint32_t& peerCount, uint64_t& minimalFee);
  std::error_code getTransaction(const std::string& transactionHashStr, TransactionRpcInfo& transactionRpcInfo);
  std::error_code getTransactionHashes(const std::vector<std::string>& addresses, const std::string& blockHashStr, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactionHashes(const std::vector<std::string>& addresses, uint32_t firstBlockIndex, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactions(const std::vector<std::string>& addresses, const std::string& blockHash, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactions(const std::vector<std::string>& addresses, uint32_t firstBlockIndex, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactionHashes);
  std::error_code getUnconfirmedTransactionHashes(const std::vector<std::string>& addresses, std::vector<std::string>& transactionHashes);
  std::error_code getViewPrivateKey(std::string& viewPrivateKey);
  void init();
  std::error_code replaceWithNewWallet(const std::string& viewPrivateKeyStr);
  std::error_code resetWallet();
  void saveWallet();
  std::error_code sendDelayedTransaction(const std::string& transactionHashStr);
  std::error_code sendTransaction(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, std::string& transactionHash, std::string& transactionPrivateKeyStr);
  std::error_code validateAddress(const std::string& address, bool& addressValid);

private:

  struct TransactionsInBlockInfoFilter;

  void addPaymentIdToExtra(const std::string& paymentId, std::string& extra);
  std::vector<std::string> collectDestinationAddresses(const std::vector<WalletRpcOrder>& orders);
  std::vector<TransactionHashesInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) const;
  std::vector<TransactionsInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) const;
  TransactionRpcInfo convertTransactionWithTransfersToTransactionRpcInfo(const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers) const;
  std::vector<CryptoNote::WalletOrder> convertWalletRpcOrdersToWalletOrders(const std::vector<WalletRpcOrder>& walletRpcOrders);
  bool createOutputBinaryFile(const std::string& filename, std::fstream& file);
  std::string createTemporaryFile(const std::string& path, std::fstream& tempFile);
  std::vector<CryptoNote::TransactionsInBlockInfo> filterTransactions(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks, const TransactionsInBlockInfoFilter& filter) const;
  std::string getPaymentIdStringFromExtra(const std::string& binaryString) const;
  std::vector<TransactionsInBlockRpcInfo> getRpcTransactions(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  std::vector<TransactionsInBlockRpcInfo> getRpcTransactions(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  std::vector<TransactionHashesInBlockRpcInfo> getRpcTransactionHashes(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  std::vector<TransactionHashesInBlockRpcInfo> getRpcTransactionHashes(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  Crypto::Hash hashStringToHash(const std::string& hashString);
  void loadWallet();
  void loadTransactionIdIndex();
  void refresh();
  void replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey);
  void reset();
  void secureSaveWallet(CryptoNote::IWallet& wallet, const std::string& path, bool saveDetailed = true, bool saveCache = true);
  void validateAddresses(const std::vector<std::string>& addresses);
  void validatePaymentId(const std::string& paymentId);

  const WalletConfiguration& m_config;
  const CryptoNote::Currency& m_currency;
  System::Dispatcher& m_dispatcher;
  bool m_initialized;
  Logging::LoggerRef m_logger;
  CryptoNote::INode& m_node;
  System::Event m_readyEvent;
  System::ContextGroup m_refreshContext;
  std::map<std::string, size_t> m_transactionHashStrIndexMap;
  CryptoNote::IWallet& m_wallet;

};

} // end namespace PaymentService
