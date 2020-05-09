// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>

#include <boost/program_options/variables_map.hpp>

#include "Common/ConsoleHandler.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/Currency.h"
#include "IWalletLegacy.h"
#include "Logging/LoggerManager.h"
#include "Logging/LoggerRef.h"
#include "NodeRpcProxy/NodeRpcProxy.h"
#include "PasswordContainer.h"
#include "SimpleWalletConfigurationOptions.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"
#include "WalletLegacy/WalletHelper.h"

namespace CryptoNote
{

class SimpleWalletCommandsHandler : public IWalletLegacyObserver, public INodeRpcProxyObserver {
public:
  SimpleWalletCommandsHandler(System::Dispatcher& dispatcher, const Currency& currency, Logging::LoggerManager& log, SimpleWalletConfigurationOptions& simpleWalletConfigurationOptions);
  bool deinit();
  bool init();
  bool start_handling();
  void stop_handling();

private:
  std::string addCommasToBlockHeight(const uint32_t& height);
  bool address(const std::vector<std::string> &args = std::vector<std::string>());
  bool all_transactions(const std::vector<std::string> &args);
  bool balance(const std::vector<std::string> &args = std::vector<std::string>());
  virtual void connectionStatusUpdated(bool connected) override; // INodeRpcProxyObserver
  bool exit(const std::vector<std::string> &args);
  virtual void externalTransactionCreated(size_t transactionIndex) override; // IWalletLegacyObserver
  uint64_t getMinimalFee();
  bool height(const std::vector<std::string> &args);
  bool help(const std::vector<std::string> &args = std::vector<std::string>());
  bool incoming_transactions(const std::vector<std::string> &args);
  std::error_code initAndLoadWallet(IWalletLegacy& walletLegacy, std::istream& walletFile, const std::string& password);
  virtual void initCompleted(std::error_code result) override; // IWalletLegacyObserver
  bool new_wallet(const std::string &walletFilenameWithExtension, const std::string& password);
  bool outgoing_transactions(const std::vector<std::string> &args);
  bool parseUrlAddress(const std::string& url, std::string& address, uint16_t& port);
  bool payments(const std::vector<std::string> &args);
  void printIncomingTransaction(const WalletLegacyTransaction& transaction);
  void printOutgoingTransaction(const WalletLegacyTransaction& transaction);
  void printTransaction(const WalletLegacyTransaction& transaction);
  bool reset(const std::vector<std::string> &args);
  bool restore_wallet_from_private_keys(const std::string &walletFilenameWithExtension, const std::string& password);
  bool save(const std::vector<std::string> &args);
  bool saveAndCloseWallet();
  bool send(const std::vector<std::string> &args);
  bool set_log(const std::vector<std::string> &args);
  bool spend_private_key(const std::vector<std::string> &args);
  bool start_mining(const std::vector<std::string> &args);
  bool stop_mining(const std::vector<std::string> &args);
  virtual void synchronizationCompleted(std::error_code result) override; // IWalletLegacyObserver
  virtual void synchronizationProgressUpdated(uint32_t current, uint32_t total) override; // IWalletLegacyObserver
  bool transaction_private_key(const std::vector<std::string> &args);
  std::string tryToOpenWalletOrLoadKeysOrThrow(const std::string& walletFile, const std::string& password);
  void updateBlockchainHeight(uint64_t height, bool force = false);
  bool view_private_key(const std::vector<std::string> &args);
  
  uint64_t m_blockchainHeight;
  Common::ConsoleHandler m_consoleHandler;
  const Currency& m_currency;
  std::string m_daemonAddress;
  std::string m_daemonHost;
  uint16_t m_daemonPort;
  System::Dispatcher& m_dispatcher;
  std::string m_generateNew;
  std::chrono::system_clock::time_point m_lastBlockchainHeightPrintTime;
  std::chrono::system_clock::time_point m_lastBlockchainHeightUpdateTime;
  Logging::LoggerRef m_logger;
  Logging::LoggerManager& m_loggerManager;
  std::unique_ptr<NodeRpcProxy> m_nodeRpcProxyPtr;
  SimpleWalletConfigurationOptions& m_simpleWalletConfigurationOptions;
  std::string m_spendPrivateKey;
  std::string m_viewPrivateKey;
  std::string m_walletFilenameWithExtension;
  std::string m_walletFileArg;
  std::unique_ptr<std::promise<std::error_code>> m_walletLegacyInitErrorPromisePtr;
  std::unique_ptr<IWalletLegacy> m_walletLegacyPtr;
  bool m_walletLegacySynchronized;
  std::condition_variable m_walletLegacySynchronizedCV;
  std::mutex m_walletLegacySynchronizedMutex;
};

} // end namespace CryptoNote
