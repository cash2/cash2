// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <list>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>

#include "Common/ObserverManager.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "INode.h"
#include "IWalletLegacy.h"
#include "Transfers/BlockchainSynchronizer.h"
#include "Transfers/TransfersSynchronizer.h"
#include "Wallet/WalletAsyncContextCounter.h"
#include "Wallet/WalletErrors.h"
#include "WalletLegacy/WalletRequest.h"
#include "WalletLegacy/WalletTransactionSender.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"
#include "WalletLegacy/WalletLegacyCache.h"

namespace CryptoNote {

class WalletLegacy : public IWalletLegacy, IBlockchainSynchronizerObserver, ITransfersObserver {

public:
  WalletLegacy(const Currency& currency, INode& node);
  virtual ~WalletLegacy();
  // IWalletLegacy
  virtual uint64_t actualBalance() override;
  virtual void addObserver(IWalletLegacyObserver* observer) override;
  virtual std::error_code cancelTransaction(size_t transactionIndex) override;
  virtual std::error_code changePassword(const std::string& oldPassword, const std::string& newPassword) override;
  virtual size_t findTransactionByTransferId(TransferId transferId) override;
  virtual void getAccountKeys(AccountKeys& keys) override;
  virtual std::string getAddress() override;
  virtual bool getTransaction(size_t transactionIndex, WalletLegacyTransaction& transaction) override;
  virtual size_t getTransactionCount() override;
  virtual bool getTransfer(TransferId transferId, WalletLegacyTransfer& transfer) override;
  virtual size_t getTransferCount() override;
  virtual Crypto::SecretKey getTxKey(const Crypto::Hash& txid) override;
  virtual void initAndGenerate(const std::string& password) override;
  virtual void initAndLoad(std::istream& inputStream, const std::string& password) override;
  virtual void initWithKeys(const AccountKeys& accountKeys, const std::string& password) override;
  virtual uint64_t pendingBalance() override;
  virtual void removeObserver(IWalletLegacyObserver* observer) override;
  virtual void reset() override;
  virtual void save(std::ostream& destination, bool saveDetailed = true, bool saveCache = true) override;
  virtual size_t sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra = "", uint64_t mixIn = 0, uint64_t unlockTimestamp = 0) override;
  virtual size_t sendTransaction(const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra = "", uint64_t mixIn = 0, uint64_t unlockTimestamp = 0) override;
  virtual void shutdown() override;

private:
  std::vector<size_t> deleteOutdatedUnconfirmedTransactions();
  void doSave(std::ostream& destination, bool saveDetailed, bool saveCache);
  void initSync();
  void load(std::istream& inputStream);
  void notifyClients(std::deque<std::shared_ptr<WalletLegacyEvent> >& events);
  void notifyIfBalanceChanged();
  virtual void onTransactionDeleted(ITransfersSubscription* object, const Crypto::Hash& transactionHash) override; // ITransfersObserver
  virtual void onTransactionUpdated(ITransfersSubscription* object, const Crypto::Hash& transactionHash) override; // ITransfersObserver
  void sendTransactionCallback(WalletRequest::Callback callback, std::error_code ec);
  void synchronizationCallback(WalletRequest::Callback callback, std::error_code ec);
  virtual void synchronizationCompleted(std::error_code result) override; // IBlockchainSynchronizerObserver
  virtual void synchronizationProgressUpdated(uint32_t current, uint32_t total) override; // IBlockchainSynchronizerObserver
  void throwIfNotInitialised();
  
  enum WalletState
  {
    NOT_INITIALIZED = 0,
    INITIALIZED,
    LOADING,
    SAVING
  };

  AccountBase m_account;
  WalletAsyncContextCounter m_walletAsyncContextCounter;
  BlockchainSynchronizer m_blockchainSynchronizer;
  std::mutex m_cacheMutex;
  const Currency& m_currency;
  bool m_walletTransactionSenderIsStopping;
  std::atomic<uint64_t> m_lastNotifiedActualBalance;
  std::atomic<uint64_t> m_lastNotifiedPendingBalance;
  INode& m_node;
  Tools::ObserverManager<IWalletLegacyObserver> m_observerManager;
  std::string m_password;
  std::unique_ptr<WalletTransactionSender> m_walletTransactionSenderPtr;
  WalletState m_walletState;
  ITransfersContainer* m_transfersContainer;
  TransfersSyncronizer m_transfersSynchronizer;
  WalletLegacyCache m_walletLegacyCache;
  
  class SyncStarter : public IWalletLegacyObserver {
  public:
    SyncStarter(BlockchainSynchronizer& blockchainSynchronizer) : m_blockchainSynchronizer(blockchainSynchronizer) {}
    virtual ~SyncStarter() {}

    virtual void initCompleted(std::error_code result) override {
      if (!result) {
        m_blockchainSynchronizer.start();
      }
    }

    BlockchainSynchronizer& m_blockchainSynchronizer;
  };

  std::unique_ptr<SyncStarter> m_syncStarterPtr;

}; // end class WalletLegacy

} //namespace CryptoNote
