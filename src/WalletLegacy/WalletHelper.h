// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <future>
#include <map>
#include <mutex>

#include "crypto/hash.h"
#include "IWalletLegacy.h"

namespace CryptoNote {

namespace WalletHelper {

class WalletLegacyInitErrorObserver : public IWalletLegacyObserver {
public:
  std::promise<std::error_code> initErrorPromise;
  virtual void initCompleted(std::error_code errorCode) override { initErrorPromise.set_value(errorCode); }
};

class WalletLegacySaveErrorObserver : public IWalletLegacyObserver {
public:
  std::promise<std::error_code> saveErrorPromise;
  virtual void saveCompleted(std::error_code result) override { saveErrorPromise.set_value(result); }
};

class WalletLegacySendErrorObserver : public IWalletLegacyObserver {
public:
  virtual void sendTransactionCompleted(size_t transactionIndex, std::error_code result) override;
  std::error_code wait(size_t transactionIndex);

private:
  std::mutex m_mutex;
  std::condition_variable m_condition;
  std::map<size_t, std::error_code> m_finishedTransactions;
  std::error_code m_result;
};

class WalletLegacySmartObserver {
public:
  WalletLegacySmartObserver(IWalletLegacy& walletLegacy, IWalletLegacyObserver& observer);
  ~WalletLegacySmartObserver();

  void removeObserver();

private:
  IWalletLegacy& m_walletLegacy;
  IWalletLegacyObserver& m_observer;
  bool m_removed;
};

void prepareFileNames(const std::string& filePath, std::string& walletFile);
void saveWallet(IWalletLegacy& walletLegacy, const std::string& walletFilename);

} // end namespace WalletHelper

} // end namespace CryptoNote
