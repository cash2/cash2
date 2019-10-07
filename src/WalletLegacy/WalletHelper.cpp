// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletHelper.h"
#include "Common/PathTools.h"

#include <fstream>
#include <boost/filesystem.hpp>

using namespace CryptoNote;

namespace {

std::error_code walletSaveWrapper(CryptoNote::IWalletLegacy& wallet, std::ofstream& file, bool saveDetails, bool saveCache) {
  CryptoNote::WalletHelper::SaveWalletResultObserver saveWalletResultObserver;

  std::error_code errorCode;
  try {
    std::future<std::error_code> saveWalletErrorFuture = saveWalletResultObserver.saveResultPromise.get_future();
    wallet.addObserver(&saveWalletResultObserver);
    wallet.save(file, saveDetails, saveCache);
    errorCode = saveWalletErrorFuture.get();
  } catch (std::exception&) {
    wallet.removeObserver(&saveWalletResultObserver);
    return make_error_code(std::errc::invalid_argument);
  }

  wallet.removeObserver(&saveWalletResultObserver);
  return errorCode;
}

}

void WalletHelper::prepareFileNames(const std::string& file_path, std::string& wallet_file) {
  if (Common::GetExtension(file_path) == ".wallet") {
    wallet_file = file_path;
  }
  else
  {
    wallet_file = file_path + ".wallet";
  }
}

void WalletHelper::SendCompleteResultObserver::sendTransactionCompleted(CryptoNote::TransactionId transactionId, std::error_code result) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_finishedTransactions[transactionId] = result;
  m_condition.notify_one();
}

std::error_code WalletHelper::SendCompleteResultObserver::wait(CryptoNote::TransactionId transactionId) {
  std::unique_lock<std::mutex> lock(m_mutex);

  m_condition.wait(lock, [this, &transactionId] {
    auto it = m_finishedTransactions.find(transactionId);
    if (it == m_finishedTransactions.end()) {
      return false;
    }

    m_result = it->second;
    return true;
  });

  return m_result;
}

WalletHelper::WalletLegacySmartObserver::WalletLegacySmartObserver(CryptoNote::IWalletLegacy& wallet, CryptoNote::IWalletLegacyObserver& observer) :
  m_wallet(wallet),
  m_observer(observer),
  m_removed(false) {
    m_wallet.addObserver(&m_observer);
}

WalletHelper::WalletLegacySmartObserver::~WalletLegacySmartObserver() {
  if (!m_removed) {
    m_wallet.removeObserver(&m_observer);
  }
}

void WalletHelper::WalletLegacySmartObserver::removeObserver() {
  m_wallet.removeObserver(&m_observer);
  m_removed = true;
}

void WalletHelper::saveWallet(CryptoNote::IWalletLegacy& wallet, const std::string& walletFilename) {
  boost::filesystem::path tempWalletFile = boost::filesystem::unique_path(walletFilename + ".tmp.%%%%-%%%%");

  if (boost::filesystem::exists(walletFilename)) {
    // rename walletFilename to tempWalletFile to save it
    boost::filesystem::rename(walletFilename, tempWalletFile);
  }

  std::ofstream file;
  try
  {
    // create a new wallet file called walletFilename
    file.open(walletFilename, std::ios_base::binary | std::ios_base::out | std::ios::trunc);

    if (file.fail()) {
      // error creating new wallet file
      throw std::runtime_error("Error opening wallet file : " + walletFilename);
    }
  }
  catch (std::exception&)
  {
    if (boost::filesystem::exists(tempWalletFile))
    {
      // rename tempWalletFile back to walletFilename
      boost::filesystem::rename(tempWalletFile, walletFilename);
    }
    throw;
  }

  std::error_code saveWalletErrorCode;

  CryptoNote::WalletHelper::SaveWalletResultObserver saveWalletResultObserver;

  try
  {
    std::future<std::error_code> saveWalletErrorFuture = saveWalletResultObserver.saveResultPromise.get_future();
    wallet.addObserver(&saveWalletResultObserver);
    wallet.save(file, true, true);
    saveWalletErrorCode = saveWalletErrorFuture.get();
  }
  catch (std::exception&)
  {
    wallet.removeObserver(&saveWalletResultObserver);
    saveWalletErrorCode = make_error_code(std::errc::invalid_argument);
  }

  wallet.removeObserver(&saveWalletResultObserver);

  if (saveWalletErrorCode) {
    file.close();
    boost::filesystem::remove(walletFilename);
    // rename tempWalletFile back to walletFilename
    boost::filesystem::rename(tempWalletFile, walletFilename);
    throw std::system_error(saveWalletErrorCode);
  }

  file.close();

  boost::system::error_code ignore;
  boost::filesystem::remove(tempWalletFile, ignore);
}
