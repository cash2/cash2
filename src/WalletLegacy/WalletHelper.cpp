// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>
#include <boost/filesystem.hpp>

#include "WalletHelper.h"
#include "Common/PathTools.h"

namespace CryptoNote {

void WalletHelper::WalletLegacySendErrorObserver::sendTransactionCompleted(size_t transactionIndex, std::error_code result) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_finishedTransactions[transactionIndex] = result;
  m_condition.notify_one();
}

std::error_code WalletHelper::WalletLegacySendErrorObserver::wait(size_t transactionIndex) {
  std::unique_lock<std::mutex> lock(m_mutex);

  m_condition.wait(lock, [this, &transactionIndex] {
    auto it = m_finishedTransactions.find(transactionIndex);
    if (it == m_finishedTransactions.end()) {
      return false;
    }

    m_result = it->second;
    return true;
  });

  return m_result;
}

WalletHelper::WalletLegacySmartObserver::WalletLegacySmartObserver(IWalletLegacy& walletLegacy, IWalletLegacyObserver& observer) :
  m_walletLegacy(walletLegacy),
  m_observer(observer),
  m_removed(false) {
    m_walletLegacy.addObserver(&m_observer);
}

WalletHelper::WalletLegacySmartObserver::~WalletLegacySmartObserver() {
  if (m_removed == false) {
    m_walletLegacy.removeObserver(&m_observer);
  }
}

void WalletHelper::WalletLegacySmartObserver::removeObserver() {
  if (m_removed == false) {
    m_walletLegacy.removeObserver(&m_observer);
    m_removed = true;
  }
}

void WalletHelper::prepareFileNames(const std::string& filePath, std::string& walletFile) {
  // add extension ".wallet" to walletFile if needed

  if (Common::GetExtension(filePath) == ".wallet") {
    walletFile = filePath;
  }
  else
  {
    walletFile = filePath + ".wallet";
  }
}

void WalletHelper::saveWallet(IWalletLegacy& walletLegacy, const std::string& walletFilename) {

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

  WalletHelper::WalletLegacySaveErrorObserver walletLegacySaveErrorObserver;
  std::future<std::error_code> saveWalletErrorFuture = walletLegacySaveErrorObserver.saveErrorPromise.get_future();
  WalletLegacySmartObserver walletLegacySmartObserver(walletLegacy, walletLegacySaveErrorObserver);

  std::error_code saveWalletError;

  try
  {
    walletLegacy.save(file, true, true);
    saveWalletError = saveWalletErrorFuture.get();
  }
  catch (std::exception&)
  {
    saveWalletError = make_error_code(std::errc::invalid_argument);
  }

  walletLegacySmartObserver.removeObserver();

  if (saveWalletError) {
    file.close();
    boost::filesystem::remove(walletFilename);
    // rename tempWalletFile back to walletFilename
    boost::filesystem::rename(tempWalletFile, walletFilename);
    throw std::system_error(saveWalletError);
  }

  file.close();

  boost::system::error_code ignore;
  boost::filesystem::remove(tempWalletFile, ignore);
}

} // end namespace CryptoNote
