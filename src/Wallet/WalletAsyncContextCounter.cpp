// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletAsyncContextCounter.h"

namespace CryptoNote
{

void WalletAsyncContextCounter::decrementAsyncContextCounter()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  m_asyncContextCounter--;

  if (m_asyncContextCounter == 0)
  {
    m_cv.notify_one();
  }
}

void WalletAsyncContextCounter::incrementAsyncContextCounter()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  m_asyncContextCounter++;
}

void WalletAsyncContextCounter::waitAsyncContextsFinish()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  while (m_asyncContextCounter > 0)
  {
    m_cv.wait(lock);
  }
}

} //namespace CryptoNote
