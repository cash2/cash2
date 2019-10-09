// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <condition_variable>
#include <mutex>
#include <stdint.h>

namespace CryptoNote {

class WalletAsyncContextCounter
{
public:
  WalletAsyncContextCounter() : m_asyncContextCounter(0) {}

  void incrementAsyncContextCounter();
  void decrementAsyncContextCounter();

  //returns true if contexts are finished before timeout
  void waitAsyncContextsFinish();

private:
  uint32_t m_asyncContextCounter;
  std::condition_variable m_cv;
  std::mutex m_mutex;
};

} //namespace CryptoNote
