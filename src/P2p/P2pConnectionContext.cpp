// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "P2pConnectionContext.h"

namespace CryptoNote
{

void P2pConnectionContext::interrupt() {
  logger(Logging::DEBUGGING) << *this << "Interrupt connection";
  assert(context != nullptr);
  stopped = true;
  queueEvent.set();
  context->interrupt();
}

std::vector<P2pMessage> P2pConnectionContext::popBuffer() {
  writeOperationStartTime = TimePoint();

  while (writeQueue.empty() && !stopped) {
    queueEvent.wait();
  }

  std::vector<P2pMessage> msgs(std::move(writeQueue));
  writeQueue.clear();
  writeQueueSize = 0;
  writeOperationStartTime = Clock::now();
  queueEvent.clear();
  return msgs;
}

bool P2pConnectionContext::pushMessage(P2pMessage&& message) {
  writeQueueSize += message.size();

  if (writeQueueSize > P2P_CONNECTION_MAX_WRITE_BUFFER_SIZE) {
    logger(Logging::DEBUGGING) << *this << "Write queue overflows. Interrupt connection";
    interrupt();
    return false;
  }

  writeQueue.push_back(std::move(message));
  queueEvent.set();
  return true;
}

uint64_t P2pConnectionContext::writeDuration(TimePoint now) const { // in milliseconds
  return writeOperationStartTime == TimePoint() ? 0 : std::chrono::duration_cast<std::chrono::milliseconds>(now - writeOperationStartTime).count();
}

} // end namespace CryptoNote