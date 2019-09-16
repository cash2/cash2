// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <chrono>
#include "CryptoNote.h"
#include "../CryptoNoteConfig.h"
#include "ConnectionContext.h"
#include "System/Dispatcher.h"
#include "System/Context.h"
#include "Logging/LoggerRef.h"
#include "System/TcpConnection.h"
#include "System/Event.h"
#include "P2pProtocolTypes.h"

namespace CryptoNote
{

struct P2pMessage {
  enum Type {
    COMMAND,
    REPLY,
    NOTIFY
  };

  P2pMessage(Type type, uint32_t command, const BinaryArray& buffer, int32_t returnCode = 0) :
    type(type), command(command), buffer(buffer), returnCode(returnCode) {
  }

  P2pMessage(P2pMessage&& message) :
    type(message.type), command(message.command), buffer(std::move(message.buffer)), returnCode(message.returnCode) {
  }

  size_t size() {
    return buffer.size();
  }

  Type type;
  uint32_t command;
  const BinaryArray buffer;
  int32_t returnCode;
};

struct P2pConnectionContext : public CryptoNoteConnectionContext {
public:
  P2pConnectionContext(System::Dispatcher& dispatcher, Logging::ILogger& log, System::TcpConnection&& conn) :
    context(nullptr),
    peerId(0),
    connection(std::move(conn)),
    logger(log, "node_server"),
    queueEvent(dispatcher),
    stopped(false) {
  }

  P2pConnectionContext(P2pConnectionContext&& ctx) : 
    CryptoNoteConnectionContext(std::move(ctx)),
    context(ctx.context),
    peerId(ctx.peerId),
    connection(std::move(ctx.connection)),
    logger(ctx.logger.getLogger(), "node_server"),
    queueEvent(std::move(ctx.queueEvent)),
    stopped(std::move(ctx.stopped)) {
  }

  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void interrupt();
  std::vector<P2pMessage> popBuffer();
  bool pushMessage(P2pMessage&& msg);
  uint64_t writeDuration(TimePoint now) const;

  System::Context<void>* context;
  PeerIdType peerId;
  System::TcpConnection connection;

private:
  Logging::LoggerRef logger;
  TimePoint writeOperationStartTime;
  System::Event queueEvent;
  std::vector<P2pMessage> writeQueue;
  size_t writeQueueSize = 0;
  bool stopped;
};

} // end namespace CryptoNote