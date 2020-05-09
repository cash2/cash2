// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "CryptoNoteCore/Core.h"
#include "P2p/NodeServer.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "Rpc/HttpServer.h"
#include "Logging/LoggerRef.h"
#include "DaemonRpcCommands.h"
#include "DaemonRpcServerConfigurationOptions.h"

namespace CryptoNote {

class DaemonRpcServer : public HttpServer {
public:
  DaemonRpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& core, NodeServer& nodeServer, const ICryptoNoteProtocolQuery& cryptoNoteProtocolQuery, const DaemonRpcServerConfigurationOptions& daemonRpcServerConfig);
  void enableCors(const std::string domain);
  std::string getCorsDomain();
  void setRestrictedRpc(const bool is_resctricted);
  void start();

private:
  bool isCoreReady();  
  virtual void processRequest(const HttpRequest& request, HttpResponse& response) override;

  DaemonRpcCommands m_daemonRpcCommands;
  const DaemonRpcServerConfigurationOptions& m_daemonRpcServerConfigurationOptions;
  Core& m_core;
  NodeServer& m_nodeServer;
  bool m_restricted_rpc;
  std::string m_cors_domain;
};

} // end namespace CryptoNote
