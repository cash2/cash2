// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <system_error>

#include "Common/JsonValue.h"
#include "HTTP/HttpRequest.h"
#include "HTTP/HttpResponse.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"
#include "Rpc/HttpServer.h"
#include "System/Dispatcher.h"
#include "System/Event.h"
#include "System/TcpConnection.h"

namespace CryptoNote {

class JsonRpcServer : HttpServer {

public :

  JsonRpcServer(System::Dispatcher& dispatcher, System::Event& m_stopEvent, Logging::ILogger& loggerGroup, std::string rpcPassword);
  JsonRpcServer(const JsonRpcServer&) = delete;

  void start(const std::string& bindAddress, uint16_t bindPort);

protected :

  static void fillJsonResponse(const Common::JsonValue& val, Common::JsonValue& reponse);
  std::string getRpcConfigurationPassword();
  static void makeErrorResponse(const std::error_code& ec, Common::JsonValue& reponse);
  static void makeGenericErrorReponse(Common::JsonValue& reponse, const char* what, int errorCode = -32001);
  static void makeIncorrectRpcPasswordResponse(Common::JsonValue& reponse);
  static void makeInvalidRpcPasswordResponse(Common::JsonValue& reponse);
  static void makeJsonParsingErrorResponse(Common::JsonValue& reponse);
  static void makeMethodNotFoundResponse(Common::JsonValue& reponse);
  static void makeMissingRpcPasswordKeyResponse(Common::JsonValue& reponse);
  static void prepareJsonResponse(const Common::JsonValue& request, Common::JsonValue& reponse);
  virtual void processJsonRpcRequest(const Common::JsonValue& request, Common::JsonValue& reponse) = 0;

private:

  virtual void processRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) override;

  System::Dispatcher& m_dispatcher;
  Logging::LoggerRef m_logger;
  System::Event& m_stopEvent;
  std::string m_rpcConfigurationPassword;
};

} // end namespace CryptoNote
