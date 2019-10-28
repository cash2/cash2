// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>
#include <future>
#include <memory>
#include <sstream>
#include <system_error>

#include "Common/JsonValue.h"
#include "HTTP/HttpParser.h"
#include "HTTP/HttpParserErrorCodes.h"
#include "HTTP/HttpResponse.h"
#include "JsonRpcServer.h"
#include "Serialization/JsonInputValueSerializer.h"
#include "Serialization/JsonOutputStreamSerializer.h"
#include "System/Ipv4Address.h"
#include "System/TcpConnection.h"
#include "System/TcpListener.h"
#include "System/TcpStream.h"

namespace CryptoNote {


// Public functions


JsonRpcServer::JsonRpcServer(System::Dispatcher& dispatcher, System::Event& stopEvent, Logging::ILogger& loggerGroup, std::string rpcConfigurationPassword) :
  HttpServer(dispatcher, loggerGroup), 
  m_dispatcher(dispatcher),
  m_stopEvent(stopEvent),
  m_logger(loggerGroup, "JsonRpcServer"),
  m_rpcConfigurationPassword(rpcConfigurationPassword)
{
}

void JsonRpcServer::start(const std::string& bindAddress, uint16_t bindPort)
{
  HttpServer::start(bindAddress, bindPort);
  m_stopEvent.wait();
  HttpServer::stop();
}


// Protected functions


void JsonRpcServer::fillJsonResponse(const Common::JsonValue& value, Common::JsonValue& response)
{
  response.insert("result", value);
}

std::string JsonRpcServer::getRpcConfigurationPassword()
{
  return m_rpcConfigurationPassword;
}

void JsonRpcServer::makeErrorResponse(const std::error_code& ec, Common::JsonValue& reponse)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32000); //Application specific error code

  Common::JsonValue message;
  message = ec.message();

  Common::JsonValue data(Common::JsonValue::OBJECT);
  Common::JsonValue appCode;
  appCode = static_cast<int64_t>(ec.value());
  data.insert("application_code", appCode);

  error.insert("code", code);
  error.insert("message", message);
  error.insert("data", data);

  reponse.insert("error", error);
}

void JsonRpcServer::makeGenericErrorReponse(Common::JsonValue& reponse, const char* what, int errorCode)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(errorCode);

  std::string msg;
  if (what) {
    msg = what;
  } else {
    msg = "Unknown application error";
  }

  Common::JsonValue message;
  message = msg;

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);

}

void JsonRpcServer::makeIncorrectRpcPasswordResponse(Common::JsonValue& reponse)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Incorrect RPC password";

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);
}

void JsonRpcServer::makeInvalidRpcPasswordResponse(Common::JsonValue& reponse)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Invalid RPC password";

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);
}

void JsonRpcServer::makeJsonParsingErrorResponse(Common::JsonValue& reponse)
{
  reponse = Common::JsonValue(Common::JsonValue::OBJECT);
  reponse.insert("jsonrpc", "2.0");
  reponse.insert("id", nullptr);

  Common::JsonValue error(Common::JsonValue::OBJECT);
  Common::JsonValue code;
  code = static_cast<int64_t>(-32700); //ambigous declaration of JsonValue::operator= (between int and JsonValue)

  Common::JsonValue message = "Parse error";

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);
}

void JsonRpcServer::makeMethodNotFoundResponse(Common::JsonValue& reponse)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32601); //ambigous declaration of JsonValue::operator= (between int and JsonValue)

  Common::JsonValue message;
  message = "Method not found";

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);
}

void JsonRpcServer::makeMissingRpcPasswordKeyResponse(Common::JsonValue& reponse)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Missing rpc_password key in JSON RPC request";

  error.insert("code", code);
  error.insert("message", message);

  reponse.insert("error", error);
}

void JsonRpcServer::prepareJsonResponse(const Common::JsonValue& request, Common::JsonValue& reponse)
{
  if (request.contains("id")) {
    reponse.insert("id", request("id"));
  }
  
  reponse.insert("jsonrpc", "2.0");
}


// Private functions


void JsonRpcServer::processRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& reponse)
{
  try
  {
    m_logger(Logging::TRACE) << "HTTP request came: \n" << request;

    if (request.getUrl() == "/json_rpc")
    {
      std::istringstream jsonInputStream(request.getBody());
      Common::JsonValue jsonRpcRequest;
      Common::JsonValue jsonRpcResponse(Common::JsonValue::OBJECT);

      try
      {
        jsonInputStream >> jsonRpcRequest;
      }
      catch (std::runtime_error&)
      {
        m_logger(Logging::DEBUGGING) << "Couldn't parse request: \"" << request.getBody() << "\"";
        makeJsonParsingErrorResponse(jsonRpcResponse);
        reponse.setStatus(CryptoNote::HttpResponse::STATUS_200);
        reponse.setBody(jsonRpcResponse.toString());
        return;
      }

      processJsonRpcRequest(jsonRpcRequest, jsonRpcResponse);

      std::ostringstream jsonOutputStream;
      jsonOutputStream << jsonRpcResponse;

      reponse.setStatus(CryptoNote::HttpResponse::STATUS_200);
      reponse.setBody(jsonOutputStream.str());

    }
    else
    {
      m_logger(Logging::WARNING) << "Requested url \"" << request.getUrl() << "\" is not found";
      reponse.setStatus(CryptoNote::HttpResponse::STATUS_404);
      return;
    }
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while processing http request: " << e.what();
    reponse.setStatus(CryptoNote::HttpResponse::STATUS_500);
  }
}

} // end namespace CryptoNote
