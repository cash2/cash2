// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DaemonRpcServer.h"
#include "Rpc/JsonRpc.h"

#undef ERROR

// Binary
// get_blocks.bin                  get_blocks()
// get_o_indexes.bin               get_indexes()
// get_pool_changes.bin            get_pool_changes()
// get_pool_changes_lite.bin       get_pool_changes_lite()
// get_random_outs.bin             get_random_outs()
// query_blocks.bin                query_blocks()
// query_blocks_lite.bin           query_blocks_lite()

// HTTP
// get_circulating_supply          get_circulating_supply()
// get_connections                 get_connections()
// get_connections_count           get_connections_count()
// get_difficulty                  get_difficulty()
// get_grey_peerlist               get_grey_peerlist()
// get_grey_peerlist_size          get_grey_peerlist_size()
// get_height                      get_height()
// get_incoming_connections        get_incoming_connections()
// get_incoming_connections_count  get_incoming_connections_count()
// get_info                        get_info()
// get_mempool_transactions_count  get_mempool_transactions_count()
// get_orphan_blocks_count         get_orphan_blocks_count()
// get_outgoing_connections        get_outgoing_connections()
// get_outgoing_connections_count  get_outgoing_connections_count()
// get_total_transactions_count    get_total_transactions_count()
// get_transaction_fee             get_transaction_fee()
// get_transactions                get_transactions()
// get_white_peerlist              get_white_peerlist()
// get_white_peerlist_size         get_white_peerlist_size()
// json_rpc                        processJsonRpcRequest()
// send_raw_transaction            send_raw_tx()
// start_mining                    start_mining()
// stop_daemon                     stop_daemon()
// stop_mining                     stop_mining()

// JSON
// check_payment                   check_payment()
// get_block                       get_block()
// get_block_count                 get_block_count()
// get_block_hash                  get_block_hash()
// get_block_header_by_hash        get_block_header_by_hash()
// get_block_header_by_height      get_block_header_by_height()
// get_block_template              get_block_template()
// get_blocks                      get_blocks_json()
// get_currency_id                 get_currency_id()
// get_last_block_header           get_last_block_header()
// get_mempool                     get_mempool()
// get_transaction                 get_transaction()
// submit_block                    submit_block()
// validate_address                validate_address()


namespace CryptoNote {


// Public functions


DaemonRpcServer::DaemonRpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& core, NodeServer& nodeServer, const ICryptoNoteProtocolQuery& cryptoNoteProtocolQuery, const DaemonRpcServerConfigurationOptions& daemonRpcServerConfigurationOptions) :
  HttpServer(dispatcher, log),
  m_daemonRpcCommands(log, core, nodeServer, cryptoNoteProtocolQuery),
  m_daemonRpcServerConfigurationOptions(daemonRpcServerConfigurationOptions),
  m_core(core),
  m_nodeServer(nodeServer) {
}

void DaemonRpcServer::enableCors(const std::string domain) {
  m_cors_domain = domain;
}

std::string DaemonRpcServer::getCorsDomain() {
  return m_cors_domain;
}

void DaemonRpcServer::setRestrictedRpc(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
}

void DaemonRpcServer::start() {
  HttpServer::start(m_daemonRpcServerConfigurationOptions.bindIp, m_daemonRpcServerConfigurationOptions.bindPort);
}


// Pirvate functions


bool DaemonRpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_nodeServer.get_payload_object().isSynchronized();
}

void DaemonRpcServer::processRequest(const HttpRequest& httpRequest, HttpResponse& httpResponse) {
  std::string url = httpRequest.getUrl();

  if (url == "/get_blocks.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_BLOCKS_FAST::request request;
    COMMAND_RPC_GET_BLOCKS_FAST::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

    m_daemonRpcCommands.get_blocks(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/query_blocks.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_QUERY_BLOCKS::request request;
    COMMAND_RPC_QUERY_BLOCKS::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.query_blocks(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/query_blocks_lite.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_QUERY_BLOCKS_LITE::request request;
    COMMAND_RPC_QUERY_BLOCKS_LITE::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.query_blocks_lite(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/get_o_indexes.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request request;
    COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_indexes(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/get_random_outs.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request request;
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_random_outs(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/get_pool_changes.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_POOL_CHANGES::request request;
    COMMAND_RPC_GET_POOL_CHANGES::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_pool_changes(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/get_pool_changes_lite.bin")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_POOL_CHANGES_LITE::request request;
    COMMAND_RPC_GET_POOL_CHANGES_LITE::response response;

    if (!loadFromBinaryKeyValue(request, httpRequest.getBody())) {
      return;
    }

    m_daemonRpcCommands.get_pool_changes_lite(request, response);
    httpResponse.setBody(storeToBinaryKeyValue(response));
  }
  else if (url == "/get_circulating_supply")
  {
    COMMAND_RPC_GET_CIRCULATING_SUPPLY::request request;
    COMMAND_RPC_GET_CIRCULATING_SUPPLY::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_circulating_supply(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_connections")
  {
    COMMAND_RPC_GET_CONNECTIONS::request request;
    COMMAND_RPC_GET_CONNECTIONS::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_connections(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_connections_count")
  {
    COMMAND_RPC_GET_CONNECTIONS_COUNT::request request;
    COMMAND_RPC_GET_CONNECTIONS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_connections_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_difficulty")
  {
    COMMAND_RPC_GET_DIFFICULTY::request request;
    COMMAND_RPC_GET_DIFFICULTY::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_difficulty(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_grey_peerlist")
  {
    COMMAND_RPC_GET_GREY_PEERLIST::request request;
    COMMAND_RPC_GET_GREY_PEERLIST::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_grey_peerlist(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_grey_peerlist_size")
  {
    COMMAND_RPC_GET_GREY_PEERLIST_SIZE::request request;
    COMMAND_RPC_GET_GREY_PEERLIST_SIZE::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_grey_peerlist_size(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_height")
  {
    COMMAND_RPC_GET_HEIGHT::request request;
    COMMAND_RPC_GET_HEIGHT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_height(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_incoming_connections")
  {
    COMMAND_RPC_GET_INCOMING_CONNECTIONS::request request;
    COMMAND_RPC_GET_INCOMING_CONNECTIONS::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_incoming_connections(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_incoming_connections_count")
  {
    COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::request request;
    COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_incoming_connections_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_info")
  {
    COMMAND_RPC_GET_INFO::request request;
    COMMAND_RPC_GET_INFO::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_info(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_mempool_transactions_count")
  {
    COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::request request;
    COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_mempool_transactions_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_orphan_blocks_count")
  {
    COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::request request;
    COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_orphan_blocks_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_outgoing_connections")
  {
    COMMAND_RPC_GET_OUTGOING_CONNECTIONS::request request;
    COMMAND_RPC_GET_OUTGOING_CONNECTIONS::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_outgoing_connections(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_outgoing_connections_count")
  {
    COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::request request;
    COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_outgoing_connections_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_total_transactions_count")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::request request;
    COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_total_transactions_count(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_transactions")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_TRANSACTIONS::request request;
    COMMAND_RPC_GET_TRANSACTIONS::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_transactions(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_transaction_fee")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_GET_TRANSACTION_FEE::request request;
    COMMAND_RPC_GET_TRANSACTION_FEE::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_transaction_fee(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_white_peerlist")
  {
    COMMAND_RPC_GET_WHITE_PEERLIST::request request;
    COMMAND_RPC_GET_WHITE_PEERLIST::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_white_peerlist(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/get_white_peerlist_size")
  {
    COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::request request;
    COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.get_white_peerlist_size(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/json_rpc")
  {
    JsonRpc::JsonRpcRequest jsonRequest;
    JsonRpc::JsonRpcResponse jsonResponse;

    try
    {
      jsonRequest.parseRequest(httpRequest.getBody());
      jsonResponse.setId(jsonRequest.getId());

      if (jsonRequest.getMethod() == "check_payment")
      {
        COMMAND_RPC_CHECK_PAYMENT::request request;
        COMMAND_RPC_CHECK_PAYMENT::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.check_payment(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_block")
      {
        COMMAND_RPC_GET_BLOCK::request request;
        COMMAND_RPC_GET_BLOCK::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_block_count")
      {
        COMMAND_RPC_GET_BLOCK_COUNT::request request;
        COMMAND_RPC_GET_BLOCK_COUNT::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block_count(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_block_hash")
      {
        COMMAND_RPC_GET_BLOCK_HASH::request request;
        COMMAND_RPC_GET_BLOCK_HASH::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block_hash(request, response);

        jsonResponse.setResult(response);
      }      
      else if (jsonRequest.getMethod() == "get_block_header_by_hash")
      {
        COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request request;
        COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block_header_by_hash(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_block_header_by_height")
      {
        COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request request;
        COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block_header_by_height(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_block_template")
      {
        COMMAND_RPC_GET_BLOCK_TEMPLATE::request request;
        COMMAND_RPC_GET_BLOCK_TEMPLATE::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_block_template(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_blocks")
      {
        COMMAND_RPC_GET_BLOCKS_JSON::request request;
        COMMAND_RPC_GET_BLOCKS_JSON::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_blocks_json(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_currency_id")
      {
        COMMAND_RPC_GET_CURRENCY_ID::request request;
        COMMAND_RPC_GET_CURRENCY_ID::response response;

         m_daemonRpcCommands.get_currency_id(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_last_block_header")
      {
        COMMAND_RPC_GET_LAST_BLOCK_HEADER::request request;
        COMMAND_RPC_GET_LAST_BLOCK_HEADER::response response;

         m_daemonRpcCommands.get_last_block_header(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_mempool")
      {
        COMMAND_RPC_GET_MEMPOOL::request request;
        COMMAND_RPC_GET_MEMPOOL::response response;

         m_daemonRpcCommands.get_mempool(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "get_transaction")
      {
        COMMAND_RPC_GET_TRANSACTION::request request;
        COMMAND_RPC_GET_TRANSACTION::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.get_transaction(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "submit_block")
      {
        COMMAND_RPC_SUBMIT_BLOCK::request request;
        COMMAND_RPC_SUBMIT_BLOCK::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.submit_block(request, response);

        jsonResponse.setResult(response);
      }
      else if (jsonRequest.getMethod() == "validate_address")
      {
        COMMAND_RPC_VALIDATE_ADDRESS::request request;
        COMMAND_RPC_VALIDATE_ADDRESS::response response;

        if (!jsonRequest.loadParams(request)) {
          throw JsonRpc::JsonRpcError(JsonRpc::errInvalidParams);
        }

         m_daemonRpcCommands.validate_address(request, response);

        jsonResponse.setResult(response);
      }
      else
      {
        throw JsonRpc::JsonRpcError(JsonRpc::errMethodNotFound);
      }
    } catch (const JsonRpc::JsonRpcError& err) {
      jsonResponse.setError(err);
    } catch (const std::exception& e) {
      jsonResponse.setError(JsonRpc::JsonRpcError(JsonRpc::errInternalError, e.what()));
    }

    httpResponse.setBody(jsonResponse.getBody());
    return;
  }
  else if (url == "/send_raw_transaction")
  {
    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    COMMAND_RPC_SEND_RAW_TX::request request;
    COMMAND_RPC_SEND_RAW_TX::response response;

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.send_raw_transaction(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/start_mining")
  {
    COMMAND_RPC_START_MINING::request request;
    COMMAND_RPC_START_MINING::response response;

    if (m_restricted_rpc) {
      response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
      return;
    }

    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.start_mining(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/stop_mining")
  {
    COMMAND_RPC_STOP_MINING::request request;
    COMMAND_RPC_STOP_MINING::response response;

    if (m_restricted_rpc) {
      response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
      return;
    }

    if (!isCoreReady())
    {
      httpResponse.setStatus(HttpResponse::STATUS_500);
      httpResponse.setBody("Core is busy");
      return;
    }

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.stop_mining(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else if (url == "/stop_daemon")
  {
    COMMAND_RPC_STOP_DAEMON::request request;
    COMMAND_RPC_STOP_DAEMON::response response;

    if (m_restricted_rpc) {
      response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
      return;
    }

    if (!loadFromJson(request, httpRequest.getBody())) {
      return;
    }

     m_daemonRpcCommands.stop_daemon(request, response);
    httpResponse.setBody(storeToJson(response));
  }
  else
  {
    httpResponse.setStatus(HttpResponse::STATUS_404);
    return;
  }

  httpResponse.addHeader("Content-Type", "application/json");
  if (!m_cors_domain.empty()) {
    httpResponse.addHeader("Access-Control-Allow-Origin", m_cors_domain);
  }

}

} // end namespace CryptoNote
