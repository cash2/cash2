// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpServer.h"

#include <functional>
#include <unordered_map>

#include <Logging/LoggerRef.h>
#include "CoreRpcServerCommandsDefinitions.h"

namespace CryptoNote {

class core;
class NodeServer;
class ICryptoNoteProtocolQuery;

class RpcServer : public HttpServer {
public:
  RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, core& c, NodeServer& p2p, const ICryptoNoteProtocolQuery& protocolQuery);

  typedef std::function<bool(RpcServer*, const HttpRequest& request, HttpResponse& response)> HandlerFunction;
  bool restrictRPC(const bool is_resctricted);
  bool enableCors(const std::string domain);
  std::string getCorsDomain();

private:

  template <class Handler>
  struct RpcHandler {
    const Handler handler;
    const bool allowBusyCore;
  };

  typedef void (RpcServer::*HandlerPtr)(const HttpRequest& request, HttpResponse& response);
  static std::unordered_map<std::string, RpcHandler<HandlerFunction>> s_handlers;

  virtual void processRequest(const HttpRequest& request, HttpResponse& response) override;
  bool processJsonRpcRequest(const HttpRequest& request, HttpResponse& response);
  bool isCoreReady();

  // binary handlers
  bool on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res);
  bool on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res);
  bool on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res);
  bool on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res);
  bool on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res);
  bool onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp);
  bool onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp);

  // json handlers
  bool on_get_circulating_supply(const COMMAND_RPC_GET_CIRCULATING_SUPPLY::request& req, COMMAND_RPC_GET_CIRCULATING_SUPPLY::response& res);
  bool on_get_difficulty(const COMMAND_RPC_GET_DIFFICULTY::request& req, COMMAND_RPC_GET_DIFFICULTY::response& res);
  bool on_get_grey_peerlist_size(const COMMAND_RPC_GET_GREY_PEERLIST_SIZE::request& req, COMMAND_RPC_GET_GREY_PEERLIST_SIZE::response& res);
  bool on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res);
  bool on_get_incoming_connections_count(const COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::request& req, COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::response& res);
  bool on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res);
  bool on_get_mempool_transactions_count(const COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::request& req, COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::response& res);
  bool on_get_orphan_blocks_count(const COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::request& req, COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::response& res);
  bool on_get_outgoing_connections_count(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::request& req, COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::response& res);
  bool on_get_total_transactions_count(const COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::request& req, COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::response& res);
  bool on_get_transaction_fee(const COMMAND_RPC_GET_TRANSACTION_FEE::request& req, COMMAND_RPC_GET_TRANSACTION_FEE::response& res);
  bool on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res);
  bool on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res);
  bool on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res);
  bool on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res);
  bool on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res);

  // json rpc
  bool on_check_payment(const COMMAND_RPC_CHECK_PAYMENT::request& req, COMMAND_RPC_CHECK_PAYMENT::response& res);
  bool on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res);
  bool on_get_block_count(const COMMAND_RPC_GET_BLOCK_COUNT::request& req, COMMAND_RPC_GET_BLOCK_COUNT::response& res);
  bool on_get_block_hash(const COMMAND_RPC_GET_BLOCK_HASH::request& req, COMMAND_RPC_GET_BLOCK_HASH::response& res);
  bool on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res);
  bool on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res);
  bool on_get_block_template(const COMMAND_RPC_GET_BLOCK_TEMPLATE::request& req, COMMAND_RPC_GET_BLOCK_TEMPLATE::response& res);
  bool on_get_blocks_json(const COMMAND_RPC_GET_BLOCKS_JSON::request& req, COMMAND_RPC_GET_BLOCKS_JSON::response& res);
  bool on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& req, COMMAND_RPC_GET_CURRENCY_ID::response& res);
  bool on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res);
  bool on_get_mempool(const COMMAND_RPC_GET_MEMPOOL::request& req, COMMAND_RPC_GET_MEMPOOL::response& res);
  bool on_get_transaction(const COMMAND_RPC_GET_TRANSACTION::request& req, COMMAND_RPC_GET_TRANSACTION::response& res);
  bool on_submit_block(const COMMAND_RPC_SUBMIT_BLOCK::request& req, COMMAND_RPC_SUBMIT_BLOCK::response& res);

  bool getRingSignatureSize(const Transaction& transaction, uint64_t& ringSignatureSize);

  void fill_block_header_response(const Block& blk, bool orphan_status, uint64_t height, const Crypto::Hash& hash, block_header_response& responce);

  Logging::LoggerRef logger;
  core& m_core;
  NodeServer& m_p2p;
  const ICryptoNoteProtocolQuery& m_protocolQuery;
  bool m_restricted_rpc;
  std::string m_cors_domain;
};

}
