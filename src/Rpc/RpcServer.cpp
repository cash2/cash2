// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <future>
#include <unordered_map>
#include "RpcServer.h"
#include "Common/StringTools.h"
#include "Common/Math.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/NodeServer.h"
#include "Rpc/CoreRpcErrors.h"
#include "Rpc/JsonRpc.h"

#undef ERROR

// check_payment                   check_payment()
// get_block                       get_block()
// get_block_count                 get_block_count()
// get_block_hash                  get_block_hash()
// get_block_header_by_hash        get_block_header_by_hash()
// get_block_header_by_height      get_block_header_by_height()
// get_block_template              get_block_template()
// get_blocks                      get_blocks_json()
// get_blocks.bin                  get_blocks()
// get_circulating_supply          get_circulating_supply()
// get_connections                 get_connections()
// get_connections_count           get_connections_count()
// get_currency_id                 get_currency_id()
// get_difficulty                  get_difficulty()
// get_grey_peerlist               get_grey_peerlist()
// get_grey_peerlist_size          get_grey_peerlist_size()
// get_height                      get_height()
// get_incoming_connections        get_incoming_connections()
// get_incoming_connections_count  get_incoming_connections_count()
// get_info                        get_info()
// get_last_block_header           get_last_block_header()
// get_mempool                     get_mempool()
// get_mempool_transactions_count  get_mempool_transactions_count()
// get_o_indexes.bin               get_indexes()
// get_orphan_blocks_count         get_orphan_blocks_count()
// get_outgoing_connections        get_outgoing_connections()
// get_outgoing_connections_count  get_outgoing_connections_count()
// get_pool_changes.bin            get_pool_changes()
// get_pool_changes_lite.bin       get_pool_changes_lite()
// get_random_outs.bin             get_random_outs()
// get_total_transactions_count    get_total_transactions_count()
// get_transaction                 get_transaction()
// get_transaction_fee             get_transaction_fee()
// get_transactions                get_transactions()
// get_white_peerlist              get_white_peerlist()
// get_white_peerlist_size         get_white_peerlist_size()
// json_rpc                        processJsonRpcRequest()
// query_blocks.bin                query_blocks()
// query_blocks_lite.bin           query_blocks_lite()
// send_raw_transaction            send_raw_tx()
// start_mining                    start_mining()
// stop_daemon                     stop_daemon()
// stop_mining                     stop_mining()
// submit_block                    submit_block()
// validate_address                validate_address()

namespace CryptoNote {


// Public functions


namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.addHeader("Content-Type", "application/json");

    std::string corsDomain = obj->getCorsDomain();

    if (!corsDomain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", corsDomain);
    }

    response.setBody(storeToJson(res.data()));
    return result;
  };
}

}
  
std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers  = {
  // binary handlers
  { "/get_blocks.bin",            { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::get_blocks), false } },
  { "/query_blocks.bin",          { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::query_blocks), false } },
  { "/query_blocks_lite.bin",     { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::query_blocks_lite), false } },
  { "/get_o_indexes.bin",         { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::get_indexes), false } },
  { "/get_random_outs.bin",       { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::get_random_outs), false } },
  { "/get_pool_changes.bin",      { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::get_pool_changes), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::get_pool_changes_lite), false } },
  
  // HTTP RPC
  { "/get_circulating_supply",          { jsonMethod<COMMAND_RPC_GET_CIRCULATING_SUPPLY>(&RpcServer::get_circulating_supply), true } },
  { "/get_connections",                 { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::get_connections), true } },
  { "/get_connections_count",           { jsonMethod<COMMAND_RPC_GET_CONNECTIONS_COUNT>(&RpcServer::get_connections_count), true } },
  { "/get_difficulty",                  { jsonMethod<COMMAND_RPC_GET_DIFFICULTY>(&RpcServer::get_difficulty), true } },
  { "/get_grey_peerlist",               { jsonMethod<COMMAND_RPC_GET_GREY_PEERLIST>(&RpcServer::get_grey_peerlist), true } },
  { "/get_grey_peerlist_size",          { jsonMethod<COMMAND_RPC_GET_GREY_PEERLIST_SIZE>(&RpcServer::get_grey_peerlist_size), true } },
  { "/get_height",                      { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::get_height), true } },
  { "/get_incoming_connections",        { jsonMethod<COMMAND_RPC_GET_INCOMING_CONNECTIONS>(&RpcServer::get_incoming_connections), true } },
  { "/get_incoming_connections_count",  { jsonMethod<COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT>(&RpcServer::get_incoming_connections_count), true } },
  { "/get_info",                        { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::get_info), true } },
  { "/get_mempool_transactions_count",  { jsonMethod<COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT>(&RpcServer::get_mempool_transactions_count), true } },
  { "/get_orphan_blocks_count",         { jsonMethod<COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT>(&RpcServer::get_orphan_blocks_count), true } },
  { "/get_outgoing_connections",        { jsonMethod<COMMAND_RPC_GET_OUTGOING_CONNECTIONS>(&RpcServer::get_outgoing_connections), true } },
  { "/get_outgoing_connections_count",  { jsonMethod<COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT>(&RpcServer::get_outgoing_connections_count), true } },
  { "/get_total_transactions_count",    { jsonMethod<COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT>(&RpcServer::get_total_transactions_count), false } },
  { "/get_transactions",                { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::get_transactions), false } },
  { "/get_transaction_fee",             { jsonMethod<COMMAND_RPC_GET_TRANSACTION_FEE>(&RpcServer::get_transaction_fee), false } },
  { "/get_white_peerlist_size",         { jsonMethod<COMMAND_RPC_GET_WHITE_PEERLIST_SIZE>(&RpcServer::get_white_peerlist_size), true } },
  { "/get_white_peerlist",              { jsonMethod<COMMAND_RPC_GET_WHITE_PEERLIST>(&RpcServer::get_white_peerlist), true } },
  { "/send_raw_transaction",            { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::send_raw_tx), false } },
  { "/start_mining",                    { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::start_mining), false } }, // disabled in restricted rpc mode
  { "/stop_mining",                     { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::stop_mining), false } }, // disabled in restricted rpc mode
  { "/stop_daemon",                     { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::stop_daemon), true } }, // disabled in restricted rpc mode

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& core, NodeServer& nodeServer, const ICryptoNoteProtocolQuery& cryptoNoteProtocolQuery) :
  HttpServer(dispatcher, log),
  m_logger(log, "DaemonRpcServer"),
  m_core(core),
  m_nodeServer(nodeServer),
  m_cryptoNoteProtocolQuery(cryptoNoteProtocolQuery) {
}

void RpcServer::enableCors(const std::string domain) {
  m_cors_domain = domain;
}

std::string RpcServer::getCorsDomain() {
  return m_cors_domain;
}

void RpcServer::setRestrictedRpc(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
}


// Pirvate functions


bool RpcServer::check_payment(const COMMAND_RPC_CHECK_PAYMENT::request& request, COMMAND_RPC_CHECK_PAYMENT::response& response) {
	// parse transaction hash
	Crypto::Hash transactionHash;
	if (!parse_hash256(request.transaction_id, transactionHash)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction id" };
	}

	// parse address
	CryptoNote::AccountPublicAddress address;
	if (!m_core.currency().parseAccountAddressString(request.receiver_address, address)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Receiver's address not found" };
	}

	// parse transaction private key
	Crypto::Hash transactionPrivateKeyHash;
	size_t size;
	if (!Common::fromHex(request.transaction_private_key, &transactionPrivateKeyHash, sizeof(transactionPrivateKeyHash), size) || size != sizeof(transactionPrivateKeyHash)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction secret key" };
	}
	Crypto::SecretKey transactionPrivateKey = *(struct Crypto::SecretKey *) &transactionPrivateKeyHash;

	// fetch tx
	Transaction tx;
	std::vector<Crypto::Hash> tx_hashes;
	tx_hashes.push_back(transactionHash);
	std::list<Crypto::Hash> missed_txs;
	std::list<Transaction> txs;
	m_core.getTransactions(tx_hashes, txs, missed_txs, true);

	if (txs.size() == 1)
  {
		tx = txs.front();
	}
	else
  {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction ID was not found" };
	}

	CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

	// obtain key derivation
	Crypto::KeyDerivation derivation;
	if (!Crypto::generate_key_derivation(address.viewPublicKey, transactionPrivateKey, derivation))
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
	}
	
	// look for outputs
	uint64_t received = 0;
	size_t keyIndex = 0;
	std::vector<TransactionOutput> outputs;
	try {
		for (const TransactionOutput& output : transaction.outputs) {
			if (output.target.type() == typeid(KeyOutput)) {
				const KeyOutput out_key = boost::get<KeyOutput>(output.target);
				Crypto::PublicKey pubkey;
				derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
				if (pubkey == out_key.key) {
					received += output.amount;
					outputs.push_back(output);
				}
			}
			++keyIndex;
		}
	}
	catch (...)
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
	}

	response.amount = received;
	response.outputs = outputs;
	response.status = CORE_RPC_STATUS_OK;
	return true;
}

void RpcServer::fill_block_header_response(const Block& block, bool orphan_status, uint64_t blockIndex, const Crypto::Hash& blockHash, block_header_response& response) {
  response.timestamp = block.timestamp;
  response.prev_hash = Common::podToHex(block.previousBlockHash);
  response.merkle_root = Common::podToHex(block.merkleRoot);
  response.nonce = block.nonce;
  response.orphan_status = orphan_status;
  response.height = blockIndex + 1;
  response.depth = m_core.get_current_blockchain_height() - blockIndex - 1;
  response.hash = Common::podToHex(blockHash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), response.difficulty);

  for (const TransactionOutput& output : block.baseTransaction.outputs) {
    response.reward += output.amount;
  }
}

bool RpcServer::getRingSignatureSize(const Transaction& transaction, uint64_t& ringSignatureSize) {
  // base input
  if (transaction.inputs.size() == 1 && transaction.inputs[0].type() == typeid(BaseInput))
  {
    ringSignatureSize = 1;
    return true;
  }

  ringSignatureSize = 0;

  // key input
  for (const TransactionInput& input : transaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      uint64_t curRingSignatureSize = boost::get<KeyInput>(input).outputIndexes.size();
      if (curRingSignatureSize > ringSignatureSize) {
        ringSignatureSize = curRingSignatureSize;
      }
    }
  }

  return true;
}

bool RpcServer::get_block(const COMMAND_RPC_GET_BLOCK::request& request, COMMAND_RPC_GET_BLOCK::response& response) {

  // Get the block hash
  // User can provide a block height or a block hash in the request
  Crypto::Hash blockHash;
  try {
    uint32_t tempBlockHeight = boost::lexical_cast<uint32_t>(request.hash);

    if (tempBlockHeight == 0) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT, std::string("Height must be greater than 0") };
    }

    uint32_t tempBlockIndex = tempBlockHeight - 1;
    blockHash = m_core.getBlockIdByHeight(tempBlockIndex);
  } catch (boost::bad_lexical_cast &) {
    if (!parse_hash256(request.hash, blockHash)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse hex representation of block hash. Hex = " + request.hash + '.' };
    }
  }


  // get the block from the block hash
  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by hash. Hash = " + request.hash + '.' };
  }

  if (block.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t blockIndex = boost::get<BaseInput>(block.baseTransaction.inputs.front()).blockIndex;
  uint32_t blockHeight = blockIndex + 1;
  response.block.height = blockHeight;

  bool isOrphaned = true;
  if (blockHash == m_core.getBlockIdByHeight(blockIndex))
  {
    isOrphaned = false;
  }

  response.block.is_orphaned = isOrphaned;
  response.block.timestamp = block.timestamp;
  response.block.prev_hash = Common::podToHex(block.previousBlockHash);
  response.block.merkle_root = Common::podToHex(block.merkleRoot);
  response.block.nonce = block.nonce;
  response.block.depth = m_core.get_current_blockchain_height() - blockIndex - 1;
  response.block.hash = Common::podToHex(blockHash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), response.block.difficulty);

  response.block.total_reward = 0;

  for (const TransactionOutput& output : block.baseTransaction.outputs) {
    response.block.total_reward += output.amount;
  }

  size_t blockSize = 0;
  if (!m_core.getBlockSize(blockHash, blockSize)) {
    return false;
  }

  response.block.transactions_size = blockSize;

  size_t blockBlobSize = getObjectBinarySize(block);
  size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
  response.block.size = blockBlobSize + response.block.transactions_size - minerTxBlobSize;

  uint64_t alreadyGeneratedCoins;
  if (!m_core.getAlreadyGeneratedCoins(blockHash, alreadyGeneratedCoins)) {
    return false;
  }

  response.block.already_generated_coins = std::to_string(alreadyGeneratedCoins);

  if (!m_core.getGeneratedTransactionsNumber(blockIndex, response.block.already_generated_transactions)) {
    return false;
  }

  uint64_t prevBlockGeneratedCoins = 0;
  if (blockIndex > 0) {
    if (!m_core.getAlreadyGeneratedCoins(block.previousBlockHash, prevBlockGeneratedCoins)) {
      return false;
    }
  }

  uint64_t baseReward = 0;
  int64_t emissionChangeIgnore = 0;

  if (!m_core.getBlockReward2(blockHeight, response.block.transactions_size, prevBlockGeneratedCoins, 0, baseReward, emissionChangeIgnore)) {
    return false;
  }

  response.block.base_reward = baseReward;

  // Base transaction
  transaction_short_response transaction_short;
  transaction_short.hash = Common::podToHex(getObjectHash(block.baseTransaction));
  transaction_short.fee = 0;
  transaction_short.amount_out = get_outs_money_amount(block.baseTransaction);
  transaction_short.size = getObjectBinarySize(block.baseTransaction);
  response.block.transactions.push_back(transaction_short);

  // Block transactions
  std::list<Crypto::Hash> missed_txs_ignore;
  std::list<Transaction> txs;
  m_core.getTransactions(block.transactionHashes, txs, missed_txs_ignore);

  response.block.total_fees = 0;

  for (const Transaction& transaction : txs) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(transaction, amount_in);
    uint64_t amount_out = get_outs_money_amount(transaction);

    transaction_short.hash = Common::podToHex(getObjectHash(transaction));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(transaction);
    response.block.transactions.push_back(transaction_short);

    response.block.total_fees += transaction_short.fee;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_block_count(const COMMAND_RPC_GET_BLOCK_COUNT::request& request, COMMAND_RPC_GET_BLOCK_COUNT::response& response) {
  response.count = m_core.get_current_blockchain_height();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_block_hash(const COMMAND_RPC_GET_BLOCK_HASH::request& request, COMMAND_RPC_GET_BLOCK_HASH::response& response) {
  if (request.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t blockHeight = static_cast<uint32_t>(request[0]);
  Crypto::Hash blockHash = m_core.getBlockIdByHeight(blockHeight);
  if (blockHash == NULL_HASH) {
    std::string errorMessage = std::string("Block height too big : ") + std::to_string(blockHeight) + ", current blockchain height is " + std::to_string(m_core.get_current_blockchain_height());
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT, errorMessage };
  }

  response = Common::podToHex(blockHash);
  return true;
}

bool RpcServer::get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& response) {
  Crypto::Hash blockHash;

  if (!parse_hash256(request.hash, blockHash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + request.hash + '.' };
  }

  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + request.hash + '.' };
  }

  if (block.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint64_t blockIndex = boost::get<BaseInput>(block.baseTransaction.inputs.front()).blockIndex;
  fill_block_header_response(block, false, blockIndex, blockHash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& response) {

  if (request.height == 0) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT, std::string("Height must be greater than 0") };
  }

  uint32_t currentBlockchainHeight = m_core.get_current_blockchain_height();
  if (request.height > currentBlockchainHeight) {
    std::string errorMessage = std::string("Height is too big : ") + std::to_string(request.height) + ", current blockchain height = " + std::to_string(currentBlockchainHeight);
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT, errorMessage };
  }

  uint32_t blockIndex = request.height - 1;
  Crypto::Hash blockHash = m_core.getBlockIdByHeight(blockIndex);
  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    std::string errorMessage = "Internal error: Cannot get block at height : " + std::to_string(request.height);
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, errorMessage };
  }

  fill_block_header_response(block, false, blockIndex, blockHash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

namespace {

uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
{
  void* buf = start_buff;
  void* end = (char*)buf + buflen - patlen;
  while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
  {
    if (buf>end)
    {
      return 0;
    }

    if (memcmp(buf, pat, patlen) == 0)
    {
      return (char*)buf - (char*)start_buff;
    }

    buf = (char*)buf + 1;
  }

  return 0;
}

}

bool RpcServer::get_block_template(const COMMAND_RPC_GET_BLOCK_TEMPLATE::request& request, COMMAND_RPC_GET_BLOCK_TEMPLATE::response& response) {
  if (request.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "Reserved size is too big, maximum 60" };
  }

  AccountPublicAddress account = boost::value_initialized<AccountPublicAddress>();

  if (!request.wallet_address.size() || !m_core.currency().parseAccountAddressString(request.wallet_address, account)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address" };
  }

  Block block = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(request.reserve_size, 0);
  if (!m_core.get_block_template(block, account, response.difficulty, response.height, blob_reserve)) {
    m_logger(Logging::ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(block);
  Crypto::PublicKey transactionPublicKey = CryptoNote::getTransactionPublicKeyFromExtra(block.baseTransaction.extra);
  if (transactionPublicKey == NULL_PUBLIC_KEY) {
    m_logger(Logging::ERROR) << "Failed to find transaction pubic key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find transaction pubic key in coinbase extra" };
  }

  if (request.reserve_size > 0) {
    response.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &transactionPublicKey, sizeof(transactionPublicKey));
    if (!response.reserved_offset) {
      m_logger(Logging::ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    response.reserved_offset += sizeof(transactionPublicKey) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (response.reserved_offset + request.reserve_size > block_blob.size()) {
      m_logger(Logging::ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    response.reserved_offset = 0;
  }

  response.block_template_blob = Common::toHex(block_blob);
  response.status = CORE_RPC_STATUS_OK;
  response.coinbase_transaction = Common::toHex(toBinaryArray(block.baseTransaction));

  BinaryArray baseTransactionBA = toBinaryArray(block.baseTransaction);

  // response.tranasction_hashes is used for the sole purpose of calculating the merkle root and does not affect what transaction hashes are included in the block

  if (baseTransactionBA.size() > 120)
  {
    BinaryArray baseTransactionHeadBA(baseTransactionBA.begin(), baseTransactionBA.end() - 120);

    Crypto::Hash baseTransactionHeadHash = getBinaryArrayHash(baseTransactionHeadBA);

    response.transaction_hashes.push_back(Common::podToHex(baseTransactionHeadHash));
  }

  for (Crypto::Hash transactionHash : block.transactionHashes)
  {
    response.transaction_hashes.push_back(Common::podToHex(transactionHash));
  }

  return true;
}

bool RpcServer::get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& request, COMMAND_RPC_GET_BLOCKS_FAST::response& response) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (request.block_ids.empty()) {
    response.status = CORE_RPC_STATUS_FAILED;
    return false;
  }

  if (request.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    response.status = CORE_RPC_STATUS_FAILED;
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(request.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  response.current_height = totalBlockCount;
  response.start_height = startBlockIndex;

  for (const Crypto::Hash& blockHash : supplement) {
    assert(m_core.have_block(blockHash));
    std::unique_ptr<IBlock> blockWithTransactions = m_core.getBlock(blockHash);
    assert(blockWithTransactions != nullptr);

    response.blocks.resize(response.blocks.size() + 1);
    response.blocks.back().block = Common::asString(toBinaryArray(blockWithTransactions->getBlock()));

    response.blocks.back().txs.reserve(blockWithTransactions->getTransactionCount());
    for (size_t i = 0; i < blockWithTransactions->getTransactionCount(); ++i) {
      response.blocks.back().txs.push_back(Common::asString(toBinaryArray(blockWithTransactions->getTransaction(i))));
    }
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_blocks_json(const COMMAND_RPC_GET_BLOCKS_JSON::request& request, COMMAND_RPC_GET_BLOCKS_JSON::response& response) {
  if (request.height == 0) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT, std::string("Height must be greater than 0") };
  }

  uint32_t currentBlockchainHeight = m_core.get_current_blockchain_height();
  if (request.height > currentBlockchainHeight) {
    std::string errorMessage = std::string("Height is too big : ") + std::to_string(request.height) + ", current blockchain height = " + std::to_string(currentBlockchainHeight);
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT, errorMessage };
  }

  uint32_t startBlockIndex = request.height - 1;
  uint32_t numBlocksToPrint = 30;
  uint32_t lastBlockIndex = 0;
  if (request.height > numBlocksToPrint)  {
    uint32_t lastBlockHeight = request.height - numBlocksToPrint;
    lastBlockIndex = lastBlockHeight - 1;
  }

  for (uint32_t blockIndex = startBlockIndex; blockIndex >= lastBlockIndex; blockIndex--) {
    Crypto::Hash blockHash = m_core.getBlockIdByHeight(static_cast<uint32_t>(blockIndex));
    Block block;
    if (!m_core.getBlockByHash(blockHash, block)) {
      std::string errorMessage = "Internal error: Cannot get block at height " + std::to_string(blockIndex + 1);
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, errorMessage };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blockBlobSize = getObjectBinarySize(block);
    size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
    difficulty_type difficulty;
    m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), difficulty);

    block_short_response block_short;
    block_short.timestamp = block.timestamp;
    block_short.height = blockIndex + 1;
    block_short.hash = Common::podToHex(blockHash);
    block_short.size = blockBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.transaction_count = block.transactionHashes.size() + 1;
    block_short.difficulty = difficulty;

    response.blocks.push_back(block_short);

    if (blockIndex == 0)
    {
      break;
    }
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_circulating_supply(const COMMAND_RPC_GET_CIRCULATING_SUPPLY::request& request, COMMAND_RPC_GET_CIRCULATING_SUPPLY::response& response) {
  response.circulating_supply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& request, COMMAND_RPC_GET_CONNECTIONS::response& response) {
  m_nodeServer.get_payload_object().get_all_connections_addresses(response.connections);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_connections_count(const COMMAND_RPC_GET_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_CONNECTIONS_COUNT::response& response) {
  response.connections_count = m_nodeServer.get_connections_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& request, COMMAND_RPC_GET_CURRENCY_ID::response& response) {
  Crypto::Hash genesisBlockHash = m_core.currency().genesisBlockHash();
  response.currency_id_blob = Common::podToHex(genesisBlockHash);
  return true;
}

bool RpcServer::get_difficulty(const COMMAND_RPC_GET_DIFFICULTY::request& request, COMMAND_RPC_GET_DIFFICULTY::response& response) {
  response.difficulty = m_core.getNextBlockDifficulty();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_grey_peerlist(const COMMAND_RPC_GET_GREY_PEERLIST::request& request, COMMAND_RPC_GET_GREY_PEERLIST::response& response) {
  std::list<PeerlistEntry> greyPeerlist;
  std::list<PeerlistEntry> whitePeerlistIgnore;

  m_nodeServer.getPeerlistManager().get_peerlist_full(greyPeerlist, whitePeerlistIgnore);

  for (const PeerlistEntry& greyPeer : greyPeerlist)
  {
    response.grey_peerlist.push_back(Common::ipAddressToString(greyPeer.adr.ip));
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_grey_peerlist_size(const COMMAND_RPC_GET_GREY_PEERLIST_SIZE::request& request, COMMAND_RPC_GET_GREY_PEERLIST_SIZE::response& response) {
  response.grey_peerlist_size = m_nodeServer.getPeerlistManager().get_gray_peers_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_height(const COMMAND_RPC_GET_HEIGHT::request& request, COMMAND_RPC_GET_HEIGHT::response& response) {
  response.height = m_core.get_current_blockchain_height();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_incoming_connections(const COMMAND_RPC_GET_INCOMING_CONNECTIONS::request& request, COMMAND_RPC_GET_INCOMING_CONNECTIONS::response& response) {
  m_nodeServer.get_payload_object().get_incoming_connections_addresses(response.incoming_connections);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_incoming_connections_count(const COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::response& response) {
  uint64_t totalConnections = m_nodeServer.get_connections_count();
  size_t outgoingConnectionsCount = m_nodeServer.get_outgoing_connections_count();
  response.incoming_connections_count = totalConnections - outgoingConnectionsCount;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& request, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& response) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexes(request.transaction_id, outputIndexes)) {
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  response.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_info(const COMMAND_RPC_GET_INFO::request& request, COMMAND_RPC_GET_INFO::response& response) {
  response.height = m_core.get_current_blockchain_height();
  response.difficulty = m_core.getNextBlockDifficulty();
  response.total_transactions_count = m_core.get_blockchain_total_transactions() - response.height; //without coinbase
  response.mempool_transactions_count = m_core.get_pool_transactions_count();
  response.orphan_blocks_count = m_core.get_alternative_blocks_count();
  uint64_t connectionsCount = m_nodeServer.get_connections_count();
  response.connections_count = connectionsCount;
  response.outgoing_connections_count = m_nodeServer.get_outgoing_connections_count();
  response.incoming_connections_count = connectionsCount - response.outgoing_connections_count;
  response.white_peerlist_size = m_nodeServer.getPeerlistManager().get_white_peers_count();
  response.grey_peerlist_size = m_nodeServer.getPeerlistManager().get_gray_peers_count();
  response.last_known_block_index = std::max(static_cast<uint32_t>(1), m_cryptoNoteProtocolQuery.getObservedHeight()) - 1;
  // uint64_t is unsafe in JavaScript environment so we display it as a formatted string instead
  response.circulating_supply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  response.transaction_fee = m_core.getMinimalFee();

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& request, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& response) {
  uint32_t topBlockIndex;
  Crypto::Hash topBlockHash;
  
  m_core.get_blockchain_top(topBlockIndex, topBlockHash);

  Block topBlock;
  if (!m_core.getBlockByHash(topBlockHash, topBlock)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }
  
  fill_block_header_response(topBlock, false, topBlockIndex, topBlockHash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_mempool(const COMMAND_RPC_GET_MEMPOOL::request& request, COMMAND_RPC_GET_MEMPOOL::response& response) {
  auto pool = m_core.getMemoryPool();
  for (const auto& transactionDetail : pool) {
    mempool_transaction_response mempool_transaction;
    uint64_t amount_out = getOutputAmount(transactionDetail.tx);

    mempool_transaction.hash = Common::podToHex(transactionDetail.id);
    mempool_transaction.fee = transactionDetail.fee;
    mempool_transaction.amount_out = amount_out;
    mempool_transaction.size = transactionDetail.blobSize;
    mempool_transaction.receive_time = transactionDetail.receiveTime;
    response.mempool.push_back(mempool_transaction);
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_mempool_transactions_count(const COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::request& request, COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::response& response) {
  response.mempool_transactions_count = m_core.get_pool_transactions_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_orphan_blocks_count(const COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::request& request, COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::response& response) {
  response.orphan_blocks_count = m_core.get_alternative_blocks_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_outgoing_connections(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS::request& request, COMMAND_RPC_GET_OUTGOING_CONNECTIONS::response& response) {
  m_nodeServer.get_payload_object().get_outgoing_connections_addresses(response.outgoing_connections);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_outgoing_connections_count(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::response& response) {
  response.outgoing_connections_count = m_nodeServer.get_outgoing_connections_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_pool_changes(const COMMAND_RPC_GET_POOL_CHANGES::request& request, COMMAND_RPC_GET_POOL_CHANGES::response& response) {
  response.status = CORE_RPC_STATUS_OK;
  std::vector<Transaction> addedTransactions;
  response.is_tail_block_actual = m_core.getPoolChanges(request.tail_block_id, request.known_txs_ids, addedTransactions, response.deleted_txs_ids);
 
  for (const Transaction& transaction : addedTransactions) {
    BinaryArray transactionBlob;
    if (!toBinaryArray(transaction, transactionBlob)) {
      response.status = CORE_RPC_STATUS_FAILED;
      break;
    }

    response.added_txs.emplace_back(std::move(transactionBlob));
  }

  return true;
}

bool RpcServer::get_pool_changes_lite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& request, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& response) {
  response.status = CORE_RPC_STATUS_OK;
  response.is_tail_block_actual = m_core.getPoolChangesLite(request.tail_block_id, request.known_txs_ids, response.added_txs, response.deleted_txs_ids);
  return true;
}

bool RpcServer::get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& request, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& response) {
  response.status = CORE_RPC_STATUS_FAILED;

  if (!m_core.get_random_outs_for_amounts(request, response)) {
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::get_total_transactions_count(const COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::request& request, COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::response& response) {
  uint32_t numCoinbaseTransactions = m_core.get_current_blockchain_height();
  response.total_transactions_count = m_core.get_blockchain_total_transactions() - numCoinbaseTransactions;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_transaction(const COMMAND_RPC_GET_TRANSACTION::request& request, COMMAND_RPC_GET_TRANSACTION::response& response) {
  Crypto::Hash transactionHash;

  if (!parse_hash256(request.hash, transactionHash)) {
    std::string errorMessage = "Failed to parse hex representation of transaction hash. Hex = " + request.hash + '.';
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, errorMessage };
  }

  std::vector<Crypto::Hash> transactionHashes;
  transactionHashes.push_back(transactionHash);

  std::list<Crypto::Hash> missedTransactionsIgnore;
  std::list<Transaction> transactions;
  m_core.getTransactions(transactionHashes, transactions, missedTransactionsIgnore, true);

  if (transactions.size() == 1) {
    response.transaction = transactions.front();
  } else {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction ID was not found" };
  }

  Crypto::Hash blockHash;
  uint32_t blockIndex;
  if (m_core.getBlockContainingTx(transactionHash, blockHash, blockIndex)) {
    Block block;
    if (m_core.getBlockByHash(blockHash, block)) {
      size_t totalBlockTransactionsSize;
      m_core.getBlockSize(blockHash, totalBlockTransactionsSize);
      size_t blockBlobSize = getObjectBinarySize(block);
      size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
      response.block.size = blockBlobSize + totalBlockTransactionsSize - minerTxBlobSize;

      difficulty_type difficulty;
      m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), difficulty);
      response.block.difficulty = difficulty;

      response.block.timestamp = block.timestamp;
      response.block.height = blockIndex + 1;
      response.block.hash = Common::podToHex(blockHash);
      response.block.transaction_count = block.transactionHashes.size() + 1;
    }
  }

  uint64_t amount_in = 0;
  get_inputs_money_amount(response.transaction, amount_in);
  uint64_t amount_out = get_outs_money_amount(response.transaction);

  response.transaction_details.hash = Common::podToHex(getObjectHash(response.transaction));
  response.transaction_details.fee = amount_in - amount_out;
  if (amount_in == 0)
  {
    response.transaction_details.fee = 0;
  }
  response.transaction_details.amount_out = amount_out;
  response.transaction_details.size = getObjectBinarySize(response.transaction);

  uint64_t ringSignatureSize;
  if (!getRingSignatureSize(response.transaction, ringSignatureSize)) {
    return false;
  }
  response.transaction_details.mixin = ringSignatureSize - 1;

  Crypto::Hash paymentId;
  if (CryptoNote::getPaymentIdFromTxExtra(response.transaction.extra, paymentId)) {
    response.transaction_details.payment_id = Common::podToHex(paymentId);
  } else {
    response.transaction_details.payment_id = "";
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_transaction_fee(const COMMAND_RPC_GET_TRANSACTION_FEE::request& request, COMMAND_RPC_GET_TRANSACTION_FEE::response& response) {
  response.transaction_fee = m_core.getMinimalFee();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& request, COMMAND_RPC_GET_TRANSACTIONS::response& response) {
  std::vector<Crypto::Hash> transactionHashes;
  for (const std::string& transactionHexString : request.txs_hashes) {
    BinaryArray transactionHexBlob;

    if (!Common::fromHex(transactionHexString, transactionHexBlob))
    {
      response.status = "Failed to parse hex representation of transaction hash";
      return true;
    }

    if (transactionHexBlob.size() != sizeof(Crypto::Hash))
    {
      response.status = "Failed, size of data mismatch";
      return true;
    }

    transactionHashes.push_back(*reinterpret_cast<const Crypto::Hash*>(transactionHexBlob.data()));
  }

  std::list<Crypto::Hash> missedTransactionHashes;
  std::list<Transaction> transactions;
  m_core.getTransactions(transactionHashes, transactions, missedTransactionHashes);

  for (const Transaction& transaction : transactions) {
    response.transactions_as_hex.push_back(Common::toHex(toBinaryArray(transaction)));
  }

  for (const Crypto::Hash& missedTransactionHash : missedTransactionHashes) {
    response.missed_transactions.push_back(Common::podToHex(missedTransactionHash));
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_white_peerlist(const COMMAND_RPC_GET_WHITE_PEERLIST::request& request, COMMAND_RPC_GET_WHITE_PEERLIST::response& response) {
  std::list<PeerlistEntry> greyPeerlistIgnore;
  std::list<PeerlistEntry> whitePeerlist;

  m_nodeServer.getPeerlistManager().get_peerlist_full(greyPeerlistIgnore, whitePeerlist);

  for (PeerlistEntry const& peer : whitePeerlist)
  {
    response.white_peerlist.push_back(Common::ipAddressToString(peer.adr.ip));
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::get_white_peerlist_size(const COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::request& request, COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::response& response) {
  response.white_peerlist_size = m_nodeServer.getPeerlistManager().get_white_peers_count();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_nodeServer.get_payload_object().isSynchronized();
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  // using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");

  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
  }

  JsonRpc::JsonRpcRequest jsonRequest;
  JsonRpc::JsonRpcResponse jsonResponse;

  try {
    m_logger(Logging::TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonRpc::JsonMemberMethod>> jsonRpcHandlers = {
      { "check_payment",              { JsonRpc::makeMemberMethod(&RpcServer::check_payment), false } },
      { "get_block",                  { JsonRpc::makeMemberMethod(&RpcServer::get_block), false } },
      { "get_block_count",            { JsonRpc::makeMemberMethod(&RpcServer::get_block_count), true } },
      { "get_block_hash",             { JsonRpc::makeMemberMethod(&RpcServer::get_block_hash), false } },
      { "get_block_header_by_hash",   { JsonRpc::makeMemberMethod(&RpcServer::get_block_header_by_hash), false } },
      { "get_block_header_by_height", { JsonRpc::makeMemberMethod(&RpcServer::get_block_header_by_height), false } },
      { "get_block_template",         { JsonRpc::makeMemberMethod(&RpcServer::get_block_template), false } },
      { "get_blocks",                 { JsonRpc::makeMemberMethod(&RpcServer::get_blocks_json), false } },
      { "get_currency_id",            { JsonRpc::makeMemberMethod(&RpcServer::get_currency_id), true } },
      { "get_last_block_header",      { JsonRpc::makeMemberMethod(&RpcServer::get_last_block_header), false } },
      { "get_mempool",                { JsonRpc::makeMemberMethod(&RpcServer::get_mempool), false } },
      { "get_transaction",            { JsonRpc::makeMemberMethod(&RpcServer::get_transaction), false } },
      { "submit_block",               { JsonRpc::makeMemberMethod(&RpcServer::submit_block), false } },
      { "validate_address",           { JsonRpc::makeMemberMethod(&RpcServer::validate_address), false } },
    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpc::JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpc::JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpc::JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  m_logger(Logging::TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  std::string url = request.getUrl();

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    response.setStatus(HttpResponse::STATUS_404);
    return;
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);
}

bool RpcServer::query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& request, COMMAND_RPC_QUERY_BLOCKS::response& response) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(request.block_ids, request.timestamp, startHeight, currentHeight, fullOffset, response.items)) {
    response.status = CORE_RPC_STATUS_FAILED;
    return false;
  }

  response.start_height = startHeight;
  response.current_height = currentHeight;
  response.full_offset = fullOffset;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& request, COMMAND_RPC_QUERY_BLOCKS_LITE::response& response) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocksLite(request.block_ids, request.timestamp, startHeight, currentHeight, fullOffset, response.items)) {
    response.status = CORE_RPC_STATUS_FAILED;
    return false;
  }

  response.start_height = startHeight;
  response.current_height = currentHeight;
  response.full_offset = fullOffset;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& request, COMMAND_RPC_SEND_RAW_TX::response& response) {
  BinaryArray transactionBlob;
  if (!Common::fromHex(request.tx_as_hex, transactionBlob))
  {
    m_logger(Logging::INFO) << "send_raw_tx : Failed to parse tx from hexbuff: " << request.tx_as_hex;
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(transactionBlob, tvc, false))
  {
    m_logger(Logging::INFO) << "send_raw_tx : Failed to process tx";
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  if (tvc.m_verification_failed)
  {
    m_logger(Logging::INFO) << "send_raw_tx : tx verification failed";
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    m_logger(Logging::INFO) << " send_raw_tx : tx accepted, but not relayed";
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  // CryptoNoteProtocol
  NOTIFY_NEW_TRANSACTIONS::request notification;
  notification.txs.push_back(Common::asString(transactionBlob));
  // send new transaction information to other peer nodes
  m_core.get_protocol()->relay_transactions(notification);
  //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::start_mining(const COMMAND_RPC_START_MINING::request& request, COMMAND_RPC_START_MINING::response& response) {
  if (m_restricted_rpc) {
    response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
    return false;
  }

  AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(request.miner_address, address)) {
    response.status = "Failed, wrong address";
    return true;
  }

  if (!m_core.get_miner().start(address, static_cast<size_t>(request.threads_count))) {
    response.status = "Failed, mining not started";
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& request, COMMAND_RPC_STOP_DAEMON::response& response) {
  if (m_restricted_rpc) {
    response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
    return false;
  }

  // Can only be called for testnet?
  if (m_core.currency().isTestnet()) {
    m_nodeServer.sendStopSignal();
    response.status = CORE_RPC_STATUS_OK;
  } else {
    response.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }

  return true;
}

bool RpcServer::stop_mining(const COMMAND_RPC_STOP_MINING::request& request, COMMAND_RPC_STOP_MINING::response& response) {
  if (m_restricted_rpc) {
    response.status = CORE_RPC_STATUS_FAILED_RESTRICTED;
    return false;
  }

  if (!m_core.get_miner().stop()) {
    response.status = CORE_RPC_STATUS_FAILED;
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::submit_block(const COMMAND_RPC_SUBMIT_BLOCK::request& request, COMMAND_RPC_SUBMIT_BLOCK::response& response) {
  if (request.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!Common::fromHex(request[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& request, COMMAND_RPC_VALIDATE_ADDRESS::response& response) {

	try {
    CryptoNote::AccountPublicAddress publicKeysIgnore;
    if (m_core.currency().parseAccountAddressString(request.address, publicKeysIgnore)) {
      response.address_valid = true;
    }
    else
    {
      response.address_valid = false;
    }
	}
	catch (...)
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
	}

  response.status = CORE_RPC_STATUS_OK;
	return true;
}

} // end namespace CryptoNote
