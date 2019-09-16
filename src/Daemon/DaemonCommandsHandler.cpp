// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DaemonCommandsHandler.h"
#include "P2p/NodeServer.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Serialization/SerializationTools.h"
#include "version.h"


// Public functions


DaemonCommandsHandler::DaemonCommandsHandler(CryptoNote::Core& core, CryptoNote::NodeServer& nodeServer, Logging::LoggerManager& log) :
  m_core(core), m_nodeServer(nodeServer), m_logger(log, "daemon"), m_logManager(log) {

  m_consoleHandler.setHandler("exit", boost::bind(&DaemonCommandsHandler::exit, this, _1), "Shutdown the daemon");
  m_consoleHandler.setHandler("help", boost::bind(&DaemonCommandsHandler::help, this, _1), "Show this help");
  m_consoleHandler.setHandler("hide_hr", boost::bind(&DaemonCommandsHandler::hide_hr, this, _1), "Stop showing hash rate");
  m_consoleHandler.setHandler("print_bc", boost::bind(&DaemonCommandsHandler::print_bc, this, _1), "Print blockchain info in a given blocks range\n * print_bc <start_height> [<end_height>]\n * start_height is the starting block height, integer, mandatory\n * end_height is the end block height, integer, optional");
  m_consoleHandler.setHandler("print_block", boost::bind(&DaemonCommandsHandler::print_block, this, _1), "Print block\n * print_block <block_hash> or print_block <block_height>\n * block_hash is a 64 character string\n * block_height is an integer");
  m_consoleHandler.setHandler("print_circulating_supply", boost::bind(&DaemonCommandsHandler::print_circulating_supply, this, _1), "Print the number of coins mined so far");
  m_consoleHandler.setHandler("print_cn", boost::bind(&DaemonCommandsHandler::print_cn, this, _1), "Print connections");
  m_consoleHandler.setHandler("print_cn_count", boost::bind(&DaemonCommandsHandler::print_cn_count, this, _1), "Print the number of nodes we are connected to");
  m_consoleHandler.setHandler("print_difficulty", boost::bind(&DaemonCommandsHandler::print_difficulty, this, _1), "Print the difficulty of the next block to be added to the blockchain");
  m_consoleHandler.setHandler("print_grey_pl", boost::bind(&DaemonCommandsHandler::print_grey_pl, this, _1), "Print the IP addresses of known but not currently active peers");
  m_consoleHandler.setHandler("print_grey_pl_count", boost::bind(&DaemonCommandsHandler::print_grey_pl_count, this, _1), "Print the number of known but not currently active peers");
  m_consoleHandler.setHandler("print_height", boost::bind(&DaemonCommandsHandler::print_blockchain_height, this, _1), "Print height of local blockchain");
  m_consoleHandler.setHandler("print_incoming_cn", boost::bind(&DaemonCommandsHandler::print_incoming_cn, this, _1), "Print the IP address and ports of the peers connected to you and pulling information from your node");
  m_consoleHandler.setHandler("print_incoming_cn_count", boost::bind(&DaemonCommandsHandler::print_incoming_cn_count, this, _1), "Print the number of the peers connected to you and pulling information from your node");
  m_consoleHandler.setHandler("print_network_height", boost::bind(&DaemonCommandsHandler::print_network_height, this, _1), "Print the height of the tallest blockchain of your peer nodes");
  m_consoleHandler.setHandler("print_outgoing_cn", boost::bind(&DaemonCommandsHandler::print_outgoing_cn, this, _1), "Print the IP addresses and ports of the peers you are connected to and that you are pulling information from");
  m_consoleHandler.setHandler("print_outgoing_cn_count", boost::bind(&DaemonCommandsHandler::print_outgoing_cn_count, this, _1), "Print the number of the peers you are connected to and that you are pulling information from");
  m_consoleHandler.setHandler("print_pl", boost::bind(&DaemonCommandsHandler::print_pl, this, _1), "Print peer list");
  m_consoleHandler.setHandler("print_pool", boost::bind(&DaemonCommandsHandler::print_pool, this, _1), "Print transaction pool (long format)");
  m_consoleHandler.setHandler("print_pool_sh", boost::bind(&DaemonCommandsHandler::print_pool_sh, this, _1), "Print transaction pool (short format)");
  m_consoleHandler.setHandler("print_total_transactions_count", boost::bind(&DaemonCommandsHandler::print_total_transactions_count, this, _1), "Print the total number of transactions ever created and sent on the network");
  m_consoleHandler.setHandler("print_transaction_fee", boost::bind(&DaemonCommandsHandler::print_transaction_fee, this, _1), "Print the minimum fee needed to send a transaction");
  m_consoleHandler.setHandler("print_tx", boost::bind(&DaemonCommandsHandler::print_tx, this, _1), "Print transaction\n * print_tx <transaction_hash>");
  m_consoleHandler.setHandler("print_white_pl", boost::bind(&DaemonCommandsHandler::print_white_pl, this, _1), "Print the IP addresses of currently active peers");
  m_consoleHandler.setHandler("print_white_pl_count", boost::bind(&DaemonCommandsHandler::print_white_pl_count, this, _1), "Print the number of currently active peers");
  m_consoleHandler.setHandler("set_log", boost::bind(&DaemonCommandsHandler::set_log, this, _1), "Change current log level\n * set_log <level>\n * <level> is a number 0-4");
  m_consoleHandler.setHandler("show_hr", boost::bind(&DaemonCommandsHandler::show_hr, this, _1), "Start showing hash rate");
  m_consoleHandler.setHandler("start_mining", boost::bind(&DaemonCommandsHandler::start_mining, this, _1), "Start mining for specified address\n * start_mining <addr> [threads=1]");
  m_consoleHandler.setHandler("stop_mining", boost::bind(&DaemonCommandsHandler::stop_mining, this, _1), "Stop mining");
}


// Private functions


bool DaemonCommandsHandler::exit(const std::vector<std::string>& args)
{
  m_consoleHandler.requestStop();
  m_nodeServer.sendStopSignal();
  return true;
}

std::string DaemonCommandsHandler::get_commands_str()
{
  std::stringstream ss;
  ss << "Daemon Commands" << ENDL << ENDL << m_consoleHandler.getUsage() << ENDL;
  return ss.str();
}

bool DaemonCommandsHandler::help(const std::vector<std::string>& args)
{
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Help" << '\n' << '\n' << get_commands_str() << std::endl;
  return true;
}

bool DaemonCommandsHandler::hide_hr(const std::vector<std::string>& args)
{
  m_core.get_miner().do_print_hashrate(false);
  return true;
}

bool DaemonCommandsHandler::print_bc(const std::vector<std::string> &args)
{
  if (!args.size()) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Need start height parameter" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  uint32_t startHeight = 1;
  uint32_t endHeight = 1;
  uint32_t blockchainHeight = m_core.get_current_blockchain_height();
  if (!Common::fromString(args[0], startHeight)) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong start height value" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (args.size() > 1 && !Common::fromString(args[1], endHeight)) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong end height value" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (startHeight == 0) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should be greater than 0" << ENDL;
    return false;
  }

  if (endHeight == 0) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should be greater than 0" << ENDL;
    return false;
  }

  if (startHeight > blockchainHeight) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should not be greater than " << blockchainHeight << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (endHeight > blockchainHeight) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should not be greater than " << blockchainHeight << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (endHeight == 1) {
    endHeight = startHeight + 1;
  }

  if (endHeight <= startHeight) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should be greater than start height" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  m_core.print_blockchain(startHeight - 1, endHeight - 1);
  return true;
}

bool DaemonCommandsHandler::print_bc_outs(const std::vector<std::string>& args)
{
  if (args.size() != 1)
  {
    std::cout << "need file path as parameter" << ENDL;
    return true;
  }
  m_core.print_blockchain_outs(args[0]);
  return true;
}

bool DaemonCommandsHandler::print_bci(const std::vector<std::string>& args)
{
  m_core.print_blockchain_index();
  return true;
}

bool DaemonCommandsHandler::print_block(const std::vector<std::string> &args)
{
  if (args.empty()) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected print_block <block_hash> or print_block <block_height>" << std::endl;
    return true;
  }

  const std::string &arg = args.front();
  try {
    uint32_t height = boost::lexical_cast<uint32_t>(arg);

    if (height == 0) {
      m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should be greater than 0" << ENDL;
      return false;
    }

    uint32_t blockchainHeight = m_core.get_current_blockchain_height();

    if (height > blockchainHeight) {
      m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should not be greater than " << blockchainHeight << ENDL;
      return false;
    }

    print_block_by_index(height - 1);
  } catch (boost::bad_lexical_cast &) {
    print_block_by_hash(arg);
  }

  return true;
}

bool DaemonCommandsHandler::print_block_by_hash(const std::string& arg)
{
  Crypto::Hash blockHash;
  if (!parse_hash256(arg, blockHash)) {
    return false;
  }

  uint32_t blockIndex;
  if(!m_core.getBlockHeight(blockHash, blockIndex))
  {
    std::cout << "Block with hash " << arg << " was not found." << std::endl;
    return false;
  }

  return print_block_by_index(blockIndex);
}

bool DaemonCommandsHandler::print_block_by_index(uint32_t blockIndex)
{
  if (!print_block_helper(blockIndex))
  {
    uint32_t topBlockIndex;
    Crypto::Hash topBlockHashIgnore;
    m_core.get_blockchain_top(topBlockIndex, topBlockHashIgnore);
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Block wasn't found. Current block chain height: " << topBlockIndex + 1 << ", requested: " << blockIndex + 1 << std::endl;
    return false;
  }

  return true;
}

bool DaemonCommandsHandler::print_block_helper(uint32_t blockIndex)
{
  std::list<CryptoNote::Block> blocks;
  m_core.get_blocks(blockIndex, 1, blocks);

  if (1 == blocks.size()) {
    CryptoNote::Block block = blocks.front();

    Crypto::Hash blockHash = get_block_hash(block);

    Crypto::Hash blockHashFromIndex = m_core.getBlockIdByHeight(blockIndex);
    bool isOrphaned = blockHash != blockHashFromIndex;

    // get block index from coinbase transaction
    uint32_t tempBlockIndex = boost::get<CryptoNote::BaseInput>(block.baseTransaction.inputs.front()).blockIndex;
    if (tempBlockIndex != blockIndex)
    {
      std::cout << "Block indexes do not match" << std::endl;
      return false;
    }

    // get total reward
    uint64_t totalReward = 0;
    for (const CryptoNote::TransactionOutput& out : block.baseTransaction.outputs) {
      totalReward += out.amount;
    }

    // get block's proof of work hash
    Crypto::cn_context cryptoContext;
    Crypto::Hash blockProofOfWorkHash;
    get_block_longhash(cryptoContext, block, blockProofOfWorkHash);

    // get block's difficulty
    CryptoNote::difficulty_type blockDifficulty;
    m_core.getBlockDifficulty(blockIndex, blockDifficulty);

    // get total fees
    std::list<Crypto::Hash> missedTransactionsIgnore;
    std::list<CryptoNote::Transaction> blockTransactions;
    m_core.getTransactions(block.transactionHashes, blockTransactions, missedTransactionsIgnore);

    uint64_t totalFees = 0;

    for (const CryptoNote::Transaction& tx : blockTransactions) {
      uint64_t amountIn = 0;
      get_inputs_money_amount(tx, amountIn);
      uint64_t amountOut = get_outs_money_amount(tx);
      uint64_t fee = amountIn - amountOut;
      totalFees += fee;
    }

    // get size of all block transactions combined
    size_t allTransactionsSize = 0;
    if (!m_core.getBlockSize(blockHash, allTransactionsSize)) {
      std::cout << "Unable to get total size of all transactions in the block" << std::endl;
      return false;
    }

    size_t blockBlobSize = getObjectBinarySize(block);
    size_t coinbaseTransactionSize = getObjectBinarySize(block.baseTransaction);
    size_t blockSize = blockBlobSize + allTransactionsSize - coinbaseTransactionSize;

    // get coinbase reward
    uint64_t prevBlockCirculatingSupply = 0;

    if (blockIndex > 0)
    {
      // if blockIndex is 0, then we are dealing with the genesis block and the genesis block previous hash is all zeros which is an invalid block hash so that is the reason for the if (blockIndex > 0) clause 
      
      if (!m_core.getAlreadyGeneratedCoins(block.previousBlockHash, prevBlockCirculatingSupply)) {
        std::cout << "Unable to get circulating supply from previous block" << std::endl;
        return false;
      }
    }

    uint64_t coinbaseReward = 0;
    int64_t emissionChangeIgnore = 0;
    if (!m_core.getBlockReward2(blockIndex, allTransactionsSize, prevBlockCirculatingSupply, 0, coinbaseReward, emissionChangeIgnore)) {
      std::cout << "Unable to calculate the block reward" << std::endl;
      return false;
    }

    if (totalReward - totalFees != coinbaseReward)
    {
      std::cout << "Block reward mismatch" << std::endl;
      return false;
    }

    // get circulating supply
    uint64_t alreadyGeneratedCoins;
    if (!m_core.getAlreadyGeneratedCoins(blockHash, alreadyGeneratedCoins)) {
      std::cout << "Unable to get circulating supply" << std::endl;
      return false;
    }

    // get block cumulative difficulty
    uint64_t blockCumulativeDifficulty;
    m_core.getBlockCumulativeDifficulty(blockIndex, blockCumulativeDifficulty);

    // get transaction hashes string
    std::string txHashesStr;
    if (block.transactionHashes.empty())
    {
      txHashesStr = "None";
    }
    else
    {
      for (const Crypto::Hash txHash : block.transactionHashes) {
        txHashesStr += "\n\t";
        txHashesStr += Common::podToHex(txHash);
      }
    }

    // get coinbase transaction hash
    Crypto::Hash coinbaseTransactionHash;
    if (!getObjectHash(block.baseTransaction, coinbaseTransactionHash))
    {
      std::cout << "Unable to get coinbase transaction hash" << std::endl;
      return false;
    }

    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << '\n' << '\n' <<
      "- Block cumulative difficulty : " << blockCumulativeDifficulty << '\n' <<
      "- Block difficulty : " << blockDifficulty << '\n' <<
      "- Block hash : " << blockHash << '\n' <<
      "- Block height : " << blockIndex + 1 << '\n' <<
      "- Block index : " << blockIndex << '\n' <<
      "- Block merkle root : " << block.merkleRoot << '\n' <<
      "- Block nonce : " << std::hex << block.nonce << std::dec << '\n' <<
      "- Block noncoinbase transactions count : " << block.transactionHashes.size()<< '\n' <<
      "- Block noncoinbase transactions hashes : " << txHashesStr << '\n' <<
      "- Block noncoinbase transactions size : " << allTransactionsSize - coinbaseTransactionSize << " bytes" << '\n' <<
      "- Block orphaned : " << std::boolalpha << isOrphaned << '\n' <<
      "- Block previous block hash : " << block.previousBlockHash << '\n' <<
      "- Block proof of work hash : " << blockProofOfWorkHash << '\n' <<
      "- Block size : " << blockSize << " bytes" << '\n' <<
      "- Block timestamp : " << std::hex << block.timestamp << std::dec << '\n' <<
      "- Block total reward : " << m_core.currency().formatAmount(totalReward) << " CASH2" << '\n' <<
      "- Block transaction fees : " << m_core.currency().formatAmount(totalFees) << " CASH2" << '\n' <<
      "- Circulating supply : " << m_core.currency().formatAmount(alreadyGeneratedCoins) << " CASH2" << '\n' <<
      "- Coinbase reward : " << m_core.currency().formatAmount(coinbaseReward) << " CASH2" << '\n' <<
      "- Coinbase transaction extra : " << Common::toHex(block.baseTransaction.extra) << '\n' <<
      "- Coinbase transaction extra size : " << block.baseTransaction.extra.size() << " bytes" << '\n' <<
      "- Coinbase transaction hash : " << coinbaseTransactionHash << '\n' <<
      "- Coinbase transaction size : " << coinbaseTransactionSize << " bytes" << '\n' <<
      "- Coinbase transaction unlock time : " << block.baseTransaction.unlockTime << '\n' <<
      "- Coinbase transaction version : " << unsigned(block.baseTransaction.version) << '\n';
  
    return true;
  }

  return false;
}

bool DaemonCommandsHandler::print_blockchain_height(const std::vector<std::string>& args)
{
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Blockchain height : " << m_core.get_current_blockchain_height() << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_circulating_supply(const std::vector<std::string>& args)
{
  std::string circulatingSupply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Circulating supply : " << circulatingSupply << " CASH2" << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_cn(const std::vector<std::string>& args)
{
  m_nodeServer.log_connections();
  return true;
}

bool DaemonCommandsHandler::print_cn_count(const std::vector<std::string>& args)
{
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Number of connections : " << m_nodeServer.get_connections_count() << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_difficulty(const std::vector<std::string>& args)
{
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Network difficulty : " << m_core.getNextBlockDifficulty() << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_grey_pl(const std::vector<std::string>& args)
{
  m_nodeServer.log_grey_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_grey_pl_count(const std::vector<std::string>& args)
{
  uint64_t greyPeerlistCount = m_nodeServer.getPeerlistManager().get_gray_peers_count();
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Grey peerlist count : " << greyPeerlistCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_incoming_cn(const std::vector<std::string>& args)
{
  m_nodeServer.log_incoming_connections();
  return true;
}

bool DaemonCommandsHandler::print_incoming_cn_count(const std::vector<std::string>& args)
{
  uint64_t totalConnections = m_nodeServer.get_connections_count();
  size_t outgoingConnectionsCount = m_nodeServer.get_outgoing_connections_count();
  size_t incoming_connections_count = totalConnections - outgoingConnectionsCount;

  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Incoming connections count : " << incoming_connections_count << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_network_height(const std::vector<std::string>& args)
{
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Network blockchain height : " << m_nodeServer.get_payload_object().getObservedHeight();
  return true;
}

bool DaemonCommandsHandler::print_outgoing_cn(const std::vector<std::string>& args)
{
  m_nodeServer.get_payload_object().log_outgoing_connections();
  return true;
}

bool DaemonCommandsHandler::print_outgoing_cn_count(const std::vector<std::string>& args)
{
  size_t outgoingConnectionsCount = m_nodeServer.get_outgoing_connections_count();

  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Outgoing connections count : " << outgoingConnectionsCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_pl(const std::vector<std::string>& args)
{
  m_nodeServer.log_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_pool(const std::vector<std::string>& args)
{
  std::string mempool = m_core.print_pool(false);

  if (mempool == "")
  {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : No tansactions in the mempool" << ENDL;
  }
  else
  {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : \n\n" << mempool << ENDL;
  }

  return true;
}

bool DaemonCommandsHandler::print_pool_sh(const std::vector<std::string>& args)
{
  std::string mempool = m_core.print_pool(true);

  if (mempool == "")
  {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : No tansactions in the mempool" << ENDL;
  }
  else
  {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : \n\n" << mempool << ENDL;
  }

  return true;
}

bool DaemonCommandsHandler::print_total_transactions_count(const std::vector<std::string>& args)
{
  uint32_t numCoinbaseTransactions = m_core.get_current_blockchain_height();
  size_t totalTransactionsCount = m_core.get_blockchain_total_transactions() - numCoinbaseTransactions;
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Total transactions count : " << totalTransactionsCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_transaction_fee(const std::vector<std::string>& args)
{
  std::string transactionFee = m_core.currency().formatAmount(m_core.getMinimalFee());
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction fee : " << transactionFee << " CASH2"  << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_tx(const std::vector<std::string>& args)
{
  if (args.empty()) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected : print_tx <transaction hash>" << std::endl;
    return true;
  }

  const std::string &str_hash = args.front();
  Crypto::Hash tx_hash;
  if (!parse_hash256(str_hash, tx_hash)) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction hash is invalid, transaction hash should be 64 characters long" << std::endl;
    return true;
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(tx_hash);
  std::list<CryptoNote::Transaction> txs;
  std::list<Crypto::Hash> missed_ids;
  m_core.getTransactions(tx_ids, txs, missed_ids, true);

  if (1 == txs.size()) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << CryptoNote::storeToJson(txs.front()) << std::endl;
  } else {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction was not found : " << str_hash << std::endl;
  }

  return true;
}

bool DaemonCommandsHandler::print_white_pl(const std::vector<std::string>& args)
{
  m_nodeServer.log_white_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_white_pl_count(const std::vector<std::string>& args)
{
  uint64_t whitePeerlistCount = m_nodeServer.getPeerlistManager().get_white_peers_count();
  m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "White peerlist count : " << whitePeerlistCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::set_log(const std::vector<std::string>& args)
{
  if (args.size() != 1) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected : set_log <log_level_number_0-4>" << ENDL;
    return true;
  }

  uint16_t l = 0;
  if (!Common::fromString(args[0], l)) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong number format, set_log <log_level_number_0-4>" << ENDL;
    return true;
  }

  ++l;

  if (l > Logging::TRACE) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong number range, set_log <log_level_number_0-4>" << ENDL;
    return true;
  }

  m_logManager.setMaxLevel(static_cast<Logging::Level>(l));
  return true;
}

bool DaemonCommandsHandler::show_hr(const std::vector<std::string>& args)
{
  if (!m_core.get_miner().is_mining())
  {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Mining is not started, you need to start mining before you can see the hash rate." << ENDL;
  } else
  {
    m_core.get_miner().do_print_hashrate(true);
  }
  return true;
}

bool DaemonCommandsHandler::start_mining(const std::vector<std::string> &args)
{
  if (!args.size()) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wallet address missiing, start_mining <addr> [threads=1]" << std::endl;
    return true;
  }

  CryptoNote::AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(args.front(), adr)) {
    m_logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Invalid Cash2 address" << std::endl;
    return true;
  }

  size_t threads_count = 1;
  if (args.size() > 1) {
    bool ok = Common::fromString(args[1], threads_count);
    threads_count = (ok && 0 < threads_count) ? threads_count : 1;
  }

  m_core.get_miner().start(adr, threads_count);
  return true;
}

bool DaemonCommandsHandler::stop_mining(const std::vector<std::string>& args)
{
  m_core.get_miner().stop();
  return true;
}

