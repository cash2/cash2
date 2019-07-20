// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DaemonCommandsHandler.h"

#include "P2p/NetNode.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Serialization/SerializationTools.h"
#include "version.h"

DaemonCommandsHandler::DaemonCommandsHandler(CryptoNote::core& core, CryptoNote::NodeServer& srv, Logging::LoggerManager& log) :
  m_core(core), m_srv(srv), logger(log, "daemon"), m_logManager(log) {

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
  m_consoleHandler.setHandler("set_log", boost::bind(&DaemonCommandsHandler::set_log, this, _1), "Change current log level\n * set_log <level>\n * <level> is a number 0-5");
  m_consoleHandler.setHandler("show_hr", boost::bind(&DaemonCommandsHandler::show_hr, this, _1), "Start showing hash rate");
  m_consoleHandler.setHandler("start_mining", boost::bind(&DaemonCommandsHandler::start_mining, this, _1), "Start mining for specified address\n * start_mining <addr> [threads=1]");
  m_consoleHandler.setHandler("stop_mining", boost::bind(&DaemonCommandsHandler::stop_mining, this, _1), "Stop mining");

}

std::string DaemonCommandsHandler::get_commands_str()
{
  std::stringstream ss;
  ss << "Daemon Commands" << ENDL << ENDL << m_consoleHandler.getUsage() << ENDL;
  return ss.str();
}

bool DaemonCommandsHandler::print_block_by_height(uint32_t height)
{
  std::list<CryptoNote::Block> blocks;
  m_core.get_blocks(height, 1, blocks);

  if (1 == blocks.size()) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << '\n' << '\n' << "Block hash : " << get_block_hash(blocks.front()) << '\n' <<
    CryptoNote::storeToJson(blocks.front()) << ENDL;
  } else {
    uint32_t current_height;
    Crypto::Hash top_id;
    m_core.get_blockchain_top(current_height, top_id);
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Block wasn't found. Current block chain height: " << current_height << ", requested: " << height << std::endl;
    return false;
  }

  return true;
}

bool DaemonCommandsHandler::print_block_by_hash(const std::string& arg)
{
  Crypto::Hash block_hash;
  if (!parse_hash256(arg, block_hash)) {
    return false;
  }

  std::list<Crypto::Hash> block_ids;
  block_ids.push_back(block_hash);
  std::list<CryptoNote::Block> blocks;
  std::list<Crypto::Hash> missed_ids;
  m_core.get_blocks(block_ids, blocks, missed_ids);

  if (1 == blocks.size())
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << CryptoNote::storeToJson(blocks.front()) << ENDL;
  } else
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "block wasn't found: " << arg << std::endl;
    return false;
  }

  return true;
}

bool DaemonCommandsHandler::exit(const std::vector<std::string>& args)
{
  m_consoleHandler.requestStop();
  m_srv.sendStopSignal();
  return true;
}

bool DaemonCommandsHandler::help(const std::vector<std::string>& args)
{
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Help" << '\n' << '\n' << get_commands_str() << std::endl;
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
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Need start height parameter" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  uint32_t startHeight = 1;
  uint32_t endHeight = 1;
  uint32_t blockchainHeight = m_core.get_current_blockchain_height();
  if (!Common::fromString(args[0], startHeight)) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong start height value" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (args.size() > 1 && !Common::fromString(args[1], endHeight)) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong end height value" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (startHeight == 0) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should be greater than 0" << ENDL;
    return false;
  }

  if (endHeight == 0) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should be greater than 0" << ENDL;
    return false;
  }

  if (startHeight > blockchainHeight) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should not be greater than " << blockchainHeight << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (endHeight > blockchainHeight) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should not be greater than " << blockchainHeight << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
    return false;
  }

  if (endHeight == 1) {
    endHeight = startHeight + 1;
  }

  if (endHeight <= startHeight) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "End height should be greater than start height" << '\n' << '\n' << "print_bc <start_height> [<end_height>]" << ENDL;
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
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected print_block <block_hash> or print_block <block_height>" << std::endl;
    return true;
  }

  const std::string &arg = args.front();
  try {
    uint32_t height = boost::lexical_cast<uint32_t>(arg);

    if (height == 0) {
      logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should be greater than 0" << ENDL;
      return false;
    }

    uint32_t blockchainHeight = m_core.get_current_blockchain_height();

    if (height > blockchainHeight) {
      logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Start height should not be greater than " << blockchainHeight << ENDL;
      return false;
    }

    print_block_by_height(height - 1);
  } catch (boost::bad_lexical_cast &) {
    print_block_by_hash(arg);
  }

  return true;
}

bool DaemonCommandsHandler::print_blockchain_height(const std::vector<std::string>& args)
{
  uint32_t height;
  Crypto::Hash blockHashIgnore;
  m_core.get_blockchain_top(height, blockHashIgnore);
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Blockchain Height : " << height << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_circulating_supply(const std::vector<std::string>& args)
{
  std::string circulatingSupply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Circulating Supply : " << circulatingSupply << " CASH2" << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_cn(const std::vector<std::string>& args)
{
  m_srv.get_payload_object().log_connections();
  return true;
}

bool DaemonCommandsHandler::print_cn_count(const std::vector<std::string>& args)
{
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Number of Connections : " << m_srv.get_connections_count() << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_difficulty(const std::vector<std::string>& args)
{
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Network Difficulty : " << m_core.getNextBlockDifficulty() << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_grey_pl(const std::vector<std::string>& args)
{
  m_srv.log_grey_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_grey_pl_count(const std::vector<std::string>& args)
{
  uint64_t greyPeerlistCount = m_srv.getPeerlistManager().get_gray_peers_count();
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Grey Peerlist Count : " << greyPeerlistCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_incoming_cn(const std::vector<std::string>& args)
{
  m_srv.get_payload_object().log_incoming_connections();
  return true;
}

bool DaemonCommandsHandler::print_incoming_cn_count(const std::vector<std::string>& args)
{
  uint64_t totalConnections = m_srv.get_connections_count();
  size_t outgoingConnectionsCount = m_srv.get_outgoing_connections_count();
  size_t incoming_connections_count = totalConnections - outgoingConnectionsCount;

  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Incoming Connections Count : " << incoming_connections_count << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_outgoing_cn(const std::vector<std::string>& args)
{
  m_srv.get_payload_object().log_outgoing_connections();
  return true;
}

bool DaemonCommandsHandler::print_outgoing_cn_count(const std::vector<std::string>& args)
{
  size_t outgoingConnectionsCount = m_srv.get_outgoing_connections_count();

  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Outgoing Connections Count : " << outgoingConnectionsCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_pl(const std::vector<std::string>& args)
{
  m_srv.log_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_pool(const std::vector<std::string>& args)
{
  std::string mempool = m_core.print_pool(false);

  if (mempool == "")
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : No tansactions in the mempool" << ENDL;
  }
  else
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : \n\n" << mempool << ENDL;
  }

  return true;
}

bool DaemonCommandsHandler::print_pool_sh(const std::vector<std::string>& args)
{
  std::string mempool = m_core.print_pool(true);

  if (mempool == "")
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : No tansactions in the mempool" << ENDL;
  }
  else
  {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "\n\nMempool : \n\n" << mempool << ENDL;
  }

  return true;
}

bool DaemonCommandsHandler::print_total_transactions_count(const std::vector<std::string>& args)
{
  uint32_t numCoinbaseTransactions = m_core.get_current_blockchain_height();
  size_t totalTransactionsCount = m_core.get_blockchain_total_transactions() - numCoinbaseTransactions;
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Total Transactions Count : " << totalTransactionsCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_transaction_fee(const std::vector<std::string>& args)
{
  std::string transactionFee = m_core.currency().formatAmount(m_core.getMinimalFee());
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction Fee : " << transactionFee << " CASH2"  << std::endl;
  return true;
}

bool DaemonCommandsHandler::print_tx(const std::vector<std::string>& args)
{
  if (args.empty()) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected : print_tx <transaction hash>" << std::endl;
    return true;
  }

  const std::string &str_hash = args.front();
  Crypto::Hash tx_hash;
  if (!parse_hash256(str_hash, tx_hash)) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction hash is invalid, transaction hash should be 64 characters long" << std::endl;
    return true;
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(tx_hash);
  std::list<CryptoNote::Transaction> txs;
  std::list<Crypto::Hash> missed_ids;
  m_core.getTransactions(tx_ids, txs, missed_ids, true);

  if (1 == txs.size()) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << CryptoNote::storeToJson(txs.front()) << std::endl;
  } else {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Transaction was not found : " << str_hash << std::endl;
  }

  return true;
}

bool DaemonCommandsHandler::print_white_pl(const std::vector<std::string>& args)
{
  m_srv.log_white_peerlist();
  return true;
}

bool DaemonCommandsHandler::print_white_pl_count(const std::vector<std::string>& args)
{
  uint64_t whitePeerlistCount = m_srv.getPeerlistManager().get_white_peers_count();
  logger(Logging::INFO, Logging::BRIGHT_CYAN) << "White Peerlist Count : " << whitePeerlistCount << std::endl;
  return true;
}

bool DaemonCommandsHandler::set_log(const std::vector<std::string>& args)
{
  if (args.size() != 1) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Expected : set_log <log_level_number_0-5>" << ENDL;
    return true;
  }

  uint16_t l = 0;
  if (!Common::fromString(args[0], l)) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong number format, set_log <log_level_number_0-5>" << ENDL;
    return true;
  }

  ++l;

  if (l > Logging::TRACE) {
    logger(Logging::INFO, Logging::BRIGHT_CYAN) << "Wrong number range, set_log <log_level_number_0-5>" << ENDL;
    return true;
  }

  m_logManager.setMaxLevel(static_cast<Logging::Level>(l));
  return true;
}

bool DaemonCommandsHandler::show_hr(const std::vector<std::string>& args)
{
  if (!m_core.get_miner().is_mining())
  {
    std::cout << "Mining is not started. You need to start mining before you can see hash rate." << ENDL;
  } else
  {
    m_core.get_miner().do_print_hashrate(true);
  }
  return true;
}

bool DaemonCommandsHandler::start_mining(const std::vector<std::string> &args)
{
  if (!args.size()) {
    std::cout << "Please, specify wallet address to mine for: start_mining <addr> [threads=1]" << std::endl;
    return true;
  }

  CryptoNote::AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(args.front(), adr)) {
    std::cout << "target account address has wrong format" << std::endl;
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

