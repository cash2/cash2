// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SimpleWallet.h"

#include <ctime>
#include <fstream>
#include <future>
#include <iomanip>
#include <thread>
#include <set>
#include <sstream>
#include <locale>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional/optional_io.hpp>

#include "Common/CommandLine.h"
#include "Common/SignalHandler.h"
#include "Common/StringTools.h"
#include "Common/PathTools.h"
#include "Common/Util.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "NodeRpcProxy/NodeRpcProxy.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"
#include "Rpc/HttpClient.h"

#include "Wallet/WalletRpcServer.h"
#include "WalletLegacy/WalletLegacy.h"
#include "Wallet/LegacyKeysImporter.h"
#include "WalletLegacy/WalletHelper.h"

#include "version.h"

#include <Logging/LoggerManager.h>

#if defined(WIN32)
#include <crtdbg.h>
#endif

using namespace CryptoNote;
using namespace Logging;
using Common::JsonValue;

namespace po = boost::program_options;

#define EXTENDED_LOGS_FILE "wallet_details.log"
#undef ERROR

namespace {

const command_line::arg_descriptor<std::string> arg_wallet_file = { "wallet-file", "Use wallet <arg>", "" };
const command_line::arg_descriptor<std::string> arg_generate_new_wallet = { "generate-new-wallet", "Generate new wallet and save it to <arg>", "" };
const command_line::arg_descriptor<std::string> arg_daemon_address = { "daemon-address", "Use daemon instance at <host>:<port>", "" };
const command_line::arg_descriptor<std::string> arg_daemon_host = { "daemon-host", "Use daemon instance at host <arg> instead of localhost", "" };
const command_line::arg_descriptor<std::string> arg_password = { "password", "Wallet password", "", true };
const command_line::arg_descriptor<uint16_t> arg_daemon_port = { "daemon-port", "Use daemon instance at port <arg> instead of 8081", 0 };
const command_line::arg_descriptor<uint32_t> arg_log_level = { "set-log", "", INFO, true };
const command_line::arg_descriptor<bool> arg_testnet = { "testnet", "Used to deploy test nets. The daemon must be launched with --testnet flag", false };
const command_line::arg_descriptor< std::vector<std::string> > arg_command = { "command", "" };


bool parseUrlAddress(const std::string& url, std::string& address, uint16_t& port) {
  auto pos = url.find("://");
  size_t addrStart = 0;

  if (pos != std::string::npos) {
    addrStart = pos + 3;
  }

  auto addrEnd = url.find(':', addrStart);

  if (addrEnd != std::string::npos) {
    auto portEnd = url.find('/', addrEnd);
    port = Common::fromString<uint16_t>(url.substr(
      addrEnd + 1, portEnd == std::string::npos ? std::string::npos : portEnd - addrEnd - 1));
  } else {
    addrEnd = url.find('/');
    port = 80;
  }

  address = url.substr(addrStart, addrEnd - addrStart);
  return true;
}


inline std::string interpret_rpc_response(bool ok, const std::string& status) {
  std::string err;
  if (ok) {
    if (status == CORE_RPC_STATUS_BUSY) {
      err = "daemon is busy. Please try later";
    } else if (status != CORE_RPC_STATUS_OK) {
      err = status;
    }
  } else {
    err = "possible lost connection to daemon";
  }
  return err;
}

template <typename IterT, typename ValueT = typename IterT::value_type>
class ArgumentReader {
public:

  ArgumentReader(IterT begin, IterT end) :
    m_begin(begin), m_end(end), m_cur(begin) {
  }

  bool eof() const {
    return m_cur == m_end;
  }

  ValueT next() {
    if (eof()) {
      throw std::runtime_error("unexpected end of arguments");
    }

    return *m_cur++;
  }

private:

  IterT m_cur;
  IterT m_begin;
  IterT m_end;
};

uint64_t getMinimalFee(const CryptoNote::NodeRpcProxy& node) {
  if (node.getLastLocalBlockHeight() < CryptoNote::parameters::SOFT_FORK_HEIGHT_1)
  {
    return CryptoNote::parameters::MINIMUM_FEE_1;
  }
  
  return CryptoNote::parameters::MINIMUM_FEE_2;
}

struct TransferCommand {
  const CryptoNote::Currency& m_currency;
  const CryptoNote::NodeRpcProxy& m_node;
  size_t fake_outs_count;
  std::vector<CryptoNote::WalletLegacyTransfer> dsts;
  std::vector<uint8_t> extra;
  uint64_t fee;

  TransferCommand(const CryptoNote::Currency& currency, const CryptoNote::NodeRpcProxy& node) :
    m_currency(currency), m_node(node), fake_outs_count(0), fee(getMinimalFee(m_node)) {
  }

  bool parseArguments(LoggerRef& logger, const std::vector<std::string> &args) {

    ArgumentReader<std::vector<std::string>::const_iterator> ar(args.begin(), args.end());

    try {

      auto mixin_str = ar.next();

      if (!Common::fromString(mixin_str, fake_outs_count)) {
        logger(ERROR, BRIGHT_RED) << "mixin_count should be non-negative integer, got " << mixin_str;
        return false;
      }

      if (fake_outs_count > m_currency.maxMixin()) {
          logger(ERROR, BRIGHT_RED) << "Mixin must be less than " << m_currency.maxMixin() + 1;
          return false;
      }

      while (!ar.eof()) {

        auto arg = ar.next();

        if (arg.size() && arg[0] == '-') {

          const auto& value = ar.next();

          if (arg == "-p") {
            if (!createTxExtraWithPaymentId(value, extra)) {
              logger(ERROR, BRIGHT_RED) << "payment ID has invalid format: \"" << value << "\", expected 64-character string";
              return false;
            }
          } else if (arg == "-f") {
            bool ok = m_currency.parseAmount(value, fee);
            if (!ok) {
              logger(ERROR, BRIGHT_RED) << "Fee value is invalid: " << value;
              return false;
            }

            uint64_t minimalFee = getMinimalFee(m_node);

            if (fee < minimalFee) {
              logger(ERROR, BRIGHT_RED) << "Your fee of " << fee << " is too low. Required fee = " << minimalFee;
              return false;
            }
          }
        } else {
          WalletLegacyTransfer destination;
          CryptoNote::TransactionDestinationEntry de;

          if (!m_currency.parseAccountAddressString(arg, de.addr)) {
            Crypto::Hash paymentId;
            if (CryptoNote::parsePaymentId(arg, paymentId)) {
              logger(ERROR, BRIGHT_RED) << "Invalid payment ID usage. Please, use -p <payment_id>. See help for details.";
            } else {
              logger(ERROR, BRIGHT_RED) << "Wrong address: " << arg;
            }

            return false;
          }

          auto value = ar.next();
          bool ok = m_currency.parseAmount(value, de.amount);
          if (!ok || 0 == de.amount) {
            logger(ERROR, BRIGHT_RED) << "amount is wrong: " << arg << ' ' << value <<
              ", expected number from 0 to " << m_currency.formatAmount(std::numeric_limits<uint64_t>::max());
            return false;
          }
          destination.address = arg;
          destination.amount = de.amount;

          dsts.push_back(destination);
        }
      }

      if (dsts.empty()) {
        logger(ERROR, BRIGHT_RED) << "At least one destination address is required";
        return false;
      }
    } catch (const std::exception& e) {
      logger(ERROR, BRIGHT_RED) << e.what();
      return false;
    }

    return true;
  }
};

JsonValue buildLoggerConfiguration(Level level, const std::string& logfile) {
  JsonValue loggerConfiguration(JsonValue::OBJECT);
  loggerConfiguration.insert("globalLevel", static_cast<int64_t>(level));

  JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", JsonValue::ARRAY);

  JsonValue& consoleLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  consoleLogger.insert("type", "console");
  consoleLogger.insert("level", static_cast<int64_t>(TRACE));
  consoleLogger.insert("pattern", "");

  JsonValue& fileLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  fileLogger.insert("type", "file");
  fileLogger.insert("filename", logfile);
  fileLogger.insert("level", static_cast<int64_t>(TRACE));

  return loggerConfiguration;
}

std::error_code initAndLoadWallet(IWalletLegacy& wallet, std::istream& walletFile, const std::string& password) {
  WalletHelper::InitWalletResultObserver initObserver;
  std::future<std::error_code> f_initError = initObserver.initResult.get_future();

  WalletHelper::IWalletRemoveObserverGuard removeGuard(wallet, initObserver);
  wallet.initAndLoad(walletFile, password);
  auto initError = f_initError.get();

  return initError;
}

std::string tryToOpenWalletOrLoadKeysOrThrow(LoggerRef& logger, std::unique_ptr<IWalletLegacy>& wallet, const std::string& walletFile, const std::string& password) {
  std::string keys_file, walletFileName;
  WalletHelper::prepareFileNames(walletFile, keys_file, walletFileName);

  boost::system::error_code ignore;
  bool keysExists = boost::filesystem::exists(keys_file, ignore);
  bool walletExists = boost::filesystem::exists(walletFileName, ignore);
  if (!walletExists && !keysExists && boost::filesystem::exists(walletFile, ignore)) {
    boost::system::error_code renameEc;
    boost::filesystem::rename(walletFile, walletFileName, renameEc);
    if (renameEc) {
      throw std::runtime_error("failed to rename file '" + walletFile + "' to '" + walletFileName + "': " + renameEc.message());
    }

    walletExists = true;
  }

  if (walletExists) {
    logger(INFO) << "\nLoading wallet...\n";
    std::ifstream walletFile;
    walletFile.open(walletFileName, std::ios_base::binary | std::ios_base::in);
    if (walletFile.fail()) {
      throw std::runtime_error("error opening wallet file '" + walletFileName + "'");
    }

    auto initError = initAndLoadWallet(*wallet, walletFile, password);

    walletFile.close();
    if (initError) { //bad password, or legacy format
      if (keysExists) {
        std::stringstream ss;
        CryptoNote::importLegacyKeys(keys_file, password, ss);
        boost::filesystem::rename(keys_file, keys_file + ".back");
        boost::filesystem::rename(walletFileName, walletFileName + ".back");

        initError = initAndLoadWallet(*wallet, ss, password);
        if (initError) {
          throw std::runtime_error("failed to load wallet: " + initError.message());
        }

        logger(INFO) << "Storing wallet...";

        try {
          CryptoNote::WalletHelper::storeWallet(*wallet, walletFileName);
        } catch (std::exception& e) {
          logger(ERROR, BRIGHT_RED) << "Failed to store wallet: " << e.what();
          throw std::runtime_error("error saving wallet file '" + walletFileName + "'");
        }

        logger(INFO, BRIGHT_GREEN) << "Stored ok";
        return walletFileName;
      } else { // no keys, wallet error loading
        throw std::runtime_error("can't load wallet file '" + walletFileName + "', check password");
      }
    } else { //new wallet ok 
      return walletFileName;
    }
  } else if (keysExists) { //wallet not exists but keys presented
    std::stringstream ss;
    CryptoNote::importLegacyKeys(keys_file, password, ss);
    boost::filesystem::rename(keys_file, keys_file + ".back");

    WalletHelper::InitWalletResultObserver initObserver;
    std::future<std::error_code> f_initError = initObserver.initResult.get_future();

    WalletHelper::IWalletRemoveObserverGuard removeGuard(*wallet, initObserver);
    wallet->initAndLoad(ss, password);
    auto initError = f_initError.get();

    removeGuard.removeObserver();
    if (initError) {
      throw std::runtime_error("failed to load wallet: " + initError.message());
    }

    logger(INFO) << "Storing wallet...";

    try {
      CryptoNote::WalletHelper::storeWallet(*wallet, walletFileName);
    } catch(std::exception& e) {
      logger(ERROR, BRIGHT_RED) << "Failed to store wallet: " << e.what();
      throw std::runtime_error("error saving wallet file '" + walletFileName + "'");
    }

    logger(INFO, BRIGHT_GREEN) << "Stored ok";
    return walletFileName;
  } else { //no wallet no keys
    throw std::runtime_error("wallet file '" + walletFileName + "' is not found");
  }
}

std::string makeCenteredString(size_t width, const std::string& text) {
  if (text.size() >= width) {
    return text;
  }

  size_t offset = (width - text.size() + 1) / 2;
  return std::string(offset, ' ') + text + std::string(width - text.size() - offset, ' ');
}

std::string addCommasToBlockHeight(const uint32_t& height)
{
  std::stringstream ss;
  ss.imbue(std::locale(""));
  ss << std::fixed << height;
  return ss.str();
}

const size_t TIMESTAMP_MAX_WIDTH = 36;
const size_t HASH_MAX_WIDTH = 64;
const size_t TOTAL_AMOUNT_MAX_WIDTH = 20;
const size_t FEE_MAX_WIDTH = 14;
const size_t BLOCK_MAX_WIDTH = 7;
const size_t UNLOCK_TIME_MAX_WIDTH = 11;

void printTransaction(LoggerRef& logger, const WalletLegacyTransaction& txInfo, IWalletLegacy& wallet, const Currency& currency) {
  std::vector<uint8_t> extraVec = Common::asBinaryArray(txInfo.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(txInfo.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  std::string rowColor = txInfo.totalAmount < 0 ? RED : GREEN;

  if (txInfo.totalAmount >= 0)
  {

    // Received money into your wallet

    logger(INFO, rowColor)
      << "Received : " << currency.formatAmount(txInfo.totalAmount) << "\n"
      << "Timestamp : " << timeString << "\n"
      << "Transaction ID : " << Common::podToHex(txInfo.hash) << "\n"
      << "Fee : " << currency.formatAmount(txInfo.fee) << "\n"
      << "Block Height : " << txInfo.blockHeight << "\n\n";
  }
  else
  {

    // Sent money out of your wallet

    Crypto::SecretKey transactionSecretKey = wallet.getTxKey(txInfo.hash);

    logger(INFO, rowColor)
      << "Sent\n"
      << "Timestamp : " << timeString << "\n"
      << "Transaction ID : " << Common::podToHex(txInfo.hash) << "\n"
      << "Transaction Secret Key : " << Common::podToHex(transactionSecretKey) << "\n"
      << "Fee : " << currency.formatAmount(txInfo.fee) << "\n"
      << "Block Height : " << txInfo.blockHeight << "\n";

    if (txInfo.transferCount > 0) {
      for (TransferId id = txInfo.firstTransferId; id < txInfo.firstTransferId + txInfo.transferCount; ++id) {
        WalletLegacyTransfer tr;
        wallet.getTransfer(id, tr);
        logger(INFO, rowColor)
        << "Receiver's Address : " << tr.address << "\n"
        << "Amount :  " << currency.formatAmount(tr.amount) << "\n\n";
      }
    }
  }

  if (!paymentIdStr.empty()) {
    logger(INFO, rowColor) << "Payment ID : " << paymentIdStr;
  }

  logger(INFO, rowColor) << " "; //just to make logger print one endline
}

std::string printIncomingTransaction(LoggerRef& logger, const WalletLegacyTransaction& txInfo, IWalletLegacy& wallet, const Currency& currency) {
  std::vector<uint8_t> extraVec = Common::asBinaryArray(txInfo.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(txInfo.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  std::stringstream ss;

  if (txInfo.totalAmount >= 0)
  {
    // Received money into your wallet
    ss <<
      "Received : " << currency.formatAmount(txInfo.totalAmount) << " CASH2" << std::endl <<
      "Timestamp : " << timeString << "\n" <<
      "Transaction Hash : " << Common::podToHex(txInfo.hash) << std::endl <<
      "Transaction Fee : " << currency.formatAmount(txInfo.fee) << " CASH2" << std::endl <<
      "Block Height : " << addCommasToBlockHeight(txInfo.blockHeight) << std::endl;

    if (!paymentIdStr.empty()) {
      ss << "Payment ID : " << paymentIdStr << std::endl;
    }

    ss << std::endl;
  }

  logger(INFO, GREEN) << ss.str();
}

void printOutgoingTransaction(LoggerRef& logger, const WalletLegacyTransaction& txInfo, IWalletLegacy& wallet, const Currency& currency) {
  std::vector<uint8_t> extraVec = Common::asBinaryArray(txInfo.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(txInfo.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  // Sent money out of your wallet

  Crypto::SecretKey transactionSecretKey = wallet.getTxKey(txInfo.hash);

  std::stringstream ss;

  ss <<
    "Sent" << std::endl <<
    "Timestamp : " << timeString << std::endl <<
    "Transaction Hash : " << Common::podToHex(txInfo.hash) << std::endl <<
    "Transaction Fee : " << currency.formatAmount(txInfo.fee) << " CASH2" << std::endl <<
    "Block Height : " << addCommasToBlockHeight(txInfo.blockHeight) << std::endl;

  if (transactionSecretKey != NULL_SECRET_KEY)
  {
    ss << "Transaction Private Key : " << Common::podToHex(transactionSecretKey) << std::endl;
  }

  if (txInfo.transferCount > 0) {
    for (TransferId id = txInfo.firstTransferId; id < txInfo.firstTransferId + txInfo.transferCount; ++id) {
      WalletLegacyTransfer tr;
      wallet.getTransfer(id, tr);
      ss <<
      "Receiver's Address : " << tr.address << std::endl <<
      "Amount :  " << currency.formatAmount(tr.amount) << " CASH2" << std::endl;
    }
  }

  if (!paymentIdStr.empty()) {
    ss << "Payment ID : " << paymentIdStr;
  }

  ss << std::endl;

  logger(INFO, RED) << ss.str();
}

std::string prepareWalletAddressFilename(const std::string& walletBaseName) {
  return walletBaseName + ".address";
}

bool writeAddressFile(const std::string& addressFilename, const std::string& address) {
  std::ofstream addressFile(addressFilename, std::ios::out | std::ios::trunc | std::ios::binary);
  if (!addressFile.good()) {
    return false;
  }

  addressFile << address;

  return true;
}

}

std::string simple_wallet::get_commands_str() {
  std::stringstream ss;
  ss << ENDL << "SimpleWallet Commands" << ENDL << ENDL << m_consoleHandler.getUsage() << ENDL;
  return ss.str();
}

bool simple_wallet::help(const std::vector<std::string> &args/* = std::vector<std::string>()*/) {
  logger(INFO, BRIGHT_CYAN) << get_commands_str();
  return true;
}

bool simple_wallet::exit(const std::vector<std::string> &args) {
  m_consoleHandler.requestStop();
  return true;
}

simple_wallet::simple_wallet(System::Dispatcher& dispatcher, const CryptoNote::Currency& currency, Logging::LoggerManager& log) :
  m_dispatcher(dispatcher),
  m_daemon_port(0), 
  m_currency(currency), 
  logManager(log),
  logger(log, "simplewallet"),
  m_refresh_progress_reporter(*this), 
  m_initResultPromise(nullptr),
  m_walletSynchronized(false) {
  m_consoleHandler.setHandler("address", boost::bind(&simple_wallet::print_address, this, _1), "Show wallet address");
  m_consoleHandler.setHandler("all_transactions", boost::bind(&simple_wallet::list_transactions, this, _1), "Show all transactions");
  m_consoleHandler.setHandler("balance", boost::bind(&simple_wallet::show_balance, this, _1), "Show wallet balance");
  m_consoleHandler.setHandler("exit", boost::bind(&simple_wallet::exit, this, _1), "Close wallet");
  m_consoleHandler.setHandler("get_transaction_private_key", boost::bind(&simple_wallet::get_tx_key, this, _1), "Get the transaction private key of a transaction\n * get_transaction_private_key <transaction_hash>");
  m_consoleHandler.setHandler("height", boost::bind(&simple_wallet::show_blockchain_height, this, _1), "Show blockchain height");
  m_consoleHandler.setHandler("help", boost::bind(&simple_wallet::help, this, _1), "Show this help");
  m_consoleHandler.setHandler("incoming_transactions", boost::bind(&simple_wallet::show_incoming_transactions, this, _1), "Show incoming transaction");
  m_consoleHandler.setHandler("outgoing_transactions", boost::bind(&simple_wallet::show_outgoing_transactions, this, _1), "Show outgoing transactions");
  m_consoleHandler.setHandler("payments", boost::bind(&simple_wallet::show_payments, this, _1), "Shows a tranaction given the transaction's payment ID\n * payments <payment_id_1> [<payment_id_2> ... <payment_id_N>]");
  m_consoleHandler.setHandler("reset", boost::bind(&simple_wallet::reset, this, _1), "Discard cache data and start synchronizing from the start");
  m_consoleHandler.setHandler("save", boost::bind(&simple_wallet::save, this, _1), "Save wallet synchronized data");
  m_consoleHandler.setHandler("set_log", boost::bind(&simple_wallet::set_log, this, _1), "Change log level\n * set_log <level>\n * <level> is a number 0-4");
  m_consoleHandler.setHandler("spend_private_key", boost::bind(&simple_wallet::print_spend_secret_key, this, _1), "Show wallet spend private key");
  m_consoleHandler.setHandler("start_mining", boost::bind(&simple_wallet::start_mining, this, _1), "Start mining\n * start_mining [<number_of_threads>]");
  m_consoleHandler.setHandler("stop_mining", boost::bind(&simple_wallet::stop_mining, this, _1), "Stop mining");
  m_consoleHandler.setHandler("transfer", boost::bind(&simple_wallet::transfer, this, _1), "Transfer amount to address with privicy level\n * transfer <privacy_level> <adreess> <amount> [-p payment_id] [-f fee]\n * <privacy_level> can be 0, 1, 2, or 3 with 3 being the most private");
  m_consoleHandler.setHandler("view_private_key", boost::bind(&simple_wallet::print_view_secret_key, this, _1), "Show wallet view private key");
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_log(const std::vector<std::string> &args) {
  if (args.size() != 1) {
    fail_msg_writer() << "use: set_log <log_level_number_0-4>";
    return true;
  }

  uint16_t l = 0;
  if (!Common::fromString(args[0], l)) {
    fail_msg_writer() << "wrong number format, use: set_log <log_level_number_0-4>";
    return true;
  }
 
  if (l > Logging::TRACE) {
    fail_msg_writer() << "wrong number range, use: set_log <log_level_number_0-4>";
    return true;
  }

  logManager.setMaxLevel(static_cast<Logging::Level>(l));
  return true;
}
//----------------------------------------------------------------------------------------------------

bool simple_wallet::get_tx_key(const std::vector<std::string> &args) {
	if (args.size() != 1)
	{
		fail_msg_writer() << "use: get_tx_key <txid>";
		return true;
	}
	const std::string &str_hash = args[0];
	Crypto::Hash txid;
	if (!parse_hash256(str_hash, txid)) {
		fail_msg_writer() << "Failed to parse txid";
		return true;
	}

	Crypto::SecretKey tx_key = m_wallet->getTxKey(txid);
	if (tx_key != NULL_SECRET_KEY) {
		success_msg_writer() << "transaction secret key : " << Common::podToHex(tx_key);
		return true;
	}
	else {
		fail_msg_writer() << "No transaction key found for this transaction";
		return true;
	}
}

bool simple_wallet::init(const boost::program_options::variables_map& vm) {
  handle_command_line(vm);

  if (!m_daemon_address.empty() && (!m_daemon_host.empty() || 0 != m_daemon_port)) {
    fail_msg_writer() << "you can't specify daemon host or port several times";
    return false;
  }

  char c;
  if (m_generate_new.empty() && m_wallet_file_arg.empty()) {
    std::cout << "What would you like to do?\n  [1] Open existing wallet\n  [2] Create new wallet\n  [3] Restore wallet from private keys\n  [4] Exit\n";
    do {
      std::string answer;
      std::getline(std::cin, answer);
      c = answer[0];
      if (!(c == '1' || c == '2' || c == '3' || c == '4')) {
        std::cout << "Unknown command: " << c <<std::endl;
      } else {
        break;
      }
    } while (true);

    if (c == '4') {
      return false;
    }

    if (c == '3')
    {
      std::string spendPrivateKeyInput;
      do
      {
        std::cout << "Spend private key: ";
        std::getline(std::cin, spendPrivateKeyInput);
        boost::algorithm::trim(spendPrivateKeyInput);
      } while (spendPrivateKeyInput.empty());

      m_spend_secret_key = spendPrivateKeyInput;

      std::string viewPrivateKeyInput;
      do
      {
        std::cout << "View private key: ";
        std::getline(std::cin, viewPrivateKeyInput);
        boost::algorithm::trim(viewPrivateKeyInput);
      } while (viewPrivateKeyInput.empty());

      m_view_secret_key = viewPrivateKeyInput;
    }

    std::string userInput;
    do {
      std::cout << "Wallet name: ";
      std::getline(std::cin, userInput);
      boost::algorithm::trim(userInput);
    } while (userInput.empty());

    if (c == '1')
    {
      m_wallet_file_arg = userInput;
    }
    else
    {
      m_generate_new = userInput;
    }
  }

  if (!m_generate_new.empty() && !m_wallet_file_arg.empty()) {
    fail_msg_writer() << "you can't specify 'generate-new-wallet' and 'wallet-file' arguments simultaneously";
    return false;
  }

  std::string walletFileName;
  if (!m_generate_new.empty()) {
    std::string ignoredString;
    WalletHelper::prepareFileNames(m_generate_new, ignoredString, walletFileName);
    boost::system::error_code ignore;
    if (boost::filesystem::exists(walletFileName, ignore)) {
      fail_msg_writer() << walletFileName << " already exists";
      return false;
    }
  }

  if (m_daemon_host.empty())
    m_daemon_host = "localhost";
  if (!m_daemon_port)
    m_daemon_port = RPC_DEFAULT_PORT;
  
  if (!m_daemon_address.empty()) {
    if (!parseUrlAddress(m_daemon_address, m_daemon_host, m_daemon_port)) {
      fail_msg_writer() << "failed to parse daemon address: " << m_daemon_address;
      return false;
    }
  } else {
    m_daemon_address = std::string("http://") + m_daemon_host + ":" + std::to_string(m_daemon_port);
  }

  Tools::PasswordContainer pwd_container;
  if (command_line::has_arg(vm, arg_password)) {
    pwd_container.password(command_line::get_arg(vm, arg_password));
  }
  else if (!pwd_container.read_password())
  {
    fail_msg_writer() << "failed to read password";
    return false;
  }

  // ask to confirm password when generating a new wallet or restoring wallet
  if (c == '2' || c == '3' || c == '4')
  {
    if (!pwd_container.read_confirm_password())
    {
      fail_msg_writer() << "failed to read confirm password";
      return false;
    }
    else if (!pwd_container.passwords_match())
    {
      fail_msg_writer() << "passwords do not match";
      return false;
    }
  }

  this->m_node.reset(new NodeRpcProxy(m_daemon_host, m_daemon_port));

  std::promise<std::error_code> errorPromise;
  std::future<std::error_code> f_error = errorPromise.get_future();
  auto callback = [&errorPromise](std::error_code e) {errorPromise.set_value(e); };

  m_node->addObserver(static_cast<INodeRpcProxyObserver*>(this));
  m_node->init(callback);
  auto error = f_error.get();
  if (error) {
    fail_msg_writer() << "failed to init NodeRPCProxy: " << error.message();
    return false;
  }

  if (!m_generate_new.empty())
  {
    std::string walletAddressFile = prepareWalletAddressFilename(m_generate_new);
    boost::system::error_code ignore;
    if (boost::filesystem::exists(walletAddressFile, ignore)) {
      logger(ERROR, BRIGHT_RED) << "Address file already exists: " + walletAddressFile;
      return false;
    }

    if (m_spend_secret_key.empty() && m_view_secret_key.empty())
    {
      // generate new wallet
      if (!new_wallet(walletFileName, pwd_container.password())) {
        logger(ERROR, BRIGHT_RED) << "Wallet creation failed";
        return false;
      }

      if (!writeAddressFile(walletAddressFile, m_wallet->getAddress())) {
        logger(WARNING, BRIGHT_RED) << "Couldn't write wallet address file: " + walletAddressFile;
      }
    }
    else if (!m_spend_secret_key.empty() && !m_view_secret_key.empty())
    {
      // restore wallet from private keys
      if (!restore_wallet_from_private_keys(walletFileName, pwd_container.password()))
      {
        logger(ERROR, BRIGHT_RED) << "Wallet restore failed";
        return false;
      }

      if (!writeAddressFile(walletAddressFile, m_wallet->getAddress()))
      {
        logger(WARNING, BRIGHT_RED) << "Couldn't write wallet address file: " + walletAddressFile;
      }
    }
    else
    {
      logger(ERROR, BRIGHT_RED) << "Wallet creation failed";
      return false;
    }
  }
  else {
    // open existing wallet
    m_wallet.reset(new WalletLegacy(m_currency, *m_node));

    try {
      m_wallet_file = tryToOpenWalletOrLoadKeysOrThrow(logger, m_wallet, m_wallet_file_arg, pwd_container.password());
    } catch (const std::exception& e) {
      fail_msg_writer() << "failed to load wallet: " << e.what();
      return false;
    }

    m_wallet->addObserver(this);
    m_node->addObserver(static_cast<INodeObserver*>(this));

    logger(INFO, BRIGHT_WHITE) << "Wallet address: " << m_wallet->getAddress() << '\n';

    success_msg_writer() <<
      "**********************************************************************\n" <<
      "Use \"help\" command to see the list of available commands.\n" <<
      "**********************************************************************";
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::deinit() {
  m_wallet->removeObserver(this);
  m_node->removeObserver(static_cast<INodeObserver*>(this));
  m_node->removeObserver(static_cast<INodeRpcProxyObserver*>(this));

  if (!m_wallet.get())
    return true;

  return close_wallet();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::handle_command_line(const boost::program_options::variables_map& vm) {
  m_wallet_file_arg = command_line::get_arg(vm, arg_wallet_file);
  m_generate_new = command_line::get_arg(vm, arg_generate_new_wallet);
  m_daemon_address = command_line::get_arg(vm, arg_daemon_address);
  m_daemon_host = command_line::get_arg(vm, arg_daemon_host);
  m_daemon_port = command_line::get_arg(vm, arg_daemon_port);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::new_wallet(const std::string &wallet_file, const std::string& password) {
  m_wallet_file = wallet_file;

  m_wallet.reset(new WalletLegacy(m_currency, *m_node.get()));
  m_node->addObserver(static_cast<INodeObserver*>(this));
  m_wallet->addObserver(this);
  try {
    m_initResultPromise.reset(new std::promise<std::error_code>());
    std::future<std::error_code> f_initError = m_initResultPromise->get_future();
    m_wallet->initAndGenerate(password);
    auto initError = f_initError.get();
    m_initResultPromise.reset(nullptr);
    if (initError) {
      fail_msg_writer() << "failed to generate new wallet: " << initError.message();
      return false;
    }

    try {
      CryptoNote::WalletHelper::storeWallet(*m_wallet, m_wallet_file);
    } catch (std::exception& e) {
      fail_msg_writer() << "failed to save new wallet: " << e.what();
      throw;
    }

    AccountKeys keys;
    m_wallet->getAccountKeys(keys);

    logger(INFO, BRIGHT_WHITE) << "Wallet Address : " << m_wallet->getAddress() << std::endl;
    logger(INFO, BRIGHT_WHITE) << "\nSpend Private Key : " << Common::podToHex(keys.spendSecretKey) << std::endl;
    logger(INFO, BRIGHT_WHITE) << "\nView Private Key : " << Common::podToHex(keys.viewSecretKey) << std::endl;
    logger(INFO, BRIGHT_WHITE) << "\nPlease keep both private keys safe\n" << std::endl;
  }
  catch (const std::exception& e) {
    fail_msg_writer() << "failed to generate new wallet: " << e.what();
    return false;
  }

  success_msg_writer() <<
    "**********************************************************************\n" <<
    "Your wallet has been generated.\n" <<
    "Use \"help\" command to see the list of available commands.\n" <<
    "Always use \"exit\" command when closing simplewallet to save\n" <<
    "current session's state. Otherwise, you will possibly need to synchronize \n" <<
    "your wallet again. Your wallet key is NOT under risk anyway.\n" <<
    "**********************************************************************";
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::restore_wallet_from_private_keys(const std::string &wallet_file, const std::string& password) {
  m_wallet_file = wallet_file;

  m_wallet.reset(new WalletLegacy(m_currency, *m_node.get()));
  m_node->addObserver(static_cast<INodeObserver*>(this));
  m_wallet->addObserver(this);

  if (!std::all_of(m_spend_secret_key.begin(), m_spend_secret_key.end(), ::isxdigit) || !std::all_of(m_view_secret_key.begin(), m_view_secret_key.end(), ::isxdigit))
  {
    return false;
  }

  if(m_spend_secret_key.length() != 64 || m_view_secret_key.length() != 64)
  {
    return false;
  }

  // convert spendSecretKeyStr to Crypto::SecretKey
  Crypto::SecretKey spendSecretKey;
  Common::podFromHex(m_spend_secret_key, spendSecretKey);

  // convert viewSecretKeyStr to Crypto::SecretKey
  Crypto::SecretKey viewSecretKey;
  Common::podFromHex(m_view_secret_key, viewSecretKey);

  // fill in temporary AccountKeys with the spend secret key
  AccountKeys tempAccountKeys;
  tempAccountKeys.spendSecretKey = spendSecretKey;
  tempAccountKeys.viewSecretKey = viewSecretKey;

  Crypto::PublicKey spendPublicKey;
  if(!Crypto::secret_key_to_public_key(spendSecretKey, spendPublicKey))
  {
    return false;
  }

  Crypto::PublicKey viewPublicKey;
  if(!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey))
  {
    return false;
  }

  tempAccountKeys.address.spendPublicKey = spendPublicKey;
  tempAccountKeys.address.viewPublicKey = viewPublicKey;

  try {
    m_initResultPromise.reset(new std::promise<std::error_code>());
    std::future<std::error_code> f_initError = m_initResultPromise->get_future();
    m_wallet->initWithKeys(tempAccountKeys, password);
    auto initError = f_initError.get();
    m_initResultPromise.reset(nullptr);
    if (initError) {
      fail_msg_writer() << "failed to restore wallet: " << initError.message();
      return false;
    }

    try {
      CryptoNote::WalletHelper::storeWallet(*m_wallet, m_wallet_file);
    } catch (std::exception& e) {
      fail_msg_writer() << "failed to save restored wallet: " << e.what();
      throw;
    }

    AccountKeys keys;
    m_wallet->getAccountKeys(keys);

    logger(INFO, BRIGHT_WHITE) << "Wallet Address\n" << m_wallet->getAddress() << std::endl;
    logger(INFO, BRIGHT_WHITE) << "\nView Private Key\n" << Common::podToHex(keys.viewSecretKey) << std::endl;
    logger(INFO, BRIGHT_WHITE) << "\nSpend Private Key\n" << Common::podToHex(keys.spendSecretKey) << std::endl;
  }
  catch (const std::exception& e) {
    fail_msg_writer() << "failed to generate new wallet: " << e.what();
    return false;
  }

  success_msg_writer() <<
    "**********************************************************************\n" <<
    "Your wallet has been generated.\n" <<
    "Use \"help\" command to see the list of available commands.\n" <<
    "Always use \"exit\" command when closing simplewallet to save\n" <<
    "current session's state. Otherwise, you will possibly need to synchronize \n" <<
    "your wallet again. Your wallet key is NOT under risk anyway.\n" <<
    "**********************************************************************";
  return true;
}
//----------------------------------------------------------------------------------------------------

bool simple_wallet::close_wallet()
{
  try {
    CryptoNote::WalletHelper::storeWallet(*m_wallet, m_wallet_file);
  } catch (const std::exception& e) {
    fail_msg_writer() << e.what();
    return false;
  }

  m_wallet->removeObserver(this);
  m_wallet->shutdown();

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::save(const std::vector<std::string> &args)
{
  try {
    CryptoNote::WalletHelper::storeWallet(*m_wallet, m_wallet_file);
    success_msg_writer() << "Wallet data saved";
  } catch (const std::exception& e) {
    fail_msg_writer() << e.what();
  }

  return true;
}

bool simple_wallet::reset(const std::vector<std::string> &args) {
  {
    std::unique_lock<std::mutex> lock(m_walletSynchronizedMutex);
    m_walletSynchronized = false;
  }

  m_wallet->reset();
  success_msg_writer(true) << "Reset completed successfully.";

  std::unique_lock<std::mutex> lock(m_walletSynchronizedMutex);
  while (!m_walletSynchronized) {
    m_walletSynchronizedCV.wait(lock);
  }

  std::cout << std::endl;

  return true;
}

bool simple_wallet::start_mining(const std::vector<std::string>& args) {
  COMMAND_RPC_START_MINING::request req;
  req.miner_address = m_wallet->getAddress();

  bool ok = true;
  size_t max_mining_threads_count = (std::max)(std::thread::hardware_concurrency(), static_cast<unsigned>(2));
  if (0 == args.size()) {
    req.threads_count = 1;
  } else if (1 == args.size()) {
    uint16_t num = 1;
    ok = Common::fromString(args[0], num);
    ok = ok && (1 <= num && num <= max_mining_threads_count);
    req.threads_count = num;
  } else {
    ok = false;
  }

  if (!ok) {
    fail_msg_writer() << "invalid arguments. Please use start_mining [<number_of_threads>], " <<
      "<number_of_threads> should be from 1 to " << max_mining_threads_count;
    return true;
  }


  COMMAND_RPC_START_MINING::response res;

  try {
    HttpClient httpClient(m_dispatcher, m_daemon_host, m_daemon_port);

    invokeJsonCommand(httpClient, "/start_mining", req, res);

    std::string err = interpret_rpc_response(true, res.status);
    if (err.empty())
      success_msg_writer() << "Mining started in daemon";
    else
      fail_msg_writer() << "mining has NOT been started: " << err;

  } catch (const ConnectException&) {
    printConnectionError();
  } catch (const std::exception& e) {
    fail_msg_writer() << "Failed to invoke rpc method: " << e.what();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::stop_mining(const std::vector<std::string>& args)
{
  COMMAND_RPC_STOP_MINING::request req;
  COMMAND_RPC_STOP_MINING::response res;

  try {
    HttpClient httpClient(m_dispatcher, m_daemon_host, m_daemon_port);

    invokeJsonCommand(httpClient, "/stop_mining", req, res);
    std::string err = interpret_rpc_response(true, res.status);
    if (err.empty())
      success_msg_writer() << "Mining stopped in daemon";
    else
      fail_msg_writer() << "mining has NOT been stopped: " << err;
  } catch (const ConnectException&) {
    printConnectionError();
  } catch (const std::exception& e) {
    fail_msg_writer() << "Failed to invoke rpc method: " << e.what();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::initCompleted(std::error_code result) {
  if (m_initResultPromise.get() != nullptr) {
    m_initResultPromise->set_value(result);
  }
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::connectionStatusUpdated(bool connected) {
  if (connected) {
    logger(INFO, GREEN) << "Wallet connected to daemon.";
  } else {
    printConnectionError();
  }
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::externalTransactionCreated(CryptoNote::TransactionId transactionId)  {
  WalletLegacyTransaction txInfo;
  m_wallet->getTransaction(transactionId, txInfo);
  
  std::stringstream logPrefix;
  if (txInfo.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    logPrefix << "Unconfirmed";
  } else {
    logPrefix << "Height " << txInfo.blockHeight << ',';
  }

  if (txInfo.totalAmount >= 0) {
    logger(INFO, GREEN) <<
      logPrefix.str() << " transaction " << Common::podToHex(txInfo.hash) <<
      ", received " << m_currency.formatAmount(txInfo.totalAmount);
  } else {
    logger(INFO, MAGENTA) <<
      logPrefix.str() << " transaction " << Common::podToHex(txInfo.hash) <<
      ", spent " << m_currency.formatAmount(static_cast<uint64_t>(-txInfo.totalAmount));
  }

  if (txInfo.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    m_refresh_progress_reporter.update(m_node->getLastLocalBlockHeight(), true);
  } else {
    m_refresh_progress_reporter.update(txInfo.blockHeight, true);
  }
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::synchronizationCompleted(std::error_code result) {
  std::unique_lock<std::mutex> lock(m_walletSynchronizedMutex);
  m_walletSynchronized = true;
  m_walletSynchronizedCV.notify_one();
}

void simple_wallet::synchronizationProgressUpdated(uint32_t current, uint32_t total) {
  std::unique_lock<std::mutex> lock(m_walletSynchronizedMutex);
  if (!m_walletSynchronized) {
    m_refresh_progress_reporter.update(current, false);
  }
}

bool simple_wallet::show_balance(const std::vector<std::string>& args/* = std::vector<std::string>()*/) {
  success_msg_writer() << "available balance: " << m_currency.formatAmount(m_wallet->actualBalance()) <<
    ", locked amount: " << m_currency.formatAmount(m_wallet->pendingBalance());

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_incoming_transactions(const std::vector<std::string>& args) {
  bool hasTransfers = false;
  size_t transactionsCount = m_wallet->getTransactionCount();
  for (size_t trantransactionNumber = 0; trantransactionNumber < transactionsCount; ++trantransactionNumber) {
    WalletLegacyTransaction txInfo;
    m_wallet->getTransaction(trantransactionNumber, txInfo);
    if (txInfo.totalAmount > 0)
    {
      hasTransfers = true;
      printIncomingTransaction(logger, txInfo, *m_wallet, m_currency);
    }
  }

  if (!hasTransfers) success_msg_writer() << "No incoming transactions";
  return true;
}

bool simple_wallet::show_outgoing_transactions(const std::vector<std::string>& args) {
  bool hasTransfers = false;
  size_t transactionsCount = m_wallet->getTransactionCount();
  for (size_t trantransactionNumber = 0; trantransactionNumber < transactionsCount; ++trantransactionNumber) {
    WalletLegacyTransaction txInfo;
    m_wallet->getTransaction(trantransactionNumber, txInfo);
    if (txInfo.totalAmount >= 0) continue;
    hasTransfers = true;
    printOutgoingTransaction(logger, txInfo, *m_wallet, m_currency);
  }

  if (!hasTransfers) success_msg_writer() << "No outgoing transactions";
  return true;
}

bool simple_wallet::list_transactions(const std::vector<std::string>& args) {
  bool haveTransfers = false;

  size_t transactionsCount = m_wallet->getTransactionCount();
  for (size_t trantransactionNumber = 0; trantransactionNumber < transactionsCount; ++trantransactionNumber) {
    WalletLegacyTransaction txInfo;
    m_wallet->getTransaction(trantransactionNumber, txInfo);
    if (txInfo.state != WalletLegacyTransactionState::Active || txInfo.blockHeight == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
      continue;
    }

    if (!haveTransfers) {
      haveTransfers = true;
    }

    printTransaction(logger, txInfo, *m_wallet, m_currency);
  }

  if (!haveTransfers) {
    success_msg_writer() << "No transfers";
  }

  return true;
}

bool simple_wallet::show_payments(const std::vector<std::string> &args) {
  if (args.empty()) {
    fail_msg_writer() << "expected at least one payment ID";
    return true;
  }

  bool payments_found = false;
  for (const std::string& arg: args) {
    Crypto::Hash expectedPaymentId;
    if (CryptoNote::parsePaymentId(arg, expectedPaymentId)) {
      std::stringstream ss;

      size_t transactionsCount = m_wallet->getTransactionCount();
      for (size_t trantransactionNumber = 0; trantransactionNumber < transactionsCount; ++trantransactionNumber) {
        WalletLegacyTransaction txInfo;
        m_wallet->getTransaction(trantransactionNumber, txInfo);
        if (txInfo.totalAmount > 0)
        {
          std::vector<uint8_t> extraVec;
          extraVec.reserve(txInfo.extra.size());
          std::for_each(txInfo.extra.begin(), txInfo.extra.end(), [&extraVec](const char el) { extraVec.push_back(el); });

          Crypto::Hash paymentId;
          if (CryptoNote::getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId == expectedPaymentId) {
            payments_found = true;

            char timeString[TIMESTAMP_MAX_WIDTH + 1];
            time_t timestamp = static_cast<time_t>(txInfo.timestamp);
            if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
              throw std::runtime_error("time buffer is too small");
            }

            ss <<
              "Received : " << m_currency.formatAmount(txInfo.totalAmount) << " CASH2" << std::endl <<
              "Timestamp : " << timeString << std::endl <<
              "Transaction Hash : " << Common::podToHex(txInfo.hash) << std::endl <<
              "Transaction Fee : " << m_currency.formatAmount(txInfo.fee) << " CASH2" << std::endl <<
              "Block Height : " << addCommasToBlockHeight(txInfo.blockHeight) << std::endl <<
              "Payment ID : " << paymentId << std::endl << std::endl;
          }
        }
      }

      logger(INFO, GREEN) << ss.str();

      if (!payments_found) {
        success_msg_writer() << "No payments with id " << expectedPaymentId << " found";
        continue;
      }
    } else {
      fail_msg_writer() << "Payment ID has invalid format: \"" << arg << "\", expected 64-character string";
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_blockchain_height(const std::vector<std::string>& args) {
  try {
    uint64_t bc_height = m_node->getLastLocalBlockHeight();
    success_msg_writer() << bc_height;
  } catch (std::exception &e) {
    fail_msg_writer() << "failed to get blockchain height: " << e.what();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
uint64_t simple_wallet::getMinimalFee() {
  if (m_node->getLastLocalBlockHeight() < CryptoNote::parameters::SOFT_FORK_HEIGHT_1)
  {
    return CryptoNote::parameters::MINIMUM_FEE_1;
  }
  
  return CryptoNote::parameters::MINIMUM_FEE_2;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer(const std::vector<std::string> &args) {
  try {
    TransferCommand cmd(m_currency, *m_node);

    if (!cmd.parseArguments(logger, args))
      return false;
    CryptoNote::WalletHelper::SendCompleteResultObserver sent;

    std::string extraString;
    std::copy(cmd.extra.begin(), cmd.extra.end(), std::back_inserter(extraString));

    WalletHelper::IWalletRemoveObserverGuard removeGuard(*m_wallet, sent);

    CryptoNote::TransactionId tx = m_wallet->sendTransaction(cmd.dsts, cmd.fee, extraString, cmd.fake_outs_count, 0);
    if (tx == WALLET_LEGACY_INVALID_TRANSACTION_ID) {
      fail_msg_writer() << "Can't send money";
      return true;
    }

    std::error_code sendError = sent.wait(tx);
    removeGuard.removeObserver();

    if (sendError) {
      fail_msg_writer() << sendError.message();
      return true;
    }

    CryptoNote::WalletLegacyTransaction txInfo;
    m_wallet->getTransaction(tx, txInfo);
    success_msg_writer(true) << "Money successfully sent, transaction " << Common::podToHex(txInfo.hash) << std::endl;

    try {
      CryptoNote::WalletHelper::storeWallet(*m_wallet, m_wallet_file);
    } catch (const std::exception& e) {
      fail_msg_writer() << e.what();
      return true;
    }
  } catch (const std::system_error& e) {
    fail_msg_writer() << e.what();
  } catch (const std::exception& e) {
    fail_msg_writer() << e.what();
  } catch (...) {
    fail_msg_writer() << "unknown error";
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::run() {
  {
    std::unique_lock<std::mutex> lock(m_walletSynchronizedMutex);
    while (!m_walletSynchronized) {
      m_walletSynchronizedCV.wait(lock);
    }
  }

  std::cout << std::endl;

  std::string addr_start = m_wallet->getAddress().substr(0, 6);
  std::string walletName = m_wallet_file_arg.substr(0, 20);
  m_consoleHandler.start(false, "[" + walletName + "]: ", Common::Console::Color::BrightYellow);
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::stop() {
  m_consoleHandler.requestStop();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_address(const std::vector<std::string> &args/* = std::vector<std::string>()*/) {
  success_msg_writer() << m_wallet->getAddress();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_view_secret_key(const std::vector<std::string> &args) {
  CryptoNote::AccountKeys accountKeys;
  m_wallet->getAccountKeys(accountKeys);
  Crypto::SecretKey viewSecretKey = accountKeys.viewSecretKey;
  success_msg_writer() << Common::podToHex(viewSecretKey);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_spend_secret_key(const std::vector<std::string> &args) {
  CryptoNote::AccountKeys accountKeys;
  m_wallet->getAccountKeys(accountKeys);
  Crypto::SecretKey spendSecretKey = accountKeys.spendSecretKey;
  success_msg_writer() << Common::podToHex(spendSecretKey);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::process_command(const std::vector<std::string> &args) {
  return m_consoleHandler.runCommand(args);
}

void simple_wallet::printConnectionError() const {
  fail_msg_writer() << "wallet failed to connect to daemon (" << m_daemon_address << ").\n";
}


int main(int argc, char* argv[]) {
#ifdef WIN32
  _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

  po::options_description desc_general("General options");
  command_line::add_arg(desc_general, command_line::arg_help);
  command_line::add_arg(desc_general, command_line::arg_version);

  po::options_description desc_params("Wallet options");
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_generate_new_wallet);
  command_line::add_arg(desc_params, arg_password);
  command_line::add_arg(desc_params, arg_daemon_address);
  command_line::add_arg(desc_params, arg_daemon_host);
  command_line::add_arg(desc_params, arg_daemon_port);
  command_line::add_arg(desc_params, arg_command);
  command_line::add_arg(desc_params, arg_log_level);
  command_line::add_arg(desc_params, arg_testnet);
  Tools::wallet_rpc_server::init_options(desc_params);

  po::positional_options_description positional_options;
  positional_options.add(arg_command.name, -1);

  po::options_description desc_all;
  desc_all.add(desc_general).add(desc_params);

  Logging::LoggerManager logManager;
  Logging::LoggerRef logger(logManager, "simplewallet");
  System::Dispatcher dispatcher;

  po::variables_map vm;

  bool r = command_line::handle_error_helper(desc_all, [&]() {
    po::store(command_line::parse_command_line(argc, argv, desc_general, true), vm);

    if (command_line::get_arg(vm, command_line::arg_help)) {
      CryptoNote::Currency tmp_currency = CryptoNote::CurrencyBuilder(logManager).currency();
      CryptoNote::simple_wallet tmp_wallet(dispatcher, tmp_currency, logManager);

      std::cout << CRYPTONOTE_NAME << " wallet v" << PROJECT_VERSION_LONG << std::endl  << std::endl;
      std::cout << "Usage:" << std::endl << "simplewallet [--wallet-file=<file>|--generate-new-wallet=<file>] [--daemon-address=<host>:<port>] [<COMMAND>]"  << std::endl;
      std::cout << desc_all;
      return false;
    } else if (command_line::get_arg(vm, command_line::arg_version))  {
      std::cout << CRYPTONOTE_NAME << " wallet v" << PROJECT_VERSION_LONG;
      return false;
    }

    auto parser = po::command_line_parser(argc, argv).options(desc_params).positional(positional_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });

  if (!r)
    return 1;

  //set up logging options
  Level logLevel = DEBUGGING;

  if (command_line::has_arg(vm, arg_log_level)) {
    logLevel = static_cast<Level>(command_line::get_arg(vm, arg_log_level));
  }

  logManager.configure(buildLoggerConfiguration(logLevel, Common::ReplaceExtenstion(argv[0], ".log")));

  logger(INFO, BRIGHT_WHITE) << CRYPTONOTE_NAME << " wallet v" << PROJECT_VERSION_LONG;

  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logManager).
    testnet(command_line::get_arg(vm, arg_testnet)).currency();

  if (command_line::has_arg(vm, Tools::wallet_rpc_server::arg_rpc_bind_port)) {
    //runs wallet with rpc interface
    if (!command_line::has_arg(vm, arg_wallet_file)) {
      logger(ERROR, BRIGHT_RED) << "Wallet file not set.";
      return 1;
    }

    if (!command_line::has_arg(vm, arg_daemon_address)) {
      logger(ERROR, BRIGHT_RED) << "Daemon address not set.";
      return 1;
    }

    if (!command_line::has_arg(vm, arg_password)) {
      logger(ERROR, BRIGHT_RED) << "Wallet password not set.";
      return 1;
    }

    std::string wallet_file = command_line::get_arg(vm, arg_wallet_file);
    std::string wallet_password = command_line::get_arg(vm, arg_password);
    std::string daemon_address = command_line::get_arg(vm, arg_daemon_address);
    std::string daemon_host = command_line::get_arg(vm, arg_daemon_host);
    uint16_t daemon_port = command_line::get_arg(vm, arg_daemon_port);
    if (daemon_host.empty())
      daemon_host = "localhost";
    if (!daemon_port)
      daemon_port = RPC_DEFAULT_PORT;

    if (!daemon_address.empty()) {
      if (!parseUrlAddress(daemon_address, daemon_host, daemon_port)) {
        logger(ERROR, BRIGHT_RED) << "failed to parse daemon address: " << daemon_address;
        return 1;
      }
    }

    std::unique_ptr<INode> node(new NodeRpcProxy(daemon_host, daemon_port));

    std::promise<std::error_code> errorPromise;
    std::future<std::error_code> error = errorPromise.get_future();
    auto callback = [&errorPromise](std::error_code e) {errorPromise.set_value(e); };
    node->init(callback);
    if (error.get()) {
      logger(ERROR, BRIGHT_RED) << ("failed to init NodeRPCProxy");
      return 1;
    }

    std::unique_ptr<IWalletLegacy> wallet(new WalletLegacy(currency, *node.get()));

    std::string walletFileName;
    try  {
      walletFileName = ::tryToOpenWalletOrLoadKeysOrThrow(logger, wallet, wallet_file, wallet_password);

      logger(INFO) << "available balance: " << currency.formatAmount(wallet->actualBalance()) <<
      ", locked amount: " << currency.formatAmount(wallet->pendingBalance());

      logger(INFO, BRIGHT_GREEN) << "Loaded ok";
    } catch (const std::exception& e)  {
      logger(ERROR, BRIGHT_RED) << "Wallet initialize failed: " << e.what();
      return 1;
    }

    Tools::wallet_rpc_server wrpc(dispatcher, logManager, *wallet, *node, currency, walletFileName);

    if (!wrpc.init(vm)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize wallet rpc server";
      return 1;
    }

    Tools::SignalHandler::install([&wrpc, &wallet] {
      wrpc.send_stop_signal();
    });

    logger(INFO) << "Starting wallet rpc server";
    wrpc.run();
    logger(INFO) << "Stopped wallet rpc server";
    
    try {
      logger(INFO) << "Storing wallet...";
      CryptoNote::WalletHelper::storeWallet(*wallet, walletFileName);
      logger(INFO, BRIGHT_GREEN) << "Stored ok";
    } catch (const std::exception& e) {
      logger(ERROR, BRIGHT_RED) << "Failed to store wallet: " << e.what();
      return 1;
    }
  } else {
    //runs wallet with console interface
    CryptoNote::simple_wallet wal(dispatcher, currency, logManager);
    
    if (!wal.init(vm)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize wallet"; 
      return 1; 
    }

    std::vector<std::string> command = command_line::get_arg(vm, arg_command);
    if (!command.empty())
      wal.process_command(command);

    Tools::SignalHandler::install([&wal] {
      wal.stop();
    });
    
    wal.run();

    if (!wal.deinit()) {
      logger(ERROR, BRIGHT_RED) << "Failed to close wallet";
    } else {
      logger(INFO) << "Wallet closed";
    }
  }
  return 1;
  //CATCH_ENTRY_L0("main", 1);
}