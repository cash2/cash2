// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "version.h"

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "DaemonCommandsHandler.h"

#include "Common/SignalHandler.h"
#include "Common/PathTools.h"
#include "crypto/hash.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "P2p/NodeServer.h"
#include "P2p/NodeServerConfig.h"
#include "Rpc/RpcServer.h"
#include "Rpc/RpcServerConfig.h"
#include "version.h"

#include "Logging/ConsoleLogger.h"
#include <Logging/LoggerManager.h>

#if defined(WIN32)
#include <crtdbg.h>
#endif

using Common::JsonValue;
using namespace CryptoNote;
using namespace Logging;

namespace po = boost::program_options;

namespace
{

const command_line::arg_descriptor<std::string> arg_config_file =       {"config-file", "Specify the configuration file", std::string(CryptoNote::CRYPTONOTE_NAME) + ".conf"};
const command_line::arg_descriptor<std::string> arg_enable_cors =       {"enable-cors", "Adds header 'Access-Control-Allow-Origin' to Daemon RPC responses. Uses the value as domain. Use * for all", "" };
const command_line::arg_descriptor<std::string> arg_log_file =          {"log-file", "", ""};
const command_line::arg_descriptor<int>         arg_log_level =         {"log-level", "", 2}; // info level
const command_line::arg_descriptor<bool>        arg_console =           {"no-console", "Disable daemon console commands"};
const command_line::arg_descriptor<bool>        arg_os_version =        {"os-version", "Shows the Cash2 software version and the OS version"};
const command_line::arg_descriptor<bool>        arg_print_genesis_tx =  {"print-genesis-tx", "Prints genesis block's coinbase transaction as hexidecimal to insert it to config" };
const command_line::arg_descriptor<bool>        arg_restricted_rpc =    {"restricted-rpc", "Restrict Daemon RPC commands to view only commands to prevent abuse"};
const command_line::arg_descriptor<bool>        arg_testnet_on =        {"testnet", "Used to deploy test nets. Checkpoints and hardcoded seeds are ignored, network id is changed. Use it with --data-dir flag. The wallet must be launched with --testnet flag.", false};

bool command_line_preprocessor(const boost::program_options::variables_map &vm, LoggerRef &logger) {
  bool exit = false;

  if (command_line::get_arg(vm, command_line::arg_version)) {
    std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL;
    exit = true;
  }
  if (command_line::get_arg(vm, arg_os_version)) {
    std::cout << "OS: " << Tools::get_os_version_string() << ENDL;
    exit = true;
  }

  if (exit) {
    return true;
  }

  return false;
}

void print_genesis_tx_hex() {
  Logging::ConsoleLogger logger;
  CryptoNote::Transaction tx = CryptoNote::CurrencyBuilder(logger).generateGenesisTransaction();
  CryptoNote::BinaryArray txb = CryptoNote::toBinaryArray(tx);
  std::string tx_hex = Common::toHex(txb);

  std::cout << "Insert this line into your coin configuration file as is: " << std::endl;
  std::cout << "const char GENESIS_COINBASE_TX_HEX[] = \"" << tx_hex << "\";" << std::endl;

  return;
}

JsonValue buildLoggerConfiguration(Level level, const std::string& logfile) {
  JsonValue loggerConfiguration(JsonValue::OBJECT);
  loggerConfiguration.insert("globalLevel", static_cast<int64_t>(level));

  JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", JsonValue::ARRAY);

  JsonValue& fileLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  fileLogger.insert("type", "file");
  fileLogger.insert("filename", logfile);
  fileLogger.insert("level", static_cast<int64_t>(TRACE));

  JsonValue& consoleLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  consoleLogger.insert("type", "console");
  consoleLogger.insert("level", static_cast<int64_t>(TRACE));
  consoleLogger.insert("pattern", "%T %L ");

  return loggerConfiguration;
}

} // end anonymous namespace


int main(int argc, char* argv[])
{

#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  LoggerManager logManager;
  LoggerRef logger(logManager, "daemon");

  try {

    po::options_description desc_daemon("Daemon Options");
    po::options_description desc_daemon_rpc("Daemon RPC Server Options");
    po::options_description desc_core("Core Options");
    po::options_description desc_network("Network Options");
    po::options_description desc_mining("Mining Options");

    command_line::add_arg(desc_daemon, arg_config_file);
    command_line::add_arg(desc_daemon, command_line::arg_data_dir, Tools::getDefaultDataDirectory());
    command_line::add_arg(desc_daemon, arg_enable_cors);
    command_line::add_arg(desc_daemon, command_line::arg_help);
    command_line::add_arg(desc_daemon, arg_log_file);
    command_line::add_arg(desc_daemon, arg_log_level);
    command_line::add_arg(desc_daemon, arg_os_version);
    command_line::add_arg(desc_daemon, arg_console);
    command_line::add_arg(desc_daemon, arg_print_genesis_tx);
    command_line::add_arg(desc_daemon, arg_restricted_rpc);
    command_line::add_arg(desc_daemon, arg_testnet_on);
    command_line::add_arg(desc_daemon, command_line::arg_version);

    RpcServerConfig::initOptions(desc_daemon_rpc);
    CoreConfig::initOptions(desc_core); // There are currently no core configuration options
    NodeServerConfig::initOptions(desc_network);
    MinerConfig::initOptions(desc_mining);

    po::options_description desc_options("Command Line Options");
    desc_options.add(desc_daemon).add(desc_daemon_rpc).add(desc_network).add(desc_mining);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]()
    {
      po::store(po::parse_command_line(argc, argv, desc_options), vm);

      if (command_line::get_arg(vm, command_line::arg_help))
      {
        std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL << ENDL;
        std::cout << desc_options << std::endl;
        return false;
      }

      if (command_line::get_arg(vm, arg_print_genesis_tx)) {
        print_genesis_tx_hex();
        return false;
      }

      std::string data_dir = command_line::get_arg(vm, command_line::arg_data_dir);
      std::string config = command_line::get_arg(vm, arg_config_file);

      boost::filesystem::path data_dir_path(data_dir);
      boost::filesystem::path config_path(config);
      if (!config_path.has_parent_path()) {
        config_path = data_dir_path / config_path;
      }

      boost::system::error_code ec;
      if (boost::filesystem::exists(config_path, ec)) {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), desc_daemon), vm);
      }
      po::notify(vm);
      return true;
    });

    if (!r)
      return 1;
  
    std::string modulePath = Common::NativePathToGeneric(argv[0]);
    std::string logFile = Common::NativePathToGeneric(command_line::get_arg(vm, arg_log_file));

    if (logFile.empty()) {
      logFile = Common::ReplaceExtenstion(modulePath, ".log");
    } else {
      if (!Common::HasParentPath(logFile)) {
        logFile = Common::CombinePath(Common::GetPathDirectory(modulePath), logFile);
      }
    }

    Level logLevel = static_cast<Level>(static_cast<int>(Logging::ERROR) + command_line::get_arg(vm, arg_log_level));

    // configure logging
    logManager.configure(buildLoggerConfiguration(logLevel, logFile));

    logger(INFO) << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG;

    if (command_line_preprocessor(vm, logger)) {
      return 0;
    }

    logger(INFO) << "Module folder: " << argv[0];

    bool testnet_mode = command_line::get_arg(vm, arg_testnet_on);
    if (testnet_mode) {
      logger(INFO) << "Starting in testnet mode!";
    }

    //create objects and link them
    CryptoNote::CurrencyBuilder currencyBuilder(logManager);
    currencyBuilder.testnet(testnet_mode);

    try {
      currencyBuilder.currency();
    } catch (std::exception&) {
      std::cout << "GENESIS_COINBASE_TX_HEX constant has an incorrect value. Please launch: " << CryptoNote::CRYPTONOTE_NAME << "d --" << arg_print_genesis_tx.name;
      return 1;
    }

    CryptoNote::Currency currency = currencyBuilder.currency();
    CryptoNote::Core core(currency, nullptr, logManager);

    CryptoNote::Checkpoints checkpoints(logManager);
    for (const CryptoNote::CheckpointData& checkpointData : CryptoNote::CHECKPOINTS) {
      checkpoints.add_checkpoint(checkpointData.blockIndex, checkpointData.blockId);
    }

    if (!testnet_mode) {
      core.set_checkpoints(std::move(checkpoints));
    }

    CoreConfig coreConfig;
    coreConfig.init(vm);
    NodeServerConfig nodeServerConfig;
    nodeServerConfig.init(vm);
    nodeServerConfig.setTestnet(testnet_mode);
    MinerConfig minerConfig;
    minerConfig.init(vm);
    RpcServerConfig rpcConfig;
    rpcConfig.init(vm);

    if (!coreConfig.configFolderDefaulted) {
      if (!Tools::directoryExists(coreConfig.configFolder)) {
        throw std::runtime_error("Directory does not exist: " + coreConfig.configFolder);
      }
    } else {
      if (!Tools::create_directories_if_necessary(coreConfig.configFolder)) {
        throw std::runtime_error("Can't create directory: " + coreConfig.configFolder);
      }
    }

    System::Dispatcher dispatcher;

    CryptoNote::CryptoNoteProtocolHandler cryptoNoteProtocolHandler(currency, dispatcher, core, nullptr, logManager);
    CryptoNote::NodeServer nodeServer(dispatcher, cryptoNoteProtocolHandler, logManager);
    CryptoNote::RpcServer rpcServer(dispatcher, logManager, core, nodeServer, cryptoNoteProtocolHandler);

    cryptoNoteProtocolHandler.set_p2p_endpoint(&nodeServer);
    core.set_cryptonote_protocol(&cryptoNoteProtocolHandler);
    DaemonCommandsHandler daemonCommandsHandler(core, nodeServer, logManager);

    // initialize objects
    logger(INFO) << "Initializing p2p server...";
    if (!nodeServer.init(nodeServerConfig)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize p2p server.";
      return 1;
    }
    logger(INFO) << "P2p server initialized OK";

    // initialize core here
    logger(INFO) << "Initializing core...";
    if (!core.init(coreConfig, minerConfig, true)) {
      logger(ERROR, BRIGHT_RED) << "Failed to initialize core";
      return 1;
    }
    logger(INFO) << "Core initialized OK";

    // start components
    if (!command_line::has_arg(vm, arg_console)) {
      daemonCommandsHandler.start_handling();
    }

    logger(INFO) << "Starting core rpc server on address " << rpcConfig.getBindAddress();
    rpcServer.start(rpcConfig.bindIp, rpcConfig.bindPort);
    rpcServer.restrictRPC(command_line::get_arg(vm, arg_restricted_rpc));
    rpcServer.enableCors(command_line::get_arg(vm, arg_enable_cors));
    logger(INFO) << "Core rpc server started ok";

    Tools::SignalHandler::install([&daemonCommandsHandler, &nodeServer] {
      daemonCommandsHandler.stop_handling();
      nodeServer.sendStopSignal();
    });

    logger(INFO) << "Starting p2p net loop...";
    nodeServer.run();
    logger(INFO) << "p2p net loop stopped";

    daemonCommandsHandler.stop_handling();

    //stop components
    logger(INFO) << "Stopping core rpc server...";
    rpcServer.stop();

    //deinitialize components
    logger(INFO) << "Deinitializing core...";
    core.deinit();
    logger(INFO) << "Deinitializing p2p...";
    nodeServer.deinit();

    core.set_cryptonote_protocol(NULL);
    cryptoNoteProtocolHandler.set_p2p_endpoint(NULL);

  } catch (const std::exception& e) {
    logger(ERROR, BRIGHT_RED) << "Exception: " << e.what();
    return 1;
  }

  logger(INFO) << "Node stopped.";
  return 0;
}
