// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "Common/PathTools.h"
#include "Common/SignalHandler.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "DaemonCommandsHandler.h"
#include "DaemonConfigurationOptions.h"
#include "DaemonRpcServer.h"
#include "DaemonRpcServerConfig.h"
#include "Logging/ConsoleLogger.h"
#include "Logging/LoggerManager.h"
#include "P2p/NodeServer.h"
#include "P2p/NodeServerConfig.h"
#include "crypto/hash.h"
#include "version.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

int main(int argc, char* argv[])
{

#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  Logging::LoggerManager logManager;
  Logging::LoggerRef logger(logManager, "Daemon");

  try {

    boost::program_options::options_description daemonConfigurationOptionsDescription("Daemon Configuration Options");
    CryptoNote::DaemonConfigurationOptions::initOptions(daemonConfigurationOptionsDescription);

    boost::program_options::options_description daemonRpcServerConfigurationOptionsDescription("Daemon RPC Server Configuration Options");
    CryptoNote::DaemonRpcServerConfig::initOptions(daemonRpcServerConfigurationOptionsDescription);

    boost::program_options::options_description coreConfigurationOptionsDescription("Core Configuration Options");
    CryptoNote::CoreConfig::initOptions(coreConfigurationOptionsDescription);

    boost::program_options::options_description nodeServerConfigurationOptionsDescription("Node Server Configuration Options");
    CryptoNote::NodeServerConfig::initOptions(nodeServerConfigurationOptionsDescription);

    boost::program_options::options_description miningConfigurationOptionsDescription("Mining Configuration Options");
    CryptoNote::MinerConfig::initOptions(miningConfigurationOptionsDescription);

    boost::program_options::options_description allConfigurationOptionsDescription("All Configuration Options");

    allConfigurationOptionsDescription.
      add(daemonConfigurationOptionsDescription).
      add(daemonRpcServerConfigurationOptionsDescription).
      add(nodeServerConfigurationOptionsDescription).
      add(miningConfigurationOptionsDescription);

    boost::program_options::variables_map vm;

    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, allConfigurationOptionsDescription), vm);

    CryptoNote::DaemonConfigurationOptions daemonConfigurationOptions;
    daemonConfigurationOptions.init(vm);

    if (daemonConfigurationOptions.help)
    {
      std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL << ENDL;
      std::cout << allConfigurationOptionsDescription << std::endl;
      return 0;
    }

    if (daemonConfigurationOptions.printGenesisTransaction) {
      Logging::ConsoleLogger logger;
      CryptoNote::Transaction tx = CryptoNote::CurrencyBuilder(logger).generateGenesisTransaction();
      CryptoNote::BinaryArray txb = CryptoNote::toBinaryArray(tx);
      std::string tx_hex = Common::toHex(txb);

      std::cout << "Insert this line into your coin configuration file as is: " << std::endl;
      std::cout << "const char GENESIS_COINBASE_TX_HEX[] = \"" << tx_hex << "\";" << std::endl;
      return 0;
    }

    std::string dataDirectory = daemonConfigurationOptions.dataDirectory;
    std::string configFile = daemonConfigurationOptions.configFile;

    boost::filesystem::path dataDirectoryPath(dataDirectory);
    boost::filesystem::path configFilePath(configFile);
    if (!configFilePath.has_parent_path()) {
      configFilePath = dataDirectoryPath / configFilePath;
    }

    boost::system::error_code ec;
    if (boost::filesystem::exists(configFilePath, ec)) {
      boost::program_options::store(boost::program_options::parse_config_file<char>(configFilePath.string<std::string>().c_str(), daemonConfigurationOptionsDescription), vm);
    }

    boost::program_options::notify(vm);

    std::string modulePath = Common::NativePathToGeneric(argv[0]);
    std::string logFile = Common::NativePathToGeneric(daemonConfigurationOptions.logFile);

    if (logFile.empty()) {
      logFile = Common::ReplaceExtenstion(modulePath, ".log");
    } else {
      if (!Common::HasParentPath(logFile)) {
        logFile = Common::CombinePath(Common::GetPathDirectory(modulePath), logFile);
      }
    }

    Logging::Level logLevel = static_cast<Logging::Level>(static_cast<int>(Logging::ERROR) + daemonConfigurationOptions.logLevel);

    // configure logging
    Common::JsonValue loggerConfiguration(Common::JsonValue::OBJECT);
    loggerConfiguration.insert("globalLevel", static_cast<int64_t>(logLevel));

    Common::JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", Common::JsonValue::ARRAY);

    Common::JsonValue& fileLogger = cfgLoggers.pushBack(Common::JsonValue::OBJECT);
    fileLogger.insert("type", "file");
    fileLogger.insert("filename", logFile);
    fileLogger.insert("level", static_cast<int64_t>(Logging::TRACE));

    Common::JsonValue& consoleLogger = cfgLoggers.pushBack(Common::JsonValue::OBJECT);
    consoleLogger.insert("type", "console");
    consoleLogger.insert("level", static_cast<int64_t>(Logging::TRACE));
    consoleLogger.insert("pattern", "%T %L ");
    logManager.configure(loggerConfiguration);
    // end configure logging

    logger(Logging::INFO) << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG;

    if (command_line::get_arg(vm, command_line::arg_version)) {
      std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL;
      return 0;
    }

    if (daemonConfigurationOptions.osVersion) {
      std::cout << "OS version : " << Tools::get_os_version_string() << ENDL;
      return 0;
    }

    logger(Logging::INFO) << "Module folder : " << argv[0];

    bool testnet_mode = daemonConfigurationOptions.testnet;
    if (testnet_mode) {
      logger(Logging::INFO) << "Starting in testnet mode ...";
    }

    CryptoNote::CurrencyBuilder currencyBuilder(logManager);
    currencyBuilder.testnet(testnet_mode);

    try {
      currencyBuilder.currency();
    } catch (std::exception&) {
      std::cout << "GENESIS_COINBASE_TX_HEX constant has an incorrect value. Please launch : " << CryptoNote::CRYPTONOTE_NAME << "d --print-genesis-tx";
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

    CryptoNote::CoreConfig coreConfig;
    coreConfig.init(vm);

    if (!coreConfig.configFolderDefaulted) {
      if (!Tools::directoryExists(coreConfig.configFolder)) {
        throw std::runtime_error("Directory does not exist : " + coreConfig.configFolder);
      }
    } else {
      if (!Tools::create_directories_if_necessary(coreConfig.configFolder)) {
        throw std::runtime_error("Can't create directory : " + coreConfig.configFolder);
      }
    }

    System::Dispatcher dispatcher;

    CryptoNote::CryptoNoteProtocolHandler cryptoNoteProtocolHandler(currency, dispatcher, core, nullptr, logManager);
    CryptoNote::NodeServer nodeServer(dispatcher, cryptoNoteProtocolHandler, logManager);

    CryptoNote::DaemonRpcServerConfig daemonRpcServerConfig;
    daemonRpcServerConfig.init(vm);
    CryptoNote::DaemonRpcServer daemonRpcServer(dispatcher, logManager, core, nodeServer, cryptoNoteProtocolHandler, daemonRpcServerConfig);

    cryptoNoteProtocolHandler.set_p2p_endpoint(&nodeServer);
    core.set_cryptonote_protocol(&cryptoNoteProtocolHandler);
    DaemonCommandsHandler daemonCommandsHandler(core, nodeServer, logManager);

    // initialize objects
    CryptoNote::NodeServerConfig nodeServerConfig;
    nodeServerConfig.init(vm);
    nodeServerConfig.setTestnet(testnet_mode);

    logger(Logging::INFO) << "Initializing Node Server ...";
    if (!nodeServer.init(nodeServerConfig)) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to initialize Node Server";
      return 1;
    }
    logger(Logging::INFO) << "Node Server initialized OK";

    // initialize core here
    CryptoNote::MinerConfig minerConfig;
    minerConfig.init(vm);

    logger(Logging::INFO) << "Initializing Core ...";
    if (!core.init(coreConfig, minerConfig, true)) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to initialize Core";
      return 1;
    }
    logger(Logging::INFO) << "Core initialized OK";

    // start components
    if (!daemonConfigurationOptions.console) {
      daemonCommandsHandler.start_handling();
    }

    logger(Logging::INFO) << "Starting Daemon RPC Server on network address " << daemonRpcServerConfig.getBindAddress() << " ...";
    daemonRpcServer.start();
    daemonRpcServer.setRestrictedRpc(daemonConfigurationOptions.restrictedRpc);
    daemonRpcServer.enableCors(daemonConfigurationOptions.enableCors);
    logger(Logging::INFO) << "Daemon RPC Server started OK";

    Tools::SignalHandler::install([&daemonCommandsHandler, &nodeServer] {
      daemonCommandsHandler.stop_handling();
      nodeServer.sendStopSignal();
    });

    logger(Logging::INFO) << "Starting Node Server ...";
    nodeServer.run();
    logger(Logging::INFO) << "Node Server stopped";

    daemonCommandsHandler.stop_handling();

    //stop components
    logger(Logging::INFO) << "Stopping Daemon RPC Server ...";
    daemonRpcServer.stop();

    //deinitialize components
    logger(Logging::INFO) << "Deinitializing Core ...";
    core.deinit();
    logger(Logging::INFO) << "Deinitializing Node Server ...";
    nodeServer.deinit();

    core.set_cryptonote_protocol(NULL);
    cryptoNoteProtocolHandler.set_p2p_endpoint(NULL);

  } catch (const std::exception& e) {
    logger(Logging::ERROR, Logging::BRIGHT_RED) << "Exception : " << e.what();
    return 1;
  }

  logger(Logging::INFO) << "Node stopped";
  return 0;
}
