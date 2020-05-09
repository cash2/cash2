// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/program_options.hpp>

#include "Common/CommandLine.h"
#include "Common/PathTools.h"
#include "Common/SignalHandler.h"
#include "SimpleWalletCommandsHandler.h"
#include "SimpleWalletConfigurationOptions.h"
#include "version.h"

int main(int argc, char* argv[]) {
#ifdef WIN32
  _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

  Logging::LoggerManager logManager;
  Logging::LoggerRef logger(logManager, "SimpleWallet");

  try {

    System::Dispatcher dispatcher;

    CryptoNote::SimpleWalletConfigurationOptions simpleWalletConfigurationOptions;
    boost::program_options::options_description simpleWalletConfigurationOptionsDescription("SimpleWallet Configuration Options");
    simpleWalletConfigurationOptions.initOptions(simpleWalletConfigurationOptionsDescription);

    boost::program_options::variables_map vm;

    boost::program_options::store(command_line::parse_command_line(argc, argv, simpleWalletConfigurationOptionsDescription, true), vm);

    simpleWalletConfigurationOptions.init(vm);

    if (simpleWalletConfigurationOptions.help) {
      simpleWalletConfigurationOptions.printHelp(simpleWalletConfigurationOptionsDescription);
      return 0;
    }

    if (simpleWalletConfigurationOptions.version)  {
      simpleWalletConfigurationOptions.printVersion();
      return 0;
    }

    // set up logging options
    Logging::Level logLevel = static_cast<Logging::Level>(simpleWalletConfigurationOptions.logLevel);

    Common::JsonValue loggerConfiguration(Common::JsonValue::OBJECT);
    loggerConfiguration.insert("globalLevel", static_cast<int64_t>(logLevel));

    Common::JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", Common::JsonValue::ARRAY);

    Common::JsonValue& consoleLogger = cfgLoggers.pushBack(Common::JsonValue::OBJECT);
    consoleLogger.insert("type", "console");
    consoleLogger.insert("level", static_cast<int64_t>(Logging::TRACE));
    consoleLogger.insert("pattern", "");

    Common::JsonValue& fileLogger = cfgLoggers.pushBack(Common::JsonValue::OBJECT);
    fileLogger.insert("type", "file");
    fileLogger.insert("filename", Common::ReplaceExtenstion(argv[0], ".log"));
    fileLogger.insert("level", static_cast<int64_t>(Logging::TRACE));

    logManager.configure(loggerConfiguration);
    // end set up logging options

    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logManager).testnet(simpleWalletConfigurationOptions.testnet).currency();

    CryptoNote::SimpleWalletCommandsHandler simpleWalletCommandsHandler(dispatcher, currency, logManager, simpleWalletConfigurationOptions);
    
    if (!simpleWalletCommandsHandler.init()) {
      logger(Logging::ERROR) << "\nExiting SimpleWallet ..."; 
      return 1; 
    }

    Tools::SignalHandler::install([&simpleWalletCommandsHandler] {
      simpleWalletCommandsHandler.stop_handling();
    });
    
    simpleWalletCommandsHandler.start_handling();

    if (!simpleWalletCommandsHandler.deinit()) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to close SimpleWallet";
    } else {
      logger(Logging::INFO) << "\nSimpleWallet closed";
    }
  } catch (const std::exception& e) {
    logger(Logging::ERROR, Logging::BRIGHT_RED) << "Exception : " << e.what();
    return 1;
  }

  return 0;
}