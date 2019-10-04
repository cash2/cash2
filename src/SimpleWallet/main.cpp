// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/program_options.hpp>

#include "Common/CommandLine.h"
#include "Common/PathTools.h"
#include "Common/SignalHandler.h"
#include "SimpleWallet.h"
#include "SimpleWalletConfigurationOptions.h"
#include "version.h"

namespace {

using Common::JsonValue;
using namespace Logging;

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

}

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

    //set up logging options
    Logging::Level logLevel = static_cast<Logging::Level>(simpleWalletConfigurationOptions.logLevel);

    logManager.configure(buildLoggerConfiguration(logLevel, Common::ReplaceExtenstion(argv[0], ".log")));

    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logManager).testnet(simpleWalletConfigurationOptions.testnet).currency();

    //runs wallet with console interface
    CryptoNote::SimpleWallet simpleWallet(dispatcher, currency, logManager, simpleWalletConfigurationOptions);
    
    if (!simpleWallet.init()) {
      logger(Logging::ERROR, Logging::DEFAULT) << "\nExiting SimpleWallet"; 
      return 1; 
    }

    Tools::SignalHandler::install([&simpleWallet] {
      simpleWallet.stop();
    });
    
    simpleWallet.run();

    if (!simpleWallet.deinit()) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to close wallet";
    } else {
      logger(Logging::INFO) << "Wallet closed";
    }
  } catch (const std::exception& e) {
    logger(Logging::ERROR, Logging::BRIGHT_RED) << "Exception : " << e.what();
    return 1;
  }

  return 0;
}