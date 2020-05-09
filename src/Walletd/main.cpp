// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <future>
#include <memory>
#include <string.h>
#include <thread>

#include "Common/SignalHandler.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "InProcessNode/InProcessNode.h"
#include "Logging/ConsoleLogger.h"
#include "Logging/LoggerGroup.h"
#include "Logging/LoggerManager.h"
#include "Logging/LoggerRef.h"
#include "Logging/StreamLogger.h"
#include "P2p/NodeServer.h"
#include "WalletdRpcNodeFactory.h"
#include "WalletdRpcServer.h"
#include "WalletHelper.h"
#include "Wallet/WalletGreen.h"
#include "System/Context.h"
#include "WalletdConfigurationOptions.h"
#include "version.h"

#ifdef ERROR
#undef ERROR
#endif

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

namespace {

void runWalletHelper(const CryptoNote::Currency& currency, CryptoNote::INode& node,
                      const Walletd::WalletdConfigurationOptions& walletdConfigurationOptions, System::Dispatcher* dispatcherPtr,
                      Logging::LoggerGroup& logger, System::Event* stopEventPtr) {

  Walletd::WalletConfiguration walletConfiguration{
    walletdConfigurationOptions.containerFile,
    walletdConfigurationOptions.containerPassword,
    walletdConfigurationOptions.spendPrivateKey,
    walletdConfigurationOptions.viewPrivateKey
  };

  std::unique_ptr<CryptoNote::IWallet> walletPtr (new CryptoNote::WalletGreen(*dispatcherPtr, currency, node));
  std::unique_ptr<Walletd::WalletHelper> walletHelperPtr(new Walletd::WalletHelper(currency, *dispatcherPtr, node, *walletPtr, walletConfiguration, logger));

  try
  {
    walletHelperPtr->init();
  }
  catch (std::exception& e)
  {
    Logging::LoggerRef loggerRun(logger, "run");
    loggerRun(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to initialize Wallet Service : " << e.what();
    throw e;
  }

  if (walletdConfigurationOptions.printAddresses)
  {

    // print addresses and exit

    std::vector<std::string> addresses;
    walletHelperPtr->getAddresses(addresses);
    for (const std::string& address: addresses)
    {
      std::cout << "Address: " << address << std::endl;
    }

  }
  else
  {
    Walletd::WalletdRpcServer walletdRpcServer(*dispatcherPtr, *stopEventPtr, *walletHelperPtr, logger, walletdConfigurationOptions.rpcConfigurationPassword);
    walletdRpcServer.start(walletdConfigurationOptions.bindAddress, walletdConfigurationOptions.bindPort);

    try
    {
      walletHelperPtr->saveWallet();
    }
    catch (std::exception& e)
    {
      Logging::LoggerRef(logger, "saveWallet")(Logging::WARNING, Logging::YELLOW) << "Couldn't save container: " << e.what();
      throw e;
    }
  }
}

}

int main(int argc, char** argv) {

  System::Dispatcher* dispatcherPtr = nullptr;
  Walletd::WalletdConfigurationOptions walletdConfigurationOptions;
  Logging::ConsoleLogger consoleLogger;
  Logging::LoggerGroup logger;
  CryptoNote::CurrencyBuilder currencyBuilder(logger);
  Logging::StreamLogger fileLogger;
  std::ofstream logFile;
  System::Event* stopEventPtr = nullptr;

  try
  {
    if (!walletdConfigurationOptions.init(argc, argv))
    {
      return 1;
    }

    logger.setMaxLevel(static_cast<Logging::Level>(walletdConfigurationOptions.logLevel));
    logger.addLogger(consoleLogger);

    Logging::LoggerRef loggerMain(logger, "main");

    if (walletdConfigurationOptions.testnet)
    {
      loggerMain(Logging::INFO) << "Starting in testnet mode";
      currencyBuilder.testnet(true);
    }

    CryptoNote::Currency currency = currencyBuilder.currency();

    if (!walletdConfigurationOptions.serverRoot.empty())
    {
      if (chdir(walletdConfigurationOptions.serverRoot.c_str()))
      {
        throw std::runtime_error("Couldn't change directory to \'" + walletdConfigurationOptions.serverRoot + "\': " + strerror(errno));
      }

      loggerMain(Logging::INFO) << "Current working directory now is " << walletdConfigurationOptions.serverRoot;
    }

    logFile.open(walletdConfigurationOptions.logFile, std::ofstream::app);

    if (!logFile)
    {
      throw std::runtime_error("Couldn't open log file");
    }

    fileLogger.attachToStream(logFile);
    logger.addLogger(fileLogger);

    loggerMain(Logging::INFO) << "Walletd " << " v" << PROJECT_VERSION_LONG;

    if (walletdConfigurationOptions.generateNewContainer)
    {
      System::Dispatcher dispatcher;

      Walletd::WalletConfiguration walletConfig {
        walletdConfigurationOptions.containerFile,
        walletdConfigurationOptions.containerPassword,
        walletdConfigurationOptions.spendPrivateKey,
        walletdConfigurationOptions.viewPrivateKey
      };

      generateNewWallet(currency, walletConfig, logger, dispatcher);
      return 0;
    }

    System::Dispatcher dispatcher;
    System::Event stopEvent(dispatcher);

    dispatcherPtr = &dispatcher;
    stopEventPtr = &stopEvent;

    Tools::SignalHandler::install([&] {
      Logging::LoggerRef loggerStop(logger, "stop");

      loggerStop(Logging::INFO) << "Stop signal caught";

      if (dispatcherPtr != nullptr) {
        dispatcherPtr->remoteSpawn([&]() {
          if (stopEventPtr != nullptr) {
            stopEventPtr->set();
          }
        });
      }
    });

    Logging::LoggerRef loggerRun(logger, "run");

    if (walletdConfigurationOptions.startInprocess)
    {

      // in process node

      if (!walletdConfigurationOptions.coreConfig.configFolderDefaulted)
      {
        if (!Tools::directoryExists(walletdConfigurationOptions.coreConfig.configFolder))
        {
          throw std::runtime_error("Directory does not exist: " + walletdConfigurationOptions.coreConfig.configFolder);
        }
      }
      else
      {
        if (!Tools::create_directories_if_necessary(walletdConfigurationOptions.coreConfig.configFolder))
        {
          throw std::runtime_error("Can't create directory: " + walletdConfigurationOptions.coreConfig.configFolder);
        }
      }

      loggerRun(Logging::INFO) << "Starting Walletd with local node";

      CryptoNote::Core core(currency, NULL, logger);
      CryptoNote::CryptoNoteProtocolHandler cryptoNoteProtocolHandler(currency, *dispatcherPtr, core, NULL, logger);
      CryptoNote::NodeServer nodeServer(*dispatcherPtr, cryptoNoteProtocolHandler, logger);

      cryptoNoteProtocolHandler.set_p2p_endpoint(&nodeServer);
      core.set_cryptonote_protocol(&cryptoNoteProtocolHandler);

      loggerRun(Logging::INFO) << "Initializing Node Server ...";

      if (!nodeServer.init(walletdConfigurationOptions.nodeServerConfig))
      {
        throw std::runtime_error("Failed to initialize Node Server");
      }

      loggerRun(Logging::INFO) << "Initializing Core ...";

      CryptoNote::MinerConfig minerConfig;
      core.init(walletdConfigurationOptions.coreConfig, minerConfig, true);

      std::promise<std::error_code> nodeInitPromise;
      std::future<std::error_code> nodeInitFuture = nodeInitPromise.get_future();

      std::unique_ptr<CryptoNote::INode> nodePtr(new CryptoNote::InProcessNode(core, cryptoNoteProtocolHandler));

      nodePtr->init([&nodeInitPromise, &loggerRun](std::error_code error) {
        if (error) {
          loggerRun(Logging::WARNING, Logging::YELLOW) << "Failed to initialize Node : " << error.message();
        } else {
          loggerRun(Logging::INFO) << "Node initialized successfully";
        }

        nodeInitPromise.set_value(error);
      });

      std::error_code error = nodeInitFuture.get();

      if (error) {
        throw std::system_error(error);
      }

      loggerRun(Logging::INFO) << "Starting Node Server ...";

      System::Event nodeServerStarted(*dispatcherPtr);
      
      System::Context<> context(*dispatcherPtr, [&]() {
        nodeServerStarted.set();
        nodeServer.run();
      });

      nodeServerStarted.wait();

      runWalletHelper(currency, *nodePtr, walletdConfigurationOptions, dispatcherPtr, logger, stopEventPtr);

      nodeServer.sendStopSignal();
      context.get();
      nodePtr->shutdown();
      core.deinit();
      nodeServer.deinit();

    }
    else
    {

      // remote node

      loggerRun(Logging::INFO) << "Starting Walletd with a remote node";

      std::unique_ptr<CryptoNote::INode> nodePtr(Walletd::WalletdRpcNodeFactory::createNode(walletdConfigurationOptions.daemonHost, walletdConfigurationOptions.daemonPort));
      
      runWalletHelper(currency, *nodePtr, walletdConfigurationOptions, dispatcherPtr, logger, stopEventPtr);
    }

    dispatcherPtr = nullptr;
    stopEventPtr = nullptr;

  }
  catch (std::exception& ex)
  {
    std::cerr << "Error: " << ex.what() << std::endl;
    return 1;
  }

  return 0;
}
