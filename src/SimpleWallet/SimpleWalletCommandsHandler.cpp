// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

#include "Common/PathTools.h"
#include "Common/StringTools.h"
#include "Common/Util.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Logging/LoggerManager.h"
#include "NodeRpcProxy/NodeRpcProxy.h"
#include "Rpc/CoreRpcCommands.h"
#include "Rpc/CoreRpcStatuses.h"
#include "Rpc/HttpClient.h"
#include "SimpleWalletCommandsHandler.h"
#include "Wallet/LegacyKeysImporter.h"
#include "WalletLegacy/WalletHelper.h"
#include "WalletLegacy/WalletLegacy.h"
#include "version.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

#define EXTENDED_LOGS_FILE "wallet_details.log"
#undef ERROR

namespace CryptoNote {


// Public functions


SimpleWalletCommandsHandler::SimpleWalletCommandsHandler(System::Dispatcher& dispatcher, const Currency& currency, Logging::LoggerManager& log, SimpleWalletConfigurationOptions& simpleWalletConfigurationOptions) :
  m_simpleWalletConfigurationOptions(simpleWalletConfigurationOptions),
  m_dispatcher(dispatcher),
  m_daemonPort(0), 
  m_currency(currency), 
  m_loggerManager(log),
  m_logger(log, "SimpleWallet"),
  m_walletLegacyInitErrorPromisePtr(nullptr),
  m_walletLegacySynchronized(false) {
    m_consoleHandler.setHandler("address", boost::bind(&SimpleWalletCommandsHandler::address, this, _1), "Show wallet address");
    m_consoleHandler.setHandler("all_transactions", boost::bind(&SimpleWalletCommandsHandler::all_transactions, this, _1), "Show all transactions");
    m_consoleHandler.setHandler("balance", boost::bind(&SimpleWalletCommandsHandler::balance, this, _1), "Show wallet balance");
    m_consoleHandler.setHandler("exit", boost::bind(&SimpleWalletCommandsHandler::exit, this, _1), "Close wallet");
    m_consoleHandler.setHandler("transaction_private_key", boost::bind(&SimpleWalletCommandsHandler::transaction_private_key, this, _1), "Get the transaction private key of a transaction\n * get_transaction_private_key <transaction_hash>");
    m_consoleHandler.setHandler("height", boost::bind(&SimpleWalletCommandsHandler::height, this, _1), "Show local blockchain height");
    m_consoleHandler.setHandler("help", boost::bind(&SimpleWalletCommandsHandler::help, this, _1), "Show this help");
    m_consoleHandler.setHandler("incoming_transactions", boost::bind(&SimpleWalletCommandsHandler::incoming_transactions, this, _1), "Show incoming transaction");
    m_consoleHandler.setHandler("outgoing_transactions", boost::bind(&SimpleWalletCommandsHandler::outgoing_transactions, this, _1), "Show outgoing transactions");
    m_consoleHandler.setHandler("payments", boost::bind(&SimpleWalletCommandsHandler::payments, this, _1), "Shows a tranaction given the transaction's payment ID\n * payments <payment_id_1> [<payment_id_2> ... <payment_id_N>]");
    m_consoleHandler.setHandler("reset", boost::bind(&SimpleWalletCommandsHandler::reset, this, _1), "Discard cache data and start synchronizing from the start");
    m_consoleHandler.setHandler("save", boost::bind(&SimpleWalletCommandsHandler::save, this, _1), "Save wallet synchronized data");
    m_consoleHandler.setHandler("send", boost::bind(&SimpleWalletCommandsHandler::send, this, _1), "Send funds to address with privicy level\n * send <privacy_level> <adreess> <amount> [-p payment_id]\n * <privacy_level> can be 0, 1, 2, or 3 with 3 being the most private");
    m_consoleHandler.setHandler("set_log", boost::bind(&SimpleWalletCommandsHandler::set_log, this, _1), "Change log level\n * set_log <level>\n * <level> is a number 0-4");
    m_consoleHandler.setHandler("spend_private_key", boost::bind(&SimpleWalletCommandsHandler::spend_private_key, this, _1), "Show wallet spend private key");
    m_consoleHandler.setHandler("start_mining", boost::bind(&SimpleWalletCommandsHandler::start_mining, this, _1), "Start mining\n * start_mining [<number_of_threads>]");
    m_consoleHandler.setHandler("stop_mining", boost::bind(&SimpleWalletCommandsHandler::stop_mining, this, _1), "Stop mining");
    m_consoleHandler.setHandler("view_private_key", boost::bind(&SimpleWalletCommandsHandler::view_private_key, this, _1), "Show wallet view private key");
}

bool SimpleWalletCommandsHandler::deinit()
{
  m_walletLegacyPtr->removeObserver(this);
  m_nodeRpcProxyPtr->removeObserver(static_cast<INodeRpcProxyObserver*>(this));

  if (m_walletLegacyPtr.get() == nullptr)
  {
    return true;
  }

  return saveAndCloseWallet();
}

bool SimpleWalletCommandsHandler::init()
{
  m_daemonAddress = m_simpleWalletConfigurationOptions.daemonAddress;
  m_daemonHost = m_simpleWalletConfigurationOptions.daemonHost;
  m_daemonPort = m_simpleWalletConfigurationOptions.daemonPort;

  // Check daemon connection first
  if (!m_daemonAddress.empty() && (!m_daemonHost.empty() || 0 != m_daemonPort)) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Can't specify daemon address and daemon host and port at the same time";
    return false;
  }

  if (m_daemonHost.empty())
    m_daemonHost = "localhost";
  if (!m_daemonPort)
    m_daemonPort = RPC_DEFAULT_PORT;
  
  if (!m_daemonAddress.empty()) {
    if (!parseUrlAddress(m_daemonAddress, m_daemonHost, m_daemonPort)) {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to parse daemon address : " << m_daemonAddress;
      return false;
    }
  } else {
    m_daemonAddress = std::string("http://") + m_daemonHost + ":" + std::to_string(m_daemonPort);
  }

  // Show the user the "What would you like to do?" prompt

  char c;

  Common::Console::setTextColor(Common::Console::Color::BrightRed);
  std::cout << "\nCash2 SimpleWallet " << PROJECT_VERSION << '.' << PROJECT_VERSION_BUILD_NO << std::endl;
  Common::Console::setTextColor(Common::Console::Color::Default);

  std::cout << "\nWhat would you like to do?\n\n [";

  Common::Console::setTextColor(Common::Console::Color::BrightRed);
  std::cout << "1";
  Common::Console::setTextColor(Common::Console::Color::Default);

  std::cout << "] Open existing wallet\n [";

  Common::Console::setTextColor(Common::Console::Color::BrightRed);
  std::cout << "2";
  Common::Console::setTextColor(Common::Console::Color::Default);

  std::cout << "] Create new wallet\n [";

  Common::Console::setTextColor(Common::Console::Color::BrightRed);
  std::cout << "3";
  Common::Console::setTextColor(Common::Console::Color::Default);

  std::cout << "] Restore wallet from private keys\n [";

  Common::Console::setTextColor(Common::Console::Color::BrightRed);
  std::cout << "4";
  Common::Console::setTextColor(Common::Console::Color::Default);

  std::cout << "] Exit\n\n";

  // Ask the user to choose option 1, 2, 3, or 4
  do {
    std::string answer;
    std::getline(std::cin, answer);
    c = answer[0];
    if (!(c == '1' || c == '2' || c == '3' || c == '4')) {
      std::cout << "Unknown command : " << c << std::endl << "Please choose 1, 2, 3, or 4\n";
    } else {
      break;
    }
  } while (true);

  
  if (c == '1')
  {
    // Open existing wallet

    bool walletNameValid = false;
    bool passwordCorrect = false;
    bool nodeInitSuccess = false;
    bool loadWalletSuccess = false;

    while (!loadWalletSuccess)
    {
      if (!walletNameValid)
      {
        // Ask the user for wallet name
        std::string walletNameUserInput;
        do {
          std::cout << "Wallet name : ";
          std::getline(std::cin, walletNameUserInput);
          boost::algorithm::trim(walletNameUserInput);
        } while (walletNameUserInput.empty());

        m_walletFileArg = walletNameUserInput;

        // Check that the wallet name exists
        bool walletExists = false;
        while(!walletExists)
        {
          std::string walletFileName;
          WalletHelper::prepareFileNames(walletNameUserInput, walletFileName);
          boost::system::error_code ignore;

          if (!boost::filesystem::exists(walletFileName, ignore)) {
            Common::Console::setTextColor(Common::Console::Color::BrightRed);
            std::cout << "\n" << walletFileName << " does not exist, please try again\n\n";
            Common::Console::setTextColor(Common::Console::Color::Default);
            
            // Ask the user again for the wallet name
            do {
              std::cout << "Wallet name : ";
              std::getline(std::cin, walletNameUserInput);
              boost::algorithm::trim(walletNameUserInput);
            } while (walletNameUserInput.empty());
          }
          else
          {
            m_walletFileArg = walletNameUserInput;
            walletExists = true;
          }
        }

        walletNameValid = true;
      }

      // Ask the user for wallet password
      Tools::PasswordContainer pwd_container;
      if (!passwordCorrect)
      {
        while (!pwd_container.read_password())
        {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read password, please try again";
        }
      }

      // Try to init NodeRPCProxy
      if (!nodeInitSuccess)
      {
        this->m_nodeRpcProxyPtr.reset(new NodeRpcProxy(m_daemonHost, m_daemonPort));

        std::promise<std::error_code> errorPromise;
        std::future<std::error_code> f_error = errorPromise.get_future();
        auto callback = [&errorPromise](std::error_code e) {errorPromise.set_value(e); };

        m_nodeRpcProxyPtr->addObserver(static_cast<INodeRpcProxyObserver*>(this));
        m_nodeRpcProxyPtr->init(callback);
        auto error = f_error.get();
        if (error) {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to initialize NodeRPCProxy : " << error.message();
          return false;
        }

        nodeInitSuccess = true;

        m_walletLegacyPtr.reset(new WalletLegacy(m_currency, *m_nodeRpcProxyPtr));
      }

      // Try to open wallet with password
      try {
        m_walletFilenameWithExtension = tryToOpenWalletOrLoadKeysOrThrow(m_walletFileArg, pwd_container.password());
        loadWalletSuccess = true;
        passwordCorrect = true;
      } catch (const std::exception& e) {
        m_logger(Logging::ERROR, Logging::RED) << "Error : " << e.what() << std::endl;
      } 
    }

    m_walletLegacyPtr->addObserver(this);

    m_logger(Logging::INFO, Logging::BRIGHT_WHITE) << "\nWallet Address\n" << m_walletLegacyPtr->getAddress() << "\n";
    m_logger(Logging::INFO) << "Loading wallet ...\n";
  }
  else if (c == '2')
  {
    // Create new wallet

    bool createNewWalletSuccess = false;
    bool nodeInitSuccess = false;
    while(!createNewWalletSuccess)
    {
      // Ask the user for wallet name
      std::string walletNameUserInput;
      do {
        std::cout << "Wallet name : ";
        std::getline(std::cin, walletNameUserInput);
        boost::algorithm::trim(walletNameUserInput);
      } while (walletNameUserInput.empty());

      m_generateNew = walletNameUserInput;

      std::string walletFileName;

      // Check that wallet name does not already exists
      bool walletNameValid = false;
      while(!walletNameValid)
      {
        WalletHelper::prepareFileNames(m_generateNew, walletFileName);
        boost::system::error_code ignore;

        if (boost::filesystem::exists(walletFileName, ignore)) {
          Common::Console::setTextColor(Common::Console::Color::BrightRed);
          std::cout << "\n" << walletFileName << " already exists, please pick a new wallet name\n\n";
          Common::Console::setTextColor(Common::Console::Color::Default);
          
          // Ask the user again for the wallet name
          do {
            std::cout << "Wallet name : ";
            std::getline(std::cin, walletNameUserInput);
            boost::algorithm::trim(walletNameUserInput);
          } while (walletNameUserInput.empty());

          m_generateNew = walletNameUserInput;
        }
        else
        {
          walletNameValid = true;
        }
      }

      // Ask the user for wallet password
      Tools::PasswordContainer pwd_container;
      while (!pwd_container.read_password())
      {
        m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read password, please try again";
      }
      
      // Ask the user to confirm the password
      bool passwordSuccess = false;
      while(!passwordSuccess)
      {
        while (!pwd_container.read_confirm_password())
        {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read confirm password, please try again";
        }

        if (!pwd_container.passwords_match())
        {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Passwords do not match, please try again\n";

          // ask for the password again
          while (!pwd_container.read_password())
          {
            m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read password, please try again";
          }
        }
        else
        {
          passwordSuccess = true;
        }
      }

      // Try to init NodeRPCProxy
      if (!nodeInitSuccess)
      {
        this->m_nodeRpcProxyPtr.reset(new NodeRpcProxy(m_daemonHost, m_daemonPort));

        std::promise<std::error_code> errorPromise;
        std::future<std::error_code> f_error = errorPromise.get_future();
        auto callback = [&errorPromise](std::error_code e) {errorPromise.set_value(e); };

        m_nodeRpcProxyPtr->addObserver(static_cast<INodeRpcProxyObserver*>(this));
        m_nodeRpcProxyPtr->init(callback);
        auto error = f_error.get();
        if (error) {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to init NodeRPCProxy : " << error.message();
          return false;
        }

        nodeInitSuccess = true;
      }

      // Try to create a new wallet file
      if (!new_wallet(walletFileName, pwd_container.password())) {
        m_logger(Logging::ERROR, Logging::RED) << "Wallet creation failed";
      }
      else
      {
        createNewWalletSuccess = true;
      }
    }
  }
  else if (c == '3')
  {
    // Restore wallet from private keys

    bool restoreWalletSuccess = false;
    bool nodeInitSuccess = false;
    while(!restoreWalletSuccess)
    {
      // Ask the user for wallet name
      std::string walletNameUserInput;
      do {
        std::cout << "Wallet name : ";
        std::getline(std::cin, walletNameUserInput);
        boost::algorithm::trim(walletNameUserInput);
      } while (walletNameUserInput.empty());

      m_generateNew = walletNameUserInput;

      std::string walletFileName;

      // Check that wallet name does not already exists
      bool walletNameValid = false;
      while(!walletNameValid)
      {
        WalletHelper::prepareFileNames(m_generateNew, walletFileName);
        boost::system::error_code errorCodeIgnore;
        if (boost::filesystem::exists(walletFileName, errorCodeIgnore)) {
          Common::Console::setTextColor(Common::Console::Color::BrightRed);
          std::cout << "\n" << walletFileName << " already exists, please pick a new wallet name\n\n";
          Common::Console::setTextColor(Common::Console::Color::Default);
          
          // Ask the user again for the wallet name
          do {
            std::cout << "Wallet name : ";
            std::getline(std::cin, walletNameUserInput);
            boost::algorithm::trim(walletNameUserInput);
          } while (walletNameUserInput.empty());

          m_generateNew = walletNameUserInput;
        }
        else
        {
          walletNameValid = true;
        }
      }

      // Ask the user for wallet password
      Tools::PasswordContainer pwd_container;
      while (!pwd_container.read_password())
      {
        m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read password, please try again";
      }
      
      // Ask the user to confirm the password
      bool passwordSuccess = false;
      while(!passwordSuccess)
      {
        while (!pwd_container.read_confirm_password())
        {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read confirm password, please try again";
        }

        if (!pwd_container.passwords_match())
        {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Passwords do not match, please try again";

          // ask for the password again
          while (!pwd_container.read_password())
          {
            m_logger(Logging::ERROR, Logging::RED) << "Error : Could not read password, please try again";
          }
        }
        else
        {
          passwordSuccess = true;
        }
      }

      // Ask the user for the spend private key
      std::string spendPrivateKeyInput;
      do
      {
        std::cout << "Spend private key : ";
        std::getline(std::cin, spendPrivateKeyInput);
        boost::algorithm::trim(spendPrivateKeyInput);
      } while (spendPrivateKeyInput.empty());
      m_spendPrivateKey = spendPrivateKeyInput;

      // Ask the user for the view private key
      std::string viewPrivateKeyInput;
      do
      {
        std::cout << "View private key : ";
        std::getline(std::cin, viewPrivateKeyInput);
        boost::algorithm::trim(viewPrivateKeyInput);
      } while (viewPrivateKeyInput.empty());
      m_viewPrivateKey = viewPrivateKeyInput;
     
      // Try to init NodeRPCProxy
      if (!nodeInitSuccess)
      {
        this->m_nodeRpcProxyPtr.reset(new NodeRpcProxy(m_daemonHost, m_daemonPort));

        std::promise<std::error_code> errorPromise;
        std::future<std::error_code> f_error = errorPromise.get_future();
        auto callback = [&errorPromise](std::error_code e) {errorPromise.set_value(e); };

        m_nodeRpcProxyPtr->addObserver(static_cast<INodeRpcProxyObserver*>(this));
        m_nodeRpcProxyPtr->init(callback);
        auto error = f_error.get();
        if (error) {
          m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to init NodeRPCProxy : " << error.message();
          return false;
        }

        nodeInitSuccess = true;
      }

      // Try to restore wallet from private keys
      if (!restore_wallet_from_private_keys(walletFileName, pwd_container.password()))
      {
        m_logger(Logging::ERROR, Logging::RED) << "Error : Wallet restore failed, please try again";
      }
      else
      {
        restoreWalletSuccess = true;
      }
    }

  }
  else if (c =='4') {
    // Exit SimpleWalletCommandsHandler
    return false;
  }
  else
  {
    return false;
  }

  return true;
}

bool SimpleWalletCommandsHandler::start_handling()
{
  {
    std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
    while (m_walletLegacySynchronized == false) {
      m_walletLegacySynchronizedCV.wait(lock);
    }
  }

  std::cout << "\n\nType \"help\" to see the list of available commands." << std::endl;

  std::string walletName = Common::RemoveExtension(m_walletFilenameWithExtension).substr(0, 20);
  m_consoleHandler.start(false, "\n[" + walletName + "] : ", Common::Console::Color::BrightYellow);
  return true;
}

void SimpleWalletCommandsHandler::stop_handling()
{
  m_consoleHandler.requestStop();
}


// Private functions


std::string SimpleWalletCommandsHandler::addCommasToBlockHeight(const uint32_t& height)
{
  std::stringstream ss;
  ss.imbue(std::locale(""));
  ss << std::fixed << height;
  return ss.str();
}

bool SimpleWalletCommandsHandler::address(const std::vector<std::string> &args)
{
  m_logger(Logging::INFO) << m_walletLegacyPtr->getAddress();
  return true;
}

bool SimpleWalletCommandsHandler::all_transactions(const std::vector<std::string>& args)
{
  bool validTransactionFound = false;

  size_t walletTransactionsCount = m_walletLegacyPtr->getTransactionCount();
  for (TransactionId transactionNumber = 0; transactionNumber < walletTransactionsCount; ++transactionNumber) {
    WalletLegacyTransaction transaction;
    m_walletLegacyPtr->getTransaction(transactionNumber, transaction);
    if (transaction.state == WalletLegacyTransactionState::Active && transaction.blockIndex != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {

      if (validTransactionFound == false) {
        validTransactionFound = true;
      }

      printTransaction(transaction);
    }
  }

  if (validTransactionFound == false) {
    m_logger(Logging::INFO) << "No transfers found";
  }

  return true;
}

bool SimpleWalletCommandsHandler::balance(const std::vector<std::string>& args)
{
  std::cout << "available balance: " << m_currency.formatAmount(m_walletLegacyPtr->actualBalance()) <<
    ", locked amount: " << m_currency.formatAmount(m_walletLegacyPtr->pendingBalance()) << '\n';

  return true;
}

void SimpleWalletCommandsHandler::connectionStatusUpdated(bool connected)
{
  if (connected)
  {
    m_logger(Logging::INFO, Logging::GREEN) << "Wallet connected to daemon.";
  }
  else
  {
    m_logger(Logging::ERROR, Logging::RED) << "SimpleWallet failed to connect to the daemon";
  }
}

bool SimpleWalletCommandsHandler::exit(const std::vector<std::string> &args)
{
  stop_handling();
  return true;
}

void SimpleWalletCommandsHandler::externalTransactionCreated(TransactionId transactionId) // IWalletLegacyObserver
{
  WalletLegacyTransaction walletLegacyTransaction;
  m_walletLegacyPtr->getTransaction(transactionId, walletLegacyTransaction);
  
  std::stringstream ss;
  if (walletLegacyTransaction.blockIndex == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
    ss << "Unconfirmed";
  } else {
    ss << "Height " << walletLegacyTransaction.blockIndex + 1 << ',';
  }

  if (walletLegacyTransaction.totalAmount >= 0)
  {
    m_logger(Logging::INFO, Logging::GREEN) <<
      ss.str() << " transaction " << Common::podToHex(walletLegacyTransaction.hash) <<
      ", received " << m_currency.formatAmount(walletLegacyTransaction.totalAmount);
  }
  else
  {
    m_logger(Logging::INFO, Logging::MAGENTA) <<
      ss.str() << " transaction " << Common::podToHex(walletLegacyTransaction.hash) <<
      ", spent " << m_currency.formatAmount(static_cast<uint64_t>(-walletLegacyTransaction.totalAmount));
  }

  {
    std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
    if(m_walletLegacySynchronized == false)
    {
      if (walletLegacyTransaction.blockIndex == WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
        updateBlockchainHeight(m_nodeRpcProxyPtr->getLastLocalBlockHeight() + 1, true);
      } else {
        updateBlockchainHeight(walletLegacyTransaction.blockIndex + 1, true);
      }
    }
  }
}

uint64_t SimpleWalletCommandsHandler::getMinimalFee()
{
  if ((m_nodeRpcProxyPtr->getLastKnownBlockHeight() + 1) < CryptoNote::parameters::SOFT_FORK_HEIGHT_1)
  {
    return CryptoNote::parameters::MINIMUM_FEE_1;
  }
  
  return CryptoNote::parameters::MINIMUM_FEE_2;
}

bool SimpleWalletCommandsHandler::height(const std::vector<std::string>& args)
{
  try
  {
    m_logger(Logging::INFO) << addCommasToBlockHeight(m_nodeRpcProxyPtr->getLastLocalBlockHeight() + 1);
  }
  catch (std::exception &e)
  {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to print local blockchain height : " << e.what();
  }

  return true;
}

bool SimpleWalletCommandsHandler::help(const std::vector<std::string> &args)
{
  std::cout << "\nSimpleWallet Commands\n\n" << m_consoleHandler.getUsage();
  return true;
}

bool SimpleWalletCommandsHandler::incoming_transactions(const std::vector<std::string>& args)
{
  bool incomingTransactionFound = false;
  size_t walletTransactionsCount = m_walletLegacyPtr->getTransactionCount();

  for (TransactionId transactionNumber = 0; transactionNumber < walletTransactionsCount; ++transactionNumber) {
    WalletLegacyTransaction transaction;
    m_walletLegacyPtr->getTransaction(transactionNumber, transaction);
    if (transaction.totalAmount > 0)
    {
      if (incomingTransactionFound == false)
      {
        incomingTransactionFound = true;
      }

      printIncomingTransaction(transaction);
    }
  }

  if (incomingTransactionFound == false)
  {
    m_logger(Logging::INFO) << "No incoming transactions";
  }

  return true;
}

std::error_code SimpleWalletCommandsHandler::initAndLoadWallet(IWalletLegacy& walletLegacy, std::istream& walletFile, const std::string& password)
{
  // Initialize the wallet legacy object
  // Check if initializing the wallet legacy object produces an error

  WalletHelper::WalletLegacyInitErrorObserver walletLegacyInitErrorObserver;
  std::future<std::error_code> walletLegacyInitErrorFuture = walletLegacyInitErrorObserver.initErrorCodePromise.get_future();

  // Adds walletLegacyInitErrorObserver as an observer of walletLegacy
  WalletHelper::WalletLegacySmartObserver walletLegacySmartObserver(walletLegacy, walletLegacyInitErrorObserver);

  walletLegacy.initAndLoad(walletFile, password);

  return walletLegacyInitErrorFuture.get();
}

void SimpleWalletCommandsHandler::initCompleted(std::error_code result) // IWalletLegacyObserver
{
  if (m_walletLegacyInitErrorPromisePtr.get() != nullptr) {
    m_walletLegacyInitErrorPromisePtr->set_value(result);
  }
}

bool SimpleWalletCommandsHandler::new_wallet(const std::string &walletFilenameWithExtension, const std::string& password)
{
  m_walletFilenameWithExtension = walletFilenameWithExtension;

  m_walletLegacyPtr.reset(new WalletLegacy(m_currency, *m_nodeRpcProxyPtr.get()));
  m_walletLegacyPtr->addObserver(this);

  try
  {
    m_walletLegacyInitErrorPromisePtr.reset(new std::promise<std::error_code>());
    std::future<std::error_code> walletLegacyInitErrorFuture = m_walletLegacyInitErrorPromisePtr->get_future();
    
    // create new wallet
    m_walletLegacyPtr->initAndGenerate(password);
    
    std::error_code walletLegacyInitErrorCode = walletLegacyInitErrorFuture.get();
    m_walletLegacyInitErrorPromisePtr.reset(nullptr);

    if (walletLegacyInitErrorCode)
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to generate new wallet : " << walletLegacyInitErrorCode.message();
      return false;
    }

    // save new wallet
    try
    {
      WalletHelper::saveWallet(*m_walletLegacyPtr, m_walletFilenameWithExtension);
    }
    catch (std::exception& e)
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to save new wallet : " << e.what();
      throw;
    }

    AccountKeys keys;
    m_walletLegacyPtr->getAccountKeys(keys);

    std::cout <<
      "\nWallet Address\n" << m_walletLegacyPtr->getAddress() << std::endl <<
      "\nSpend Private Key\n" << Common::podToHex(keys.spendSecretKey) << std::endl <<
      "\nView Private Key\n" << Common::podToHex(keys.viewSecretKey) << std::endl <<
      "\nPlease write down and keep both private keys safe\n" << std::endl <<
      "\nWallet files can become corrupted, and the only way to recover the funds will be with the private keys\n" << std::endl;
  }
  catch (const std::exception& e)
  {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to generate new wallet : " << e.what();
    return false;
  }

  m_logger(Logging::INFO) <<
    "Type \"help\" to see a list of available commands.\n" <<
    "Always type \"exit\" to save and close SimpleWallet.\n";
  return true;
}

bool SimpleWalletCommandsHandler::outgoing_transactions(const std::vector<std::string>& args)
{
  bool outgoingTransactionFound = false;
  size_t walletTransactionsCount = m_walletLegacyPtr->getTransactionCount();

  for (TransactionId transactionNumber = 0; transactionNumber < walletTransactionsCount; ++transactionNumber) {
    WalletLegacyTransaction transaction;
    m_walletLegacyPtr->getTransaction(transactionNumber, transaction);
    if (transaction.totalAmount < 0)
    {
      if (outgoingTransactionFound == false)
      {
        outgoingTransactionFound = true;
      }

      printOutgoingTransaction(transaction);
    }
  }

  if (outgoingTransactionFound == false)
  {
    m_logger(Logging::INFO) << "No outgoing transactions";
  }

  return true;
}

bool SimpleWalletCommandsHandler::parseUrlAddress(const std::string& url, std::string& address, uint16_t& port)
{
  size_t pos = url.find("://");
  size_t addrStart = 0;

  if (pos != std::string::npos) {
    addrStart = pos + 3;
  }

  size_t addrEnd = url.find(':', addrStart);

  if (addrEnd != std::string::npos) {
    size_t portEnd = url.find('/', addrEnd);
    port = Common::fromString<uint16_t>(url.substr(
      addrEnd + 1, portEnd == std::string::npos ? std::string::npos : portEnd - addrEnd - 1));
  } else {
    addrEnd = url.find('/');
    port = 80;
  }

  address = url.substr(addrStart, addrEnd - addrStart);
  return true;
}

namespace
{
  const size_t TIMESTAMP_MAX_WIDTH = 36;
  const size_t HASH_MAX_WIDTH = 64;
  const size_t TOTAL_AMOUNT_MAX_WIDTH = 20;
  const size_t FEE_MAX_WIDTH = 14;
  const size_t BLOCK_MAX_WIDTH = 7;
  const size_t UNLOCK_TIME_MAX_WIDTH = 11;
}

bool SimpleWalletCommandsHandler::payments(const std::vector<std::string> &args)
{
  if (args.empty()) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Expected at least one payment ID";
    return true;
  }

  bool paymentsFound = false;
  for (const std::string& paymentIdStr: args)
  {
    Crypto::Hash paymentId;
    if (parsePaymentId(paymentIdStr, paymentId)) // convert paymentId string to paymentId hash
    {
      std::stringstream ss;

      ss << '\n';

      size_t walletTransactionsCount = m_walletLegacyPtr->getTransactionCount();
      for (TransactionId transactionNumber = 0; transactionNumber < walletTransactionsCount; ++transactionNumber) {
        WalletLegacyTransaction transaction;
        m_walletLegacyPtr->getTransaction(transactionNumber, transaction);
        if (transaction.totalAmount > 0) // incoming transaction
        {
          std::vector<uint8_t> transactionExtra(transaction.extra.begin(), transaction.extra.end()); // converts string to vector of uint8_t
          
          Crypto::Hash paymentIdFromTransactionExtra;
          if (getPaymentIdFromTxExtra(transactionExtra, paymentIdFromTransactionExtra) && paymentIdFromTransactionExtra == paymentId) {
            
            if (paymentsFound == false)
            {
              paymentsFound = true;
            }

            char timeString[TIMESTAMP_MAX_WIDTH + 1];
            time_t timestamp = static_cast<time_t>(transaction.timestamp);
            if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
              throw std::runtime_error("time buffer is too small");
            }

            ss <<
              "Received" << '\n' <<
              "Amount : " << m_currency.formatAmount(transaction.totalAmount) << " CASH2" << '\n' <<
              "Timestamp : " << timeString << '\n' <<
              "Transaction hash : " << Common::podToHex(transaction.hash) << '\n' <<
              "Block height : " << addCommasToBlockHeight(transaction.blockIndex + 1) << '\n' <<
              "Payment ID : " << paymentIdFromTransactionExtra << '\n';
          }
        }
      }

      if (paymentsFound == true)
      {
        m_logger(Logging::INFO, Logging::GREEN) << ss.str();
      }
      else
      {
        m_logger(Logging::INFO) << "No payments with id " << paymentId << " found";
      }
    }
    else
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Payment ID has invalid format : \"" << paymentIdStr << "\", expected 64-character string";
    }
  }

  return true;
}

void SimpleWalletCommandsHandler::printIncomingTransaction(const WalletLegacyTransaction& transaction)
{
  std::vector<uint8_t> transactionExtra = Common::asBinaryArray(transaction.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(transactionExtra, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(transaction.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  std::stringstream ss;

  ss << '\n';

  if (transaction.totalAmount >= 0)
  {
    // Received money into your wallet

    ss <<
      "Received" << '\n' <<
      "Amount : " << m_currency.formatAmount(transaction.totalAmount) << " CASH2" << '\n' <<
      "Timestamp : " << timeString << '\n' <<
      "Transaction hash : " << Common::podToHex(transaction.hash) << '\n' <<
      "Block height : " << addCommasToBlockHeight(transaction.blockIndex + 1) << '\n';
  }
  
  if (!paymentIdStr.empty()) {
    ss << "Payment ID : " << paymentIdStr << "\n";
  }

  m_logger(Logging::INFO, Logging::GREEN) << ss.str();
}

void SimpleWalletCommandsHandler::printOutgoingTransaction(const WalletLegacyTransaction& transaction)
{
  std::vector<uint8_t> extraVec = Common::asBinaryArray(transaction.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(transaction.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  std::stringstream ss;

  ss << '\n';

  if (transaction.totalAmount < 0)
  {

    // Sent money out of your wallet

    Crypto::SecretKey transactionPrivateKey = m_walletLegacyPtr->getTxKey(transaction.hash);

    ss <<
      "Sent" << '\n' <<
      "Timestamp : " << timeString << '\n' <<
      "Transaction hash : " << Common::podToHex(transaction.hash) << '\n' <<
      "Transaction private key : " << Common::podToHex(transactionPrivateKey) << '\n' <<
      "Fee : " << m_currency.formatAmount(transaction.fee) << " CASH2" << '\n' <<
      "Block height : " << addCommasToBlockHeight(transaction.blockIndex + 1) << '\n';

    if (transaction.transferCount > 0) {
      for (TransferId id = transaction.firstTransferId; id < transaction.firstTransferId + transaction.transferCount; ++id) {
        WalletLegacyTransfer tr;
        m_walletLegacyPtr->getTransfer(id, tr);

        ss <<
        "Receiver's address : " << tr.address << '\n' <<
        "Amount : " << m_currency.formatAmount(tr.amount) << " CASH2" << '\n';
      }
    }
  }

  if (!paymentIdStr.empty()) {
    ss << "Payment ID : " << paymentIdStr << "\n";
  }

  m_logger(Logging::INFO, Logging::RED) << ss.str();
}

void SimpleWalletCommandsHandler::printTransaction(const WalletLegacyTransaction& transaction)
{
  std::vector<uint8_t> extraVec = Common::asBinaryArray(transaction.extra);

  Crypto::Hash paymentId;
  std::string paymentIdStr = (getPaymentIdFromTxExtra(extraVec, paymentId) && paymentId != NULL_HASH ? Common::podToHex(paymentId) : "");

  char timeString[TIMESTAMP_MAX_WIDTH + 1];
  time_t timestamp = static_cast<time_t>(transaction.timestamp);
  if (std::strftime(timeString, sizeof(timeString), "%b %d, %Y, %A, %I:%M:%S %p", std::gmtime(&timestamp)) == 0) {
    throw std::runtime_error("time buffer is too small");
  }

  std::string rowColor = transaction.totalAmount < 0 ? Logging::RED : Logging::GREEN;

  std::stringstream ss;

  ss << '\n';

  if (transaction.totalAmount >= 0)
  {

    // Received money into your wallet

    ss <<
      "Received" << '\n' <<
      "Amount : " << m_currency.formatAmount(transaction.totalAmount) << " CASH2" << '\n' <<
      "Timestamp : " << timeString << '\n' <<
      "Transaction hash : " << Common::podToHex(transaction.hash) << '\n' <<
      "Block height : " << addCommasToBlockHeight(transaction.blockIndex + 1) << '\n';
  }
  else
  {

    // Sent money out of your wallet

    Crypto::SecretKey transactionPrivateKey = m_walletLegacyPtr->getTxKey(transaction.hash);

    ss <<
      "Sent" << '\n' <<
      "Timestamp : " << timeString << '\n' <<
      "Transaction hash : " << Common::podToHex(transaction.hash) << '\n' <<
      "Transaction private key : " << Common::podToHex(transactionPrivateKey) << '\n' <<
      "Fee : " << m_currency.formatAmount(transaction.fee) << " CASH2" << '\n' <<
      "Block height : " << addCommasToBlockHeight(transaction.blockIndex + 1) << '\n';

    if (transaction.transferCount > 0) {
      for (TransferId id = transaction.firstTransferId; id < transaction.firstTransferId + transaction.transferCount; ++id) {
        WalletLegacyTransfer tr;
        m_walletLegacyPtr->getTransfer(id, tr);

        ss <<
        "Receiver's address : " << tr.address << '\n' <<
        "Amount : " << m_currency.formatAmount(tr.amount) << " CASH2" << '\n';
      }
    }
  }

  if (!paymentIdStr.empty()) {
    ss << "Payment ID : " << paymentIdStr << "\n";
  }

  m_logger(Logging::INFO, rowColor) << ss.str();
}

bool SimpleWalletCommandsHandler::reset(const std::vector<std::string> &args)
{
  {
    std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
    m_walletLegacySynchronized = false;
  }

  m_walletLegacyPtr->reset();
  m_logger(Logging::INFO, Logging::GREEN) << "Reset completed successfully.";

  {
    std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
    while (!m_walletLegacySynchronized) {
      m_walletLegacySynchronizedCV.wait(lock);
    }
  }

  std::cout << std::endl;

  return true;
}

bool SimpleWalletCommandsHandler::restore_wallet_from_private_keys(const std::string &walletFilenameWithExtension, const std::string& password)
{
  m_walletFilenameWithExtension = walletFilenameWithExtension;

  m_walletLegacyPtr.reset(new WalletLegacy(m_currency, *m_nodeRpcProxyPtr.get()));
  m_walletLegacyPtr->addObserver(this);

  if (!std::all_of(m_spendPrivateKey.begin(), m_spendPrivateKey.end(), ::isxdigit) ||
      !std::all_of(m_viewPrivateKey.begin(), m_viewPrivateKey.end(), ::isxdigit))
  {
    return false;
  }

  if(m_spendPrivateKey.length() != 64 || m_viewPrivateKey.length() != 64)
  {
    return false;
  }

  // convert std::string m_spendPrivateKey to Crypto::SecretKey spendPrivateKey
  Crypto::SecretKey spendPrivateKey;
  Common::podFromHex(m_spendPrivateKey, spendPrivateKey);

  // convert std::string m_viewPrivateKey to Crypto::SecretKey viewPrivateKey
  Crypto::SecretKey viewPrivateKey;
  Common::podFromHex(m_viewPrivateKey, viewPrivateKey);

  AccountKeys accountKeys;
  accountKeys.spendSecretKey = spendPrivateKey;
  accountKeys.viewSecretKey = viewPrivateKey;

  Crypto::PublicKey spendPublicKey;
  if(!Crypto::secret_key_to_public_key(spendPrivateKey, spendPublicKey))
  {
    return false;
  }

  Crypto::PublicKey viewPublicKey;
  if(!Crypto::secret_key_to_public_key(viewPrivateKey, viewPublicKey))
  {
    return false;
  }

  accountKeys.address.spendPublicKey = spendPublicKey;
  accountKeys.address.viewPublicKey = viewPublicKey;

  try
  {
    m_walletLegacyInitErrorPromisePtr.reset(new std::promise<std::error_code>());
    std::future<std::error_code> walletLegacyInitErrorFuture = m_walletLegacyInitErrorPromisePtr->get_future();
    
    m_walletLegacyPtr->initWithKeys(accountKeys, password);
    
    std::error_code walletLegacyInitErrorCode = walletLegacyInitErrorFuture.get();
    m_walletLegacyInitErrorPromisePtr.reset(nullptr);
    if (walletLegacyInitErrorCode) {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to restore wallet : " << walletLegacyInitErrorCode.message();
      return false;
    }

    // save new wallet
    try 
    {
      WalletHelper::saveWallet(*m_walletLegacyPtr, m_walletFilenameWithExtension);
    }
    catch (std::exception& e)
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to save restored wallet : " << e.what();
      throw;
    }

    m_walletLegacyPtr->getAccountKeys(accountKeys);

    std::cout <<
      "\nWallet Address\n" << m_walletLegacyPtr->getAddress() << std::endl <<
      "\nView Private Key\n" << Common::podToHex(accountKeys.viewSecretKey) << std::endl <<
      "\nSpend Private Key\n" << Common::podToHex(accountKeys.spendSecretKey) << std::endl <<
      "\nPlease write down and keep both private keys safe\n" << std::endl <<
      "\nWallet files can become corrupted, and the only way to recover the funds will be with the private keys\n" << std::endl;
  }
  catch (const std::exception& e)
  {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to generate new wallet : " << e.what();
    return false;
  }

  m_logger(Logging::INFO) <<
    "Type \"help\" to see a list of available commands.\n" <<
    "Always type \"exit\" to save and close SimpleWallet.\n";
  return true;
}

bool SimpleWalletCommandsHandler::save(const std::vector<std::string> &args)
{
  try
  {
    WalletHelper::saveWallet(*m_walletLegacyPtr, m_walletFilenameWithExtension);
    m_logger(Logging::INFO) << "Wallet saved";
  }
  catch (const std::exception& e)
  {
    m_logger(Logging::ERROR, Logging::RED) << "Error saving wallet : " << e.what();
  }

  return true;
}

bool SimpleWalletCommandsHandler::saveAndCloseWallet()
{
  try
  {
    WalletHelper::saveWallet(*m_walletLegacyPtr, m_walletFilenameWithExtension);
  }
  catch (const std::exception& e)
  {
    m_logger(Logging::ERROR, Logging::RED) << "Error : " << e.what();
    return false;
  }

  m_walletLegacyPtr->shutdown();

  return true;
}

bool SimpleWalletCommandsHandler::send(const std::vector<std::string> &args)
{
  try
  {
    size_t numArgs = args.size();

    if (numArgs != 3 && numArgs != 5)
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Wrong number of arguments given. Please use send <privacy_level> <adreess> <amount> [-p payment_id]";
      return true;
    }

    size_t mixin;
    WalletLegacyTransfer destination;
    std::vector<uint8_t> transactionExtra;

    std::vector<std::string>::const_iterator it = args.begin();


    // get mixin
    std::string mixinStr = *it++;

    if (!Common::fromString(mixinStr, mixin)) {
      m_logger(Logging::ERROR, Logging::RED) << "Mixin should be a positive number, got " << mixinStr;
      return false;
    }

    if (mixin > m_currency.maxMixin()) {
        m_logger(Logging::ERROR, Logging::RED) << "Mixin must be less than " << m_currency.maxMixin() + 1;
        return false;
    }

    // get address
    std::string address = *it++;
    
    TransactionDestinationEntry destinationEntryIgnore;

    if (!m_currency.parseAccountAddressString(address, destinationEntryIgnore.addr)) {
      m_logger(Logging::ERROR, Logging::RED) << "Wrong address : " << address;
      return false;
    }

    destination.address = address;

    // get amount
    std::string amount = *it++;

    TransactionDestinationEntry destinationEntry;

    bool amountValid = m_currency.parseAmount(amount, destinationEntry.amount);

    if (amountValid == false || destinationEntry.amount == 0)
    {
      m_logger(Logging::ERROR, Logging::RED) << "Amount is wrong : " << amount <<
        ", expected number from 0 to " << m_currency.formatAmount(std::numeric_limits<uint64_t>::max());
      return false;
    }

    destination.amount = destinationEntry.amount;

    if (numArgs == 5)
    {
      std::string paymentIdOption = *it++;
      if (paymentIdOption != "-p")
      {
        m_logger(Logging::ERROR, Logging::RED) << "Unexpected option " << paymentIdOption <<
          ", expected -p ";
        return false;
      }

      // get payment id
      std::string paymentId = *it;

      if (!createTxExtraWithPaymentId(paymentId, transactionExtra))
      {
        m_logger(Logging::ERROR, Logging::RED) << "Payment ID has invalid format: \"" << paymentId << "\", expected 64-character string";
        return false;
      }
    }

    WalletHelper::SendCompleteResultObserver sent;
    WalletHelper::WalletLegacySmartObserver walletLegacySmartObserver(*m_walletLegacyPtr, sent);

    std::vector<WalletLegacyTransfer> destinations = {destination};
    uint64_t fee = getMinimalFee();
    std::string transactionExtraStr;
    std::copy(transactionExtra.begin(), transactionExtra.end(), std::back_inserter(transactionExtraStr));
    uint64_t unlockTimestamp = 0;

    TransactionId transactionNumber = m_walletLegacyPtr->sendTransaction(destinations, fee, transactionExtraStr, mixin, unlockTimestamp);

    if (transactionNumber == WALLET_LEGACY_INVALID_TRANSACTION_ID) {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Error sending money";
      return true;
    }

    std::error_code sendError = sent.wait(transactionNumber);
    walletLegacySmartObserver.removeObserver();

    if (sendError) {
      m_logger(Logging::ERROR, Logging::RED) << "Error : " << sendError.message();
      return true;
    }

    WalletLegacyTransaction transaction;
    m_walletLegacyPtr->getTransaction(transactionNumber, transaction);
    m_logger(Logging::INFO, Logging::MAGENTA) << "Money successfully sent, transaction " << Common::podToHex(transaction.hash) << std::endl;

    try {
      WalletHelper::saveWallet(*m_walletLegacyPtr, m_walletFilenameWithExtension);
    } catch (const std::exception& e) {
      m_logger(Logging::ERROR, Logging::RED) << "Error : " << e.what();
      return true;
    }
  } catch (const std::system_error& e) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : " << e.what();
  } catch (const std::exception& e) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : " << e.what();
  } catch (...) {
    m_logger(Logging::ERROR, Logging::RED) << "An unknown error occurred.";
  }

  return true;
}

bool SimpleWalletCommandsHandler::set_log(const std::vector<std::string> &args)
{
  if (args.size() != 1) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Use set_log <0-5>";
    return true;
  }

  uint16_t logLevel = 0;
  if (!Common::fromString(args[0], logLevel)) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Wrong number format, use set_log <0-5>";
    return true;
  }
 
  if (logLevel > Logging::TRACE) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Wrong number range, use set_log <0-5>";
    return true;
  }

  m_loggerManager.setMaxLevel(static_cast<Logging::Level>(logLevel));
  return true;
}

bool SimpleWalletCommandsHandler::spend_private_key(const std::vector<std::string> &args)
{
  AccountKeys accountKeys;
  m_walletLegacyPtr->getAccountKeys(accountKeys);
  Crypto::SecretKey spendPrivateKey = accountKeys.spendSecretKey;
  std::cout << Common::podToHex(spendPrivateKey) << '\n';
  return true;
}

bool SimpleWalletCommandsHandler::start_mining(const std::vector<std::string>& args)
{
  CORE_RPC_COMMAND_START_MINING::request request;

  request.miner_address = m_walletLegacyPtr->getAddress();

  bool validThreadCount = false;
  size_t maxThreads = (std::max)(std::thread::hardware_concurrency(), static_cast<unsigned>(2));
  if (args.size() == 0)
  {
    request.threads_count = 1;
    validThreadCount = true;
  }
  else if (args.size() == 1)
  {
    uint16_t threadsCount;
    if (Common::fromString(args[0], threadsCount) && threadsCount > 0 && threadsCount <= maxThreads)
    {
      validThreadCount = true;
      request.threads_count = threadsCount;
    }
  }

  if (!validThreadCount) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Invalid arguments. Please use start_mining [<number_of_threads>], " <<
      "<number_of_threads> should be from 1 to " << maxThreads;
    return true;
  }

  CORE_RPC_COMMAND_START_MINING::response response;

  try {

    HttpClient httpClient(m_dispatcher, m_daemonHost, m_daemonPort);

    invokeJsonCommand(httpClient, "/start_mining", request, response);

    std::string error;

    if (response.status == CORE_RPC_STATUS_BUSY)
    {
      error = "daemon is busy. Please try later";
    }
    else if (response.status != CORE_RPC_STATUS_OK)
    {
      error = response.status;
    }
    
    if (error.empty())
    {
      m_logger(Logging::INFO) << "Mining started in daemon";
    }
    else
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Mining has NOT been started : " << error;
    }

  } catch (const ConnectException&) {
    m_logger(Logging::ERROR, Logging::RED) << "SimpleWallet failed to connect to the daemon";
  } catch (const std::exception& e) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to invoke RPC method : " << e.what();
  }

  return true;
}

bool SimpleWalletCommandsHandler::stop_mining(const std::vector<std::string>& args)
{
  CORE_RPC_COMMAND_STOP_MINING::request request;
  CORE_RPC_COMMAND_STOP_MINING::response response;

  try {
    HttpClient httpClient(m_dispatcher, m_daemonHost, m_daemonPort);

    invokeJsonCommand(httpClient, "/stop_mining", request, response);

    std::string error;

    if (response.status == CORE_RPC_STATUS_BUSY)
    {
      error = "Daemon is busy. Please try again later";
    }
    else if (response.status != CORE_RPC_STATUS_OK)
    {
      error = response.status;
    }

    if (error.empty())
    {
      m_logger(Logging::INFO) << "Mining stopped in daemon";
    }
    else
    {
      m_logger(Logging::ERROR, Logging::RED) << "Error : Mining has NOT been stopped : " << error;
    }
  } catch (const ConnectException&) {
    m_logger(Logging::ERROR, Logging::RED) << "SimpleWallet failed to connect to the daemon";
  } catch (const std::exception& e) {
    m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to invoke RPC method : " << e.what();
  }

  return true;
}

void SimpleWalletCommandsHandler::synchronizationCompleted(std::error_code result) // IWalletLegacyObserver
{
  std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
  m_walletLegacySynchronized = true;
  m_walletLegacySynchronizedCV.notify_one();
}

void SimpleWalletCommandsHandler::synchronizationProgressUpdated(uint32_t currentHeight, uint32_t total) // IWalletLegacyObserver
{
  std::unique_lock<std::mutex> lock(m_walletLegacySynchronizedMutex);
  if (!m_walletLegacySynchronized) {
    updateBlockchainHeight(currentHeight, false);
  }
}

bool SimpleWalletCommandsHandler::transaction_private_key(const std::vector<std::string> &args)
{
	if (args.size() != 1)
	{
		m_logger(Logging::ERROR, Logging::RED) << "Error : Use get_transaction_private_key <transactionHash>";
		return true;
	}

	const std::string& trasnactionHashStr = args[0];
	Crypto::Hash transactionHash;
	if (!parse_hash256(trasnactionHashStr, transactionHash)) {
		m_logger(Logging::ERROR, Logging::RED) << "Error : Failed to parse transaction hash";
		return true;
	}

	Crypto::SecretKey transactionPrivateKey = m_walletLegacyPtr->getTxKey(transactionHash);
	if (transactionPrivateKey != NULL_SECRET_KEY) {
		std::cout << "transaction private key : " << Common::podToHex(transactionPrivateKey) << std::endl;
		return true;
	}
	else {
		m_logger(Logging::ERROR, Logging::RED) << "Error : No transaction private key found for this transaction";
		return true;
	}
}

std::string SimpleWalletCommandsHandler::tryToOpenWalletOrLoadKeysOrThrow(const std::string& walletFile, const std::string& password)
{
  std::string walletFileName;
  WalletHelper::prepareFileNames(walletFile, walletFileName);

  boost::system::error_code errorCodeIgnore;
  bool walletExists = boost::filesystem::exists(walletFileName, errorCodeIgnore);

  if (!walletExists && boost::filesystem::exists(walletFile, errorCodeIgnore)) {
    boost::system::error_code renameErrorCode;
    boost::filesystem::rename(walletFile, walletFileName, renameErrorCode);
    if (renameErrorCode) {
      throw std::runtime_error("failed to rename file '" + walletFile + "' to '" + walletFileName + "': " + renameErrorCode.message());
    }

    walletExists = true;
  }

  if (walletExists) {
    std::ifstream walletFile;
    walletFile.open(walletFileName, std::ios_base::binary | std::ios_base::in);
    if (walletFile.fail()) {
      throw std::runtime_error("error opening wallet file '" + walletFileName + "'");
    }

    std::error_code initError = initAndLoadWallet(*m_walletLegacyPtr, walletFile, password);

    walletFile.close();

    if (initError) 
    {
      throw std::runtime_error("Error loading wallet file '" + walletFileName + "', please check password\n");
    }

    return walletFileName;
  }
  
  throw std::runtime_error("Wallet file '" + walletFileName + "' was not found");
  
}

void SimpleWalletCommandsHandler::updateBlockchainHeight(uint64_t height, bool force)
{
  std::chrono::time_point<std::chrono::system_clock> currentTime = std::chrono::system_clock::now();

  // update the stored blockchain height
  if (currentTime - m_lastBlockchainHeightUpdateTime >= std::chrono::seconds(m_currency.difficultyTarget() / 2) || m_blockchainHeight <= height) {
    m_blockchainHeight = m_nodeRpcProxyPtr->getLastLocalBlockHeight() + 1;
    m_lastBlockchainHeightUpdateTime = std::chrono::system_clock::now();
    m_blockchainHeight = std::max(m_blockchainHeight, height);
  }

  // print the blockchain height
  if (currentTime - m_lastBlockchainHeightPrintTime >= std::chrono::milliseconds(1) || force) {
    Common::Console::setTextColor(Common::Console::Color::BrightCyan);
    std::cout << "Height " << addCommasToBlockHeight(height) << " of " << addCommasToBlockHeight(m_blockchainHeight) << '\r';
    Common::Console::setTextColor(Common::Console::Color::Default);
    m_lastBlockchainHeightPrintTime = currentTime;
  }

}

bool SimpleWalletCommandsHandler::view_private_key(const std::vector<std::string> &args)
{
  AccountKeys accountKeys;
  m_walletLegacyPtr->getAccountKeys(accountKeys);
  Crypto::SecretKey viewPrivateKey = accountKeys.viewSecretKey;
  std::cout << Common::podToHex(viewPrivateKey) << '\n';
  return true;
}

} // end namespace CryptoNote
