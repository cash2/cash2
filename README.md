# Cash2 - Cash Version 2

https://cash2.org

Welcome to the Cash2 repository on GitHub.

Cash2 is a new cryptocurrency with all the useful properties of cash but with added beneficial features.

Launch date : December 5, 2018 9:00 am EST

## Key Highlights of Cash2
- 9 second block time
- Low transaction fees
- No premine
- BLAKE2b hashing algorithm
- 15,000,000 maximum supply
- CryptoNote based
- Recommended mining hardware is the Innosilicon S11 SiaMaster

[Whitepaper](https://cash2.org/Cash2+Whitepaper+English+11012018.pdf)

Recommended Mining Hardware  
Innosilicon S11 SiaMaster  
[APW7 by Bitmain](https://shop.bitmain.com/product/detail?pid=000201809111802447941Bf38AO30604)

Contact  
Paul Aphivantrakul  
cash2@protonmail.com

YouTube  
https://www.youtube.com/channel/UCJ79rbHYc2tFJ-pL-v9guaw

Reddit  
https://www.reddit.com/r/Cash2/

Twitter  
https://twitter.com/cash2org

Paper Wallet  
https://cash2.org/#paperWallet

USA East Mining Pool  
https://pool1.cash2.org

Block Explorer  
https://blocks.cash2.org

## Frequently Asked Questions

**What is Cash2?**  
Cash2 is a new cryptocurrency with all the useful properties of cash but with added beneficial features.
The goal is for Cash2 to become a mainstream digital currency used for day-to-day purchases.

**Is Cash2 a Scam?**  
No. Cash2 will have no premine, and everyone has an equal opportunity to mine, buy, and sell Cash2.

**How Can I Mine Cash2?**  
The Antminer A3 by Bitmain is recommend for mining Cash2.
The Antminer A3 uses the BLAKE2b hashing algorithm.
The price for one Antminer A3 is $39 USD plus shipping.
Please check out our YouTube channel for help with mining.

**How Can I Buy Cash2?**  
Cash2 will be listed on exchanges after it is launched.

**Is Cash2 a Privacy Coin?**  
No. Cash2 provides only a basic level of privacy for improved fungibility.
The focus of Cash2 is towards becoming a mainstream digital currency and not towards absolute privacy.

**Why does Cash2 use BLAKE2b instead of Cryptonight?**  
Fast block times requires a fast hashing algorithm, and BLAKE2b is one of the fastest algorithms available.

## How To Compile from Source

#### Cloning the repository

`$ git clone --recursive https://github.com/cash2/cash2`

#### Linux Ubuntu

- `sudo apt-get install -y build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev`
- `cd <your cash2 directory>`
- `make`

#### Windows (Instructions borrowed from Turtlecoin)

- Install [Visual Studio 2017 Community Edition](https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=Community&rel=15&page=inlineinstall)
- When installing Visual Studio, it is required that you install Desktop development with C++
- Install the latest version of [Boost](https://bintray.com/boostorg/release/download_file?file_path=1.68.0%2Fbinaries%2Fboost_1_68_0-msvc-14.1-64.exe) - Currently Boost 1.68.
- From the start menu, search for 'x64 Native Tools Command Prompt for vs2017'.
- `cd <your cash2 directory>`
- `mkdir build`
- `cd build`
- `set PATH="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin";%PATH%`
- `cmake -G "Visual Studio 15 2017 Win64" .. -DBOOST_ROOT=C:/local/boost_1_68_0`

If you have errors on this step about not being able to find the following static libraries, you may need to update your cmake. Open 'Visual Studio Installer' and click 'Update'.

- `MSBuild Cash2.sln /p:Configuration=Release /m`

The `.exe` files will be in the `src/Release` folder when you are complete.
