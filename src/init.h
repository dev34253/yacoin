// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#ifndef BITCOIN_WALLET_H
 #include "wallet.h"
#endif

class CScheduler;

namespace boost
{
class thread_group;
} // namespace boost

extern ::int64_t 
    nLongAverageBP2000,
    nLongAverageBP1000,
    nLongAverageBP200, 
    nLongAverageBP100, 
    nLongAverageBP;

extern CWallet* pwalletMain;
extern std::string strWalletFileName;

/** Interrupt threads */
void Interrupt(boost::thread_group& threadGroup);
void StartShutdown();
void Shutdown(void* parg);
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler);
std::string HelpMessage();

#endif
