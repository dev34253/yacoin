// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <string>
#include <vector>

#include <stdlib.h>

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif

#ifndef BITCOIN_UI_INTERFACE_H
 #include "ui_interface.h"
#endif

#ifndef BITCOIN_WALLETDB_H
 #include "walletdb.h"
#endif
#include "streams.h"

static const unsigned int DEFAULT_KEYPOOL_SIZE = 100;

//extern unsigned int nStakeMaxAge;
extern bool fWalletUnlockMintOnly;
extern bool fConfChange;
class CAccountingEntry;
class CWalletTx;
class CReserveKey;
class CInputCoin;
class COutput;
class CCoinControl;

// Set of selected transactions
typedef std::set<std::pair<const CWalletTx*,unsigned int> > CoinsSet;

// Preloaded coins metadata
// (txid, vout.n) => ((txindex, (tx, vout.n)), (block, modifier))
//typedef std::map< std::pair<uint256, unsigned int>, std::pair< std::pair< CTxIndex, std::pair<const CWalletTx*,unsigned int> >, std::pair<CBlock, ::uint64_t> > > MetaMap;
typedef std::map<
                  std::pair<uint256, unsigned int>,     // the unique key
                  std::pair<
                            std::pair<
                                      CTxIndex, 
                                      std::pair<const CWalletTx*,unsigned int> 
                                     >, 
                            std::pair<CBlock, ::uint64_t> 
                           >                            // the value 
                > MetaMap;


/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys
    FEATURE_LATEST = 60000
};

/** A key pool entry */
class CKeyPool
{
public:
    ::int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool()
    {
        nTime = GetTime();
    }

    CKeyPool(const CPubKey& vchPubKeyIn)
    {
        nTime = GetTime();
        vchPubKey = vchPubKeyIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

struct CRecipient
{
    CScript scriptPubKey;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
};

/** A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore
{
private:
	bool SelectCoinsSimple(::int64_t nTargetValue, ::int64_t nMinValue,
			::int64_t nMaxValue, int64_t nSpendTime, int nMinConf,
			std::set<std::pair<const CWalletTx*, unsigned int> > &setCoinsRet,
			::int64_t &nValueRet) const;
    /**
     * Select a set of coins such that nValueRet >= nTargetValue and at least
     * all coins from coinControl are selected; Never select unconfirmed coins
     * if they are not ours
     */
    bool SelectCoins(const CAmount &nTargetValue, int64_t nSpendTime,
            const std::vector<COutput> &vAvailableCoins,
            std::set<CInputCoin> &setCoinsRet, CAmount &nValueRet,
            const CCoinControl *coinControl = NULL) const;
    bool SelectTokens(
        int64_t nSpendTime,
        const std::map<std::string, std::vector<COutput> >& mapAvailableTokens,
        const std::map<std::string, CAmount>& mapTokenTargetValue,
        std::set<CInputCoin>& setCoinsRet,
        std::map<std::string, CAmount>& mapValueRet) const;

    CWalletDB *pwalletdbEncryption, *pwalletdbDecryption;

    // the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    // the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    // selected coins metadata
    std::map<std::pair<uint256, unsigned int>, std::pair<std::pair<CTxIndex, std::pair<const CWalletTx*,unsigned int> >, std::pair<CBlock, uint64_t> > > mapMeta;

    // stake mining statistics
    ::uint64_t nKernelsTried;
    ::uint64_t nCoinDaysTried;

public:
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    std::string strWalletFile;

    std::set< ::int64_t> setKeyPool;
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;


    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CWallet()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        pwalletdbDecryption = NULL;
        nOrderPosNext = 0;
        nKernelsTried = 0;
        nCoinDaysTried = 0;
    }
    CWallet(std::string strWalletFileIn)
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        strWalletFile = strWalletFileIn;
        fFileBacked = true;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        pwalletdbDecryption = NULL;
        nOrderPosNext = 0;
        nKernelsTried = 0;
        nCoinDaysTried = 0;
    }

    std::map<uint256, CWalletTx> mapWallet;
    std::vector<uint256> vMintingWalletUpdated;
    ::int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, std::string> mapAddressBook;

    CPubKey vchDefaultKey;
    ::int64_t nTimeFirstKey;

    // check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { return nWalletMaxVersion >= wf; }

    void AvailableCoinsMinConf(std::vector<COutput>& vCoins, int nConf, ::int64_t nMinValue, ::int64_t nMaxValue) const;

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(std::vector<COutput> &vCoins, bool fOnlySafe = true,
            const CCoinControl *coinControl = NULL,
            const CScript *fromScriptPubKey = NULL,
            bool useExpiredTimelockUTXO = false, const CAmount &nMinimumAmount = 1,
            const CAmount &nMaximumAmount = MAX_MONEY,
            const CAmount &nMinimumSumAmount = MAX_MONEY,
            const uint64_t nMaximumCount = 0, const int nMinDepth = 0,
            const int nMaxDepth = 9999999) const;

    /**
     * Helper function that calls AvailableCoinsAll, used for transfering tokens
     */
    void AvailableTokens(
        std::map<std::string, std::vector<COutput> >& mapTokenCoins,
        bool fOnlySafe = true, const CCoinControl* coinControl = nullptr,
        const CAmount& nMinimumAmount = 1,
        const CAmount& nMaximumAmount = MAX_MONEY,
        const CAmount& nMinimumSumAmount = MAX_MONEY,
        const uint64_t& nMaximumCount = 0, const int& nMinDepth = 0,
        const int& nMaxDepth = 9999999) const;

    /**
     * Helper function that calls AvailableCoinsAll, used to receive all coins,
     * Tokens and YAC
     */
    void AvailableCoinsWithTokens(
        std::vector<COutput>& vCoins,
        std::map<std::string, std::vector<COutput> >& mapTokenCoins,
        bool fOnlySafe = true, const CCoinControl* coinControl = nullptr,
        const CScript *fromScriptPubKey = NULL, bool useExpiredTimelockUTXO = false,
        const CAmount& nMinimumAmount = 1,
        const CAmount& nMaximumAmount = MAX_MONEY,
        const CAmount& nMinimumSumAmount = MAX_MONEY,
        const uint64_t& nMaximumCount = 0, const int& nMinDepth = 0,
        const int& nMaxDepth = 9999999) const;

    /**
     * populate vCoins with vector of available COutputs, and populates vTokenCoins in fWithTokens is set to true.
     */
    void AvailableCoinsAll(std::vector<COutput> &vCoins,
            std::map<std::string, std::vector<COutput> > &mapTokenCoins,
            bool fGetYAC = true, bool fGetTokens = false,
            bool fOnlySafe = true, const CCoinControl *coinControl = nullptr,
            const CScript *fromScriptPubKey = NULL,
            bool useExpiredTimelockUTXO = false, const CAmount &nMinimumAmount = 1,
            const CAmount &nMaximumAmount = MAX_MONEY,
            const CAmount &nMinimumSumAmount = MAX_MONEY,
            const uint64_t &nMaximumCount = 0, const int &nMinDepth = 0,
            const int &nMaxDepth = 9999999) const;

    /**
     * Shuffle and select coins until nTargetValue is reached while avoiding
     * small change; This method is stochastic for some inputs and upon
     * completion the coin set and corresponding actual target value is
     * assembled
     */
    bool SelectCoinsMinConf(const CAmount &nTargetValue, int64_t nSpendTime,
            int nConfMine, int nConfTheirs, std::vector<COutput> vCoins,
            std::set<CInputCoin> &setCoinsRet, CAmount &nValueRet) const;
    bool SelectTokensMinConf(const CAmount& nTargetValue, int64_t nSpendTime,
                             int nConfMine, int nConfTheirs,
                             const std::string& strTokenName,
                             std::vector<COutput> vCoins,
                             std::set<CInputCoin>& setCoinsRet,
                             CAmount& nValueRet) const;

    // keystore implementation
    // Generate a new key
    CPubKey GenerateNewKey();
    // Adds a key to the store, and saves it to disk.
    bool AddKey(const CKey& key);
    // Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key) { return CCryptoKeyStore::AddKey(key); }
    // Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) { nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }

    // Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    // Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) { SetMinVersion(FEATURE_WALLETCRYPT); return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret); }
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    // Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript &dest);
    bool RemoveWatchOnly(const CScript &dest);
    // Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);
    bool DecryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, ::int64_t> &mapKeyBirth) const;


    /** Increment the next transaction order id
        @return next transaction order id
     */
    ::int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap< ::int64_t, TxPair > TxItems;

    /** Get the wallet's activity log
        @return multimap of ordered transactions and accounting entries
        @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    TxItems OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount = "");

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate = false, bool fFindBlock = false);
    bool EraseFromWallet(uint256 hash);
    void ClearOrphans();
    void WalletUpdateSpent(const CTransaction& prevout, bool fBlock = false);
#ifdef WIN32
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false, int nTotalToScan = 0);
#else
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
#endif
//    int ScanForWalletTransaction(const uint256& hashTx);  NA
    void ReacceptWalletTransactions();
    void ResendWalletTransactions();
    ::int64_t GetBalance(bool fExcludeNotExpiredTimelock=false) const;
    ::int64_t GetWatchOnlyBalance() const;
    ::int64_t GetUnconfirmedBalance() const;
    ::int64_t GetUnconfirmedWatchOnlyBalance() const;
    ::int64_t GetImmatureBalance() const;
    ::int64_t GetImmatureWatchOnlyBalance() const;
    ::int64_t GetStake() const;
    ::int64_t GetNewMint() const;
    ::int64_t GetWatchOnlyStake() const;
    ::int64_t GetWatchOnlyNewMint() const;
    bool CreateTransaction(CScript scriptPubKey, ::int64_t nValue,
            CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
            int &nChangePosInOut, std::string &strFailReason,
            const CCoinControl &coinControl,
            const CScript *fromScriptPubKey = NULL,
            bool useExpiredTimelockUTXO = false);

    bool CreateTransaction(const std::vector<CRecipient> &vecSend,
            CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
            int &nChangePosInOut, std::string &strFailReason,
            const CCoinControl &coinControl,
            const CScript *fromScriptPubKey = NULL,
            bool useExpiredTimelockUTXO = false);

    bool CreateTransactionAll(
        const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
        CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
        std::string& strFailReason, const CCoinControl& coinControl,
        const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO, bool fNewToken,
        const CNewToken& token, const CTxDestination destination,
        bool fTransferToken, bool fReissueToken,
        const CReissueToken& reissueToken, const ETokenType& tokenType);

    bool CreateTransactionAll(
        const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
        CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
        std::string& strFailReason, const CCoinControl& coinControl,
        const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO, bool fNewToken,
        const std::vector<CNewToken> tokens, const CTxDestination destination,
        bool fTransferToken, bool fReissueToken,
        const CReissueToken& reissueToken, const ETokenType& tokenType);

    /** YAC_TOKEN START */
    bool CreateTransactionWithTokens(
        const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
        CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
        std::string& strFailReason, const CCoinControl& coinControl,
        const std::vector<CNewToken> tokens, const CTxDestination destination,
        const ETokenType& tokenType);

    bool CreateTransactionWithTransferToken(
        const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
        CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
        std::string& strFailReason, const CCoinControl& coinControl);

    bool CreateTransactionWithReissueToken(
        const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
        CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
        std::string& strFailReason, const CCoinControl& coinControl,
        const CReissueToken& reissueToken, const CTxDestination destination);

    bool CreateNewChangeAddress(CReserveKey& reservekey, CKeyID& keyID,
                                std::string& strFailReason);
    /** YAC_TOKEN END */

    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey);

    void GetStakeStats(float &nKernelsRate, float &nCoinDaysRate);
    void GetStakeWeightFromValue(const ::int64_t& nTime, const ::int64_t& nValue, ::uint64_t& nWeight);
    bool MergeCoins(const ::int64_t& nAmount, const ::int64_t& nMinValue, const ::int64_t& nMaxValue, std::list<uint256>& listMerged);

    std::string SendMoney(CScript scriptPubKey, ::int64_t nValue, CWalletTx& wtxNew, bool fAskFee=false, const CScript* fromScriptPubKey=NULL, bool useExpiredTimelockUTXO = false);
    std::string SendMoneyToDestination(const CTxDestination &address, ::int64_t nValue, CWalletTx& wtxNew, bool fAskFee=false, const CScript* fromScriptPubKey=NULL, bool useExpiredTimelockUTXO = false);

    bool NewKeyPool(unsigned int nSize = 0);
    bool TopUpKeyPool(unsigned int nSize = 0);
    ::int64_t AddReserveKey(const CKeyPool& keypool);
    void ReserveKeyFromKeyPool(::int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(::int64_t nIndex);
    void ReturnKey(::int64_t nIndex);
    bool GetKeyFromPool(CPubKey &key, bool fAllowReuse=true);
    ::int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;
    ScriptMap GetP2SHRedeemScriptMap() const;

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, ::int64_t> GetAddressBalances();

    isminetype IsMine(const CTxIn& txin) const;
    ::int64_t GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const
    {
        return ::IsMine(*this, txout.scriptPubKey);
    }
    bool IsSpendableTimelockUTXO(const CTxOut& txout, txnouttype& retType, uint32_t& retLockDur) const
    {
        return ::IsSpendableTimelockUTXO(*this, txout.scriptPubKey, retType, retLockDur);
    }
    bool IsTimelockUTXOExpired(const CInputCoin& inputCoin, txnouttype utxoType, uint32_t lockDuration) const;

    ::int64_t GetCredit(const CTxOut& txout, const isminefilter& filter) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetCredit() : value out of range");
        return (IsMine(txout) & filter ? txout.nValue : 0);
    }
    bool IsChange(const CTxOut& txout) const;
    ::int64_t GetChange(const CTxOut& txout) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetChange() : value out of range");
        return (IsChange(txout) ? txout.nValue : 0);
    }
    bool IsMine(const CTransaction& tx) const
    {
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
            if (IsMine(txout) && txout.nValue >= 0) // Token UTXO has nValue = 0
                return true;
        return false;
    }
    bool IsFromMe(const CTransaction& tx) const
    {
        return (GetDebit(tx, MINE_ALL) > 0);
    }
    ::int64_t GetDebit(const CTransaction& tx, const isminefilter& filter) const
    {
        ::int64_t nDebit = 0;
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            nDebit += GetDebit(txin, filter);
            if (!MoneyRange(nDebit))
                throw std::runtime_error("CWallet::GetDebit() : value out of range");
        }
        return nDebit;
    }
    ::int64_t GetCredit(const CTransaction& tx, const isminefilter& filter) const
    {
        ::int64_t nCredit = 0;
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
        {
            nCredit += GetCredit(txout, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWallet::GetCredit() : value out of range");
        }
        return nCredit;
    }
    ::int64_t GetChange(const CTransaction& tx) const
    {
        ::int64_t nChange = 0;
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
        {
            nChange += GetChange(txout);
            if (!MoneyRange(nChange))
                throw std::runtime_error("CWallet::GetChange() : value out of range");
        }
        return nChange;
    }
    void SetBestChain(const CBlockLocator& loc);

    DBErrors LoadWallet(bool& fFirstRunRet);

    bool SetAddressBookName(const CTxDestination& address, const std::string& strName);

    bool DelAddressBookName(const CTxDestination& address);

    void UpdatedTransaction(const uint256 &hashTx);

    void PrintWallet(const CBlock& block);

    void Inventory(const uint256 &hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    unsigned int GetKeyPoolSize()
    {
        return (unsigned int)(setKeyPool.size());
    }

    bool GetTransaction(const uint256 &hashTx, CWalletTx& wtx);

    bool SetDefaultKey(const CPubKey &vchPubKey);

    // signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    // change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    // get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { return nWalletVersion; }

    void FixSpentCoins(int& nMismatchSpent, ::int64_t& nBalanceInQuestion, bool fCheckOnly = false);
    void DisableTransaction(const CTransaction &tx);

    /** Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination &address, const std::string &label, bool isMine, ChangeType status)> NotifyAddressBookChanged;

    /** Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx, ChangeType status)> NotifyTransactionChanged;

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;
};

/** A key allocated from the key pool. */
class CReserveKey
{
protected:
    CWallet* pwallet;
    ::int64_t nIndex;
    CPubKey vchPubKey;
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        if (!fShutdown)
            ReturnKey();
    }

    void ReturnKey();
    CPubKey GetReservedKey();
    void KeepKey();
};


typedef std::map<std::string, std::string> mapValue_t;


static void ReadOrderPos(::int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void WriteOrderPos(const ::int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** YAC_TOKEN START */
struct CTokenOutputEntry
{
    txnouttype type;
    std::string tokenName;
    CTxDestination destination;
    CAmount nAmount = 0;
    int vout;
};
/** YAC_TOKEN END */

/** A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    std::vector<CMerkleTx> vtxPrev;
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived;  // time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    std::vector<char> vfSpent; // which outputs are already spent
    ::int64_t nOrderPos;  // position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fWatchDebitCached;
    mutable bool fCreditCached;
    mutable bool fWatchCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable ::int64_t nDebitCached;
    mutable ::int64_t nWatchDebitCached;
    mutable ::int64_t nCreditCached;
    mutable ::int64_t nWatchCreditCached;
    mutable ::int64_t nAvailableCreditCached;
    mutable ::int64_t nImmatureCreditCached;
    mutable ::int64_t nImmatureWatchCreditCached;
    mutable ::int64_t nAvailableWatchCreditCached;
    mutable ::int64_t nChangeCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(const CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        vtxPrev.clear();
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        vfSpent.clear();
        fDebitCached = false;
        fWatchDebitCached = false;
        fCreditCached = false;
        fWatchCreditCached = false;
        fAvailableCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureCreditCached = false;
        fImmatureWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nWatchDebitCached = 0;
        nCreditCached = 0;
        nWatchCreditCached = 0;
        nAvailableCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        CWalletTx* pthis = const_cast<CWalletTx*>(this);
        if (ser_action.ForRead())
            pthis->Init(NULL);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            pthis->mapValue["fromaccount"] = pthis->strFromAccount;

            std::string str;
            BOOST_FOREACH(char f, vfSpent)
            {
                str += (f ? '1' : '0');
                if (f)
                    fSpent = true;
            }
            pthis->mapValue["spent"] = str;

            WriteOrderPos(pthis->nOrderPos, pthis->mapValue);

            if (nTimeSmart)
                pthis->mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            pthis->strFromAccount = pthis->mapValue["fromaccount"];

            if (mapValue.count("spent"))
                BOOST_FOREACH(char c, pthis->mapValue["spent"])
                    pthis->vfSpent.push_back(c != '0');
            else
                pthis->vfSpent.assign(vout.size(), fSpent);

            ReadOrderPos(pthis->nOrderPos, pthis->mapValue);

            pthis->nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(pthis->mapValue["timesmart"]) : 0;
        }

        pthis->mapValue.erase("fromaccount");
        pthis->mapValue.erase("version");
        pthis->mapValue.erase("spent");
        pthis->mapValue.erase("n");
        pthis->mapValue.erase("timesmart");
    }

    // marks certain txout's as spent
    // returns true if any update took place
    bool UpdateSpent(const std::vector<char>& vfNewSpent)
    {
        bool fReturn = false;
        for (unsigned int i = 0; i < vfNewSpent.size(); i++)
        {
            if (i == vfSpent.size())
                break;

            if (vfNewSpent[i] && !vfSpent[i])
            {
                vfSpent[i] = true;
                fReturn = true;
                fAvailableCreditCached = fAvailableWatchCreditCached = false;
            }
        }
        return fReturn;
    }

    // make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = fAvailableWatchCreditCached = false;
        fDebitCached = fWatchDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    void MarkSpent(unsigned int nOut)
    {
        if (nOut >= vout.size())
            throw std::runtime_error("CWalletTx::MarkSpent() : nOut out of range");
        vfSpent.resize(vout.size());
        if (!vfSpent[nOut])
        {
            vfSpent[nOut] = true;
            fAvailableCreditCached = fAvailableWatchCreditCached = false;
        }
    }

    void MarkUnspent(unsigned int nOut)
    {
        if (nOut >= vout.size())
            throw std::runtime_error("CWalletTx::MarkUnspent() : nOut out of range");
        vfSpent.resize(vout.size());
        if (vfSpent[nOut])
        {
            vfSpent[nOut] = false;
            fAvailableCreditCached = fAvailableWatchCreditCached = false;
        }
    }

    bool IsSpent(unsigned int nOut) const
    {
        if (nOut >= vout.size())
            throw std::runtime_error("CWalletTx::IsSpent() : nOut out of range");
        if (nOut >= vfSpent.size())
            return false;
        return (!!vfSpent[nOut]);
    }

    ::int64_t GetDebit(const isminefilter& filter) const
    {
        if (vin.empty())
            return 0;

        ::int64_t nDebit = 0;
        if (filter & MINE_SPENDABLE)
        {
            if (fDebitCached)
                nDebit += nDebitCached;
            else
            {
                nDebitCached = pwallet->GetDebit(*this, MINE_SPENDABLE);
                fDebitCached = true;
                nDebit += nDebitCached;
            }
        }
        if (filter & MINE_WATCH_ONLY)
        {
            if (fWatchDebitCached)
                nDebit += nWatchDebitCached;
            else
            {
                nWatchDebitCached = pwallet->GetDebit(*this, MINE_WATCH_ONLY);
                fWatchDebitCached = true;
                nDebit += nWatchDebitCached;
            }
        }

        return nDebit;
    }

    ::int64_t GetCredit(const isminefilter& filter) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (
            (IsCoinBase() || IsCoinStake()) && 
            (GetBlocksToMaturity() > 0)
           )
            return 0;

        ::int64_t 
            credit = 0;

        {
        // fix win gcc crash in WalletUpdateSpent with addresses holding coins minted the second time
            LOCK(pwallet->cs_wallet);

            if (filter & MINE_SPENDABLE)
            {
            // GetBalance can assume transactions in mapWallet won't change
                if (fCreditCached)
                    credit += nCreditCached;
                else
                {
                    nCreditCached = pwallet->GetCredit(*this, MINE_SPENDABLE);
                    fCreditCached = true;
                    credit += nCreditCached;
                }
            }
            if (filter & MINE_WATCH_ONLY)
            {
                if (fWatchCreditCached)
                    credit += nWatchCreditCached;
                else
                {
                    nWatchCreditCached = pwallet->GetCredit(*this, MINE_WATCH_ONLY);
                    fWatchCreditCached = true;
                    credit += nWatchCreditCached;
                }
            }
        }
        return credit;
    }

    ::int64_t GetImmatureCredit(bool fUseCache=true) const
    {
        if (
            IsCoinBase() && 
            (GetBlocksToMaturity() > 0) && 
            IsInMainChain()
           )
        {
            if (fUseCache && fImmatureCreditCached)
                return nImmatureCreditCached;
            nImmatureCreditCached = pwallet->GetCredit(*this, MINE_SPENDABLE);
            fImmatureCreditCached = true;
            return nImmatureCreditCached;
        }

        return 0;
    }

    ::int64_t GetImmatureWatchOnlyCredit(bool fUseCache=true) const
    {
        if (
            IsCoinBase() && 
            (GetBlocksToMaturity() > 0) && 
            IsInMainChain()
           )
        {
            if (fUseCache && fImmatureWatchCreditCached)
                return nImmatureWatchCreditCached;
            nImmatureWatchCreditCached = pwallet->GetCredit(*this, MINE_WATCH_ONLY);
            fImmatureWatchCreditCached = true;
            return nImmatureWatchCreditCached;
        }

        return 0;
    }


    ::int64_t GetAvailableCredit(bool fUseCache=true, bool fExcludeNotExpiredTimelock=false) const;

    ::int64_t GetAvailableWatchCredit(bool fUseCache=true) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (
            (IsCoinBase() || IsCoinStake()) && 
            (GetBlocksToMaturity() > 0)
           )
            return 0;

        if (fUseCache) 
        {
            if (fAvailableWatchCreditCached)
                return nAvailableWatchCreditCached;
        }

        ::int64_t 
            nCredit = 0;
        for (unsigned int i = 0; i < vout.size(); ++i)
        {
            if (!IsSpent(i))
            {
                const CTxOut 
                    &txout = vout[i];
                nCredit += pwallet->GetCredit(txout, MINE_WATCH_ONLY);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
            }
        }

        nAvailableWatchCreditCached = nCredit;
        fAvailableWatchCreditCached = true;

        return nCredit;
    }

    ::int64_t GetChange() const
    {
        if (fChangeCached)
            return nChangeCached;
        nChangeCached = pwallet->GetChange(*this);
        fChangeCached = true;
        return nChangeCached;
    }

    void GetAmounts(::int64_t& nGeneratedImmature, ::int64_t& nGeneratedMature,
                    std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee,
                    std::string& strSentAccount, const isminefilter& filter,
                    bool fExcludeNotExpiredTimelock=false) const;

    void GetAmounts(::int64_t& nGeneratedImmature, ::int64_t& nGeneratedMature,
                    std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee,
                    std::string& strSentAccount, const isminefilter& filter,
                    std::list<CTokenOutputEntry>& tokensReceived,
                    std::list<CTokenOutputEntry>& tokensSent,
                    bool fExcludeNotExpiredTimelock=false) const;

    void GetAccountAmounts(
                           const std::string& strAccount, 
                           ::int64_t& nGenerated, 
                           ::int64_t& nReceived,
                           ::int64_t& nSent, 
                           ::int64_t& nFee, 
                           const isminefilter& filter,
                           bool fExcludeNotExpiredTimelock=false
                          ) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool IsTrusted() const
    {
        // Quick answer in most cases
        if (!IsFinal())
            return false;
        if (GetDepthInMainChain() >= 1)
            return true;
        if (fConfChange || !IsFromMe(MINE_ALL)) // using wtx's cached debit
            return false;

        // If no confirmations but it's from us, we can still
        // consider it confirmed if all dependencies are confirmed
        std::map<uint256, const CMerkleTx*> mapPrev;
        std::vector<const CMerkleTx*> vWorkQueue;
        vWorkQueue.reserve(vtxPrev.size()+1);
        vWorkQueue.push_back(this);
        for (unsigned int i = 0; i < vWorkQueue.size(); i++)
        {
            const CMerkleTx* ptx = vWorkQueue[i];

            if (!ptx->IsFinal())
                return false;
            if (ptx->GetDepthInMainChain() >= 1)
                continue;
            if (!pwallet->IsFromMe(*ptx))
                return false;

            if (mapPrev.empty())
            {
                BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
                    mapPrev[tx.GetHash()] = &tx;
            }

            BOOST_FOREACH(const CTxIn& txin, ptx->vin)
            {
                if (!mapPrev.count(txin.prevout.COutPointGetHash()))
                    return false;
                vWorkQueue.push_back(mapPrev[txin.prevout.COutPointGetHash()]);
            }
        }

        return true;
    }

    bool WriteToDisk();

    ::int64_t GetTxTime() const;
    int GetRequestCount() const;

    void AddSupportingTransactions(CTxDB& txdb);

    bool AcceptWalletTransaction(CTxDB& txdb);
    bool AcceptWalletTransaction();

    void RelayWalletTransaction(CTxDB& txdb);
    void RelayWalletTransaction();
};

class CInputCoin {
public:
    CInputCoin(const CWalletTx* walletTx, unsigned int i)
    {
        if (!walletTx)
            throw std::invalid_argument("walletTx should not be null");
        if (i >= walletTx->vout.size())
            throw std::out_of_range("The output index is out of range");

        outpoint = COutPoint(walletTx->GetHash(), i);
        txout = walletTx->vout[i];
    }

    COutPoint outpoint;
    CTxOut txout;

    bool operator<(const CInputCoin& rhs) const {
        return outpoint < rhs.outpoint;
    }

    bool operator!=(const CInputCoin& rhs) const {
        return outpoint != rhs.outpoint;
    }

    bool operator==(const CInputCoin& rhs) const {
        return outpoint == rhs.outpoint;
    }
};

class COutput
{
public:
    const CWalletTx *tx;
    int i;
    int nDepth;

    /** Whether we have the private keys to spend this output */
    bool fSpendable;

    /**
     * Whether this output is considered safe to spend. Unconfirmed transactions
     * from outside keys and unconfirmed replacement transactions are considered
     * unsafe and will not be used to fund new spending transactions.
     */
    bool fSafe;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn, bool fSafeIn=true)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn; fSafe = fSafeIn;
    }

    std::string ToString() const
    {
        return strprintf("COutput(%s, %d, %d, %d) [%s]", tx->GetHash().ToString(), i, fSpendable, nDepth, FormatMoney(tx->vout[i].nValue).c_str());
    }

    void print() const
    {
        LogPrintf("%s\n", ToString());
    }
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    ::int64_t nTimeCreated;
    ::int64_t nTimeExpires;
    std::string strComment;
    //// todo: add something to note what created it (user, getnewaddress, change)
    ////   maybe should have a map<string, string> property map

    CWalletKey(::int64_t nExpires=0)
    {
        nTimeCreated = (nExpires ? GetTime() : 0);
        nTimeExpires = nExpires;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(strComment);
    }
};






/** Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(vchPubKey);
    }
};



/** Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    ::int64_t nCreditDebit;
    ::int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    ::int64_t nOrderPos;  // position in ordered transaction list
    ::uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        CAccountingEntry& me = *const_cast<CAccountingEntry*>(this);
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        // Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(strOtherAccount);

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, me.mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(s.GetType(), nVersion);
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(
                            ss.end(), 
                            (_ssExtra.begin()), 
                            (_ssExtra.end())
                         );
                me.strComment.append(ss.str());
            }
        }

        READWRITE(strComment);

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            me.mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(
                                std::vector<char>(
                                            strComment.begin() + nSepPos + 1, 
                                            strComment.end()
                                                 ), 
                                s.GetType(),
                                nVersion
                              );
                ss >> me.mapValue;
                me._ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(me.nOrderPos, me.mapValue);
        }
        if (std::string::npos != nSepPos)
            me.strComment.erase(nSepPos);

        me.mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

//bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);
extern std::atomic<int64_t> nTimeBestReceived;

#endif
