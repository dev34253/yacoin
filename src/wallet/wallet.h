// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_WALLET_WALLET_H
#define YACOIN_WALLET_WALLET_H

#include "amount.h"
#include "policy/feerate.h"
#include "streams.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "script/ismine.h"
#include "script/sign.h"
#include "wallet/crypter.h"
#include "wallet/walletdb.h"
//#include "wallet/rpcwallet.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

// TACA: OLD LOGIC BEGIN
#include "primitives/block.h"
#include "primitives/transaction.h"

#include "streams.h"
#include "script/standard.h"
#include "tokens/tokentypes.h"

#include <boost/foreach.hpp>
#include <stdlib.h>
// TACA: OLD LOGIC END

typedef CWallet* CWalletRef;
extern CCriticalSection cs_vpwallets;
extern std::vector<CWalletRef> vpwallets;
extern CWallet* pwalletMain;

/**
 * Settings
 */
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;

static const unsigned int DEFAULT_KEYPOOL_SIZE = 100;
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! -txconfirmtarget default
static const unsigned int DEFAULT_TX_CONFIRM_TARGET = 6;
static const bool DEFAULT_DISABLE_WALLET = false;
extern const char * DEFAULT_WALLET_DAT;

class CBlockIndex;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CScheduler;
class CTxMemPool;
class CBlockPolicyEstimator;
class CWalletTx;
struct FeeCalculation;
enum class FeeEstimateMode;

// TACA: OLD LOGIC BEGIN
extern bool fWalletUnlockMintOnly;
extern bool fConfChange;
class CAccountingEntry;
class COutput;
class CInputCoin;
// TACA: OLD LOGIC END

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_HD = 130000, // Hierarchical key derivation after BIP32 (HD Wallet)

    FEATURE_HD_SPLIT = 139900, // Wallet with HD chain split (change outputs will use m/0'/1'/k)

    FEATURE_LATEST = FEATURE_COMPRPUBKEY // HD is optional, use FEATURE_COMPRPUBKEY as latest version
};

/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;
    bool fInternal; // for change outputs

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn = false); // TODO: TACA support external/internal later

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
        if (ser_action.ForRead()) {
            try {
                READWRITE(fInternal);
            }
            catch (std::ios_base::failure&) {
                /* flag as external address if we can't read the internal boolean
                   (this will be the case for any wallet before the HD chain split version) */
                fInternal = false;
            }
        }
        else {
            READWRITE(fInternal);
        }
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData() : purpose("unknown") {}

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

struct CRecipient
{
    CScript scriptPubKey;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
};

typedef std::map<std::string, std::string> mapValue_t;


static inline void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static inline void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
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

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx
{
private:
  /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    CTransactionRef tx;
    uint256 hashBlock;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CMerkleTx()
    {
        SetTx(MakeTransactionRef());
        Init();
    }

    CMerkleTx(CTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    /** Helper conversion operator to allow passing CMerkleTx where CTransaction is expected.
     *  TODO: adapt callers and remove this operator. */
    operator const CTransaction&() const { return *tx; }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    void SetMerkleBranch(const CBlockIndex* pIndex, int posInBlock);

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet) > 0; }
    int GetBlocksToMaturity() const;
    /** Pass this transaction to the mempool. Fails if absolute fee exceeds absurd fee. */
    bool AcceptToMemoryPool(CValidationState& state);
    bool hashUnset() const { return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); }
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }

    const uint256& GetHash() const { return tx->GetHash(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
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
    /**
     * Key/value map with information about the transaction.
     *
     * The following keys can be read and written through the map and are
     * serialized in the wallet database:
     *
     *     "comment", "to"   - comment strings provided to sendtoaddress,
     *                         sendfrom, sendmany wallet RPCs
     *     "replaces_txid"   - txid (as HexStr) of transaction replaced by
     *                         bumpfee on transaction created by bumpfee
     *     "replaced_by_txid" - txid (as HexStr) of transaction created by
     *                         bumpfee on transaction replaced by bumpfee
     *     "from", "message" - obsolete fields that could be set in UI prior to
     *                         2011 (removed in commit 4d9b223)
     *
     * The following keys are serialized in the wallet database, but shouldn't
     * be read or written through the map (they will be temporarily added and
     * removed from the map during serialization):
     *
     *     "fromaccount"     - serialized strFromAccount value
     *     "n"               - serialized nOrderPos value
     *     "timesmart"       - serialized nTimeSmart value
     *     "spent"           - serialized vfSpent value that existed prior to
     *                         2014 (removed in commit 93a18a3)
     */
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //!< time received by this node
    /**
     * Stable timestamp that never changes, and reflects the order a transaction
     * was added to the wallet. Timestamp is based on the block time for a
     * transaction added as part of a block, or else the time when the
     * transaction was received if it wasn't part of a block, with the timestamp
     * adjusted in both cases so timestamp order matches the order transactions
     * were added to the wallet. More details can be found in
     * CWallet::ComputeTimeSmart().
     */
    unsigned int nTimeSmart;
    /**
     * From me flag is set to 1 for transactions that were created by the wallet
     * on this bitcoin node, and set to 0 for transactions that were created
     * externally and came in through the network or sendrawtransaction RPC.
     */
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //!< position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(nullptr);
    }

    CWalletTx(const CWallet* pwalletIn, CTransactionRef arg) : CMerkleTx(std::move(arg))
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead())
            Init(nullptr);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //!< Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fImmatureCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache, bool fExcludeNotExpiredTimelock) const;
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee,
                    std::string& strSentAccount, const isminefilter& filter,
                    bool fExcludeNotExpiredTimelock=false) const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee,
                    std::string& strSentAccount, const isminefilter& filter,
                    std::list<CTokenOutputEntry>& tokensReceived,
                    std::list<CTokenOutputEntry>& tokensSent,
                    bool fExcludeNotExpiredTimelock=false) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    // True if only scriptSigs are different
    bool IsEquivalentTo(const CWalletTx& tx) const;

    bool InMempool() const;
    bool IsTrusted() const;

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    // RelayWalletTransaction may only be called if fBroadcastTransactions!
    bool RelayWalletTransaction(CConnman* connman);
    std::set<uint256> GetConflicts() const;
};

class CInputCoin {
public:
    CInputCoin(const CWalletTx* walletTx, unsigned int i)
    {
        if (!walletTx)
            throw std::invalid_argument("walletTx should not be null");
        if (i >= walletTx->tx->vout.size())
            throw std::out_of_range("The output index is out of range");

        outpoint = COutPoint(walletTx->GetHash(), i);
        txout = walletTx->tx->vout[i];
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

    /** Whether we know how to spend this output, ignoring the lack of keys */
    bool fSolvable;

    /**
     * Whether this output is considered safe to spend. Unconfirmed transactions
     * from outside keys and unconfirmed replacement transactions are considered
     * unsafe and will not be used to fund new spending transactions.
     */
    bool fSafe;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn, bool fSolvableIn, bool fSafeIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn; fSolvable = fSolvableIn; fSafe = fSafeIn;
    }

    std::string ToString() const;

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
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires=0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};

/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos; //!< position in ordered transaction list
    uint64_t nEntryNo;

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
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(s.GetType(), s.GetVersion());
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), s.GetType(), s.GetVersion());
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

/** A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore
{
private:
    static std::atomic<bool> fFlushScheduled;
    std::atomic<bool> fAbortRescan;
    std::atomic<bool> fScanningWallet;

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

    // stake mining statistics
    ::uint64_t nKernelsTried;
    ::uint64_t nCoinDaysTried;

public:
    std::unique_ptr<CWalletDBWrapper> dbw;
    mutable CCriticalSection cs_wallet;

    /** Get database handle used by this wallet. Ideally this function would
     * not be necessary.
     */
    CWalletDBWrapper& GetDBHandle()
    {
        return *dbw;
    }

    /** Get a name for this wallet for logging/debugging purposes.
     */
    std::string GetName() const
    {
        if (dbw) {
            return dbw->GetName();
        } else {
            return "dummy";
        }
    }

    bool fFileBacked;

    std::set< ::int64_t> setKeyPool;
    // Map from Key ID (for regular keys) or Script ID (for watch-only keys) to
    // key metadata.
    std::map<CTxDestination, CKeyMetadata> mapKeyMetadata;


    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    // Create wallet with dummy database handle
    CWallet(): dbw(new CWalletDBWrapper())
    {
        SetNull();
    }

    // Create wallet with passed-in database handle
    CWallet(std::unique_ptr<CWalletDBWrapper> dbw_in) : dbw(std::move(dbw_in))
    {
        SetNull();
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = nullptr;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
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
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    // Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    // Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CTxDestination& pubKey, const CKeyMetadata &meta);

    bool LoadMinVersion(int nVersion) { nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }
    void UpdateTimeFirstKey(int64_t nCreateTime);

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

    void GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const;
    //! Responsible for reading and validating the -wallet arguments and verifying the wallet database.
    //  This function will perform salvage on the wallet if requested, as long as only one wallet is
    //  being loaded (CWallet::ParameterInteraction forbids -salvagewallet, -zapwallettxes or -upgradewallet with multiwallet).
    static bool Verify();

    /** Increment the next transaction order id
        @return next transaction order id
     */
    ::int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);
    DBErrors ReorderTransactions();

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
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
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
        return (GetDebit(tx, ISMINE_ALL) > 0);
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

    /* Wallets parameter interaction */
    static bool ParameterInteraction();

    /* Initializes the wallet, returns a new CWallet instance or a null pointer in case of an error */
    static CWallet* CreateWalletFromFile(const std::string walletFile);
    static bool InitLoadWallet();
    DBErrors LoadWallet(bool& fFirstRunRet);
    bool BackupWallet(const std::string& strDest);

    /**
     * Wallet post-init setup
     * Gives the wallet a chance to register repetitive tasks and complete post-init tasks
     */
    void postInitProcess(CScheduler& scheduler);

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

extern std::atomic<int64_t> nTimeBestReceived;

#endif // YACOIN_WALLET_WALLET_H
