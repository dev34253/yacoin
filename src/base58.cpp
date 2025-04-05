// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2023 The Yacoin core Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encode a byte sequence as a base58-encoded string
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getuint32();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string
std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setuint32((uint32_t)(p1 - pszBase58));
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

// Decode a base58-encoded string str into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

// Encode a byte vector to a base58-encoded string, including checksum
std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

// Decode a base58-encoded string str that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

std::string EncodeDestination(const CTxDestination& dest)
{
    CBitcoinAddress addr(dest);
    if (!addr.IsValid()) return "";
    return addr.ToString();
}

CTxDestination DecodeDestination(const std::string& str)
{
    return CBitcoinAddress(str).Get();
}

bool IsValidDestinationString(const std::string& str)
{
    return CBitcoinAddress(str).IsValid();
}

/** Base class for all base58-encoded data */
CBase58Data::CBase58Data()
{
    nVersion = 0;
    vchData.clear();
}

CBase58Data::~CBase58Data()
{
    // zero the memory, as it may contain sensitive data
    if (!vchData.empty())
        memset(&vchData[0], 0, vchData.size());
}

void CBase58Data::SetData(int nVersionIn, const void* pdata, size_t nSize)
{
    nVersion = nVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CBase58Data::SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
{
    SetData(nVersionIn, (void*)pbegin, pend - pbegin);
}

bool CBase58Data::SetString(const char* psz)
{
    std::vector<unsigned char> vchTemp;
    DecodeBase58Check(psz, vchTemp);
    if (vchTemp.empty())
    {
        vchData.clear();
        nVersion = 0;
        return false;
    }
    nVersion = vchTemp[0];
    vchData.resize(vchTemp.size() - 1);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[1], vchData.size());
    memset(&vchTemp[0], 0, vchTemp.size());
    return true;
}

bool CBase58Data::SetString(const std::string& str)
{
    return SetString(str.c_str());
}

std::string CBase58Data::ToString() const
{
    std::vector<unsigned char> vch(1, nVersion);
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}

int CBase58Data::CompareTo(const CBase58Data& b58) const
{
    if (nVersion < b58.nVersion) return -1;
    if (nVersion > b58.nVersion) return  1;
    if (vchData < b58.vchData)   return -1;
    if (vchData > b58.vchData)   return  1;
    return 0;
}

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
bool CBitcoinAddress::Set(const CKeyID &id) {
    SetData(fTestNet ? PUBKEY_ADDRESS_TEST : PUBKEY_ADDRESS, &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CScriptID &id) {
    SetData(fTestNet ? SCRIPT_ADDRESS_TEST : SCRIPT_ADDRESS, &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CTxDestination &dest)
{
    return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
}

bool CBitcoinAddress::IsValid() const
{
    unsigned int nExpectedSize = 20;
    bool fExpectTestNet = false;
    switch(nVersion)
    {
        case PUBKEY_ADDRESS:
            nExpectedSize = 20; // Hash of public key
            fExpectTestNet = false;
            break;
        case SCRIPT_ADDRESS:
            nExpectedSize = 20; // Hash of CScript
            fExpectTestNet = false;
            break;

        case PUBKEY_ADDRESS_TEST:
            nExpectedSize = 20;
            fExpectTestNet = true;
            break;
        case SCRIPT_ADDRESS_TEST:
            nExpectedSize = 20;
            fExpectTestNet = true;
            break;

        default:
            return false;
    }
    return fExpectTestNet == fTestNet && vchData.size() == nExpectedSize;
}

CBitcoinAddress::CBitcoinAddress()
{
}

CBitcoinAddress::CBitcoinAddress(const CTxDestination &dest)
{
    Set(dest);
}

CBitcoinAddress::CBitcoinAddress(const std::string& strAddress)
{
    SetString(strAddress);
}

CBitcoinAddress::CBitcoinAddress(const char* pszAddress)
{
    SetString(pszAddress);
}

CTxDestination CBitcoinAddress::Get() const {
    if (!IsValid())
        return CNoDestination();
    switch (nVersion) {
    case PUBKEY_ADDRESS:
    case PUBKEY_ADDRESS_TEST: {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        return CKeyID(id);
    }
    case SCRIPT_ADDRESS:
    case SCRIPT_ADDRESS_TEST: {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        return CScriptID(id);
    }
    }
    return CNoDestination();
}

bool CBitcoinAddress::GetKeyID(CKeyID &keyID) const {
    if (!IsValid())
        return false;
    switch (nVersion) {
    case PUBKEY_ADDRESS:
    case PUBKEY_ADDRESS_TEST: {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
        return true;
    }
    default: return false;
    }
}

bool CBitcoinAddress::IsScript() const {
    if (!IsValid())
        return false;
    switch (nVersion) {
    case SCRIPT_ADDRESS:
    case SCRIPT_ADDRESS_TEST: {
        return true;
    }
    default: return false;
    }
}

bool CBitcoinAddress::GetIndexKey(uint160& hashBytes, int& type) const
{
    if (!IsValid()) {
        return false;
    } else if (nVersion == PUBKEY_ADDRESS) {
        memcpy(&hashBytes, &vchData[0], 20);
        type = 1;
        return true;
    } else if (nVersion == SCRIPT_ADDRESS) {
        memcpy(&hashBytes, &vchData[0], 20);
        type = 2;
        return true;
    }

    return false;
}

void CBitcoinSecret::SetKey(const CKey& vchSecret)
{
    Yassert(vchSecret.IsValid());
    SetData(128 + (fTestNet ? CBitcoinAddress::PUBKEY_ADDRESS_TEST : CBitcoinAddress::PUBKEY_ADDRESS), vchSecret.begin(), vchSecret.size());
    if (vchSecret.IsCompressed())
        vchData.push_back(1);
}

CKey CBitcoinSecret::GetKey()
{
    CKey ret;
    ret.Set(&vchData[0], &vchData[32], vchData.size() > 32 && vchData[32] == 1);
    return ret;
}

bool CBitcoinSecret::IsValid() const
{
    bool fExpectTestNet = false;
    switch(nVersion)
    {
        case (128 + CBitcoinAddress::PUBKEY_ADDRESS):
            break;

        case (128 + CBitcoinAddress::PUBKEY_ADDRESS_TEST):
            fExpectTestNet = true;
            break;

        default:
            return false;
    }
    return fExpectTestNet == fTestNet && (vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1));
}

bool CBitcoinSecret::SetString(const char* pszSecret)
{
    return CBase58Data::SetString(pszSecret) && IsValid();
}

bool CBitcoinSecret::SetString(const std::string& strSecret)
{
    return SetString(strSecret.c_str());
}
