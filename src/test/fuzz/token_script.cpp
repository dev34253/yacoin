// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A token script: the input is an output script (scriptPubKey). The target
// runs the token script detection functions of script.h and tokens.h on it,
// the functions that read a token amount from it, and the token decoders of
// tokens.cpp; a decoded token is checked as the node checks one.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "amount.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "tokens/tokens.h"
#include "tokens/tokentypes.h"
#include "uint256.h"

#include <string>

namespace {
void CheckTokenName(const std::string& name)
{
    ETokenType type;
    std::string strError;
    if (IsTokenNameValid(name, type, strError)) {
        (void)GetParentName(name);
    }
    (void)IsTokenNameAnOwner(name);
    (void)IsTokenNameAYatoken(name);
}
} // namespace

FUZZ_TARGET(token_script)
{
    if (buffer.size() > MAX_FUZZ_INPUT_SIZE) return;
    const CScript script(buffer.begin(), buffer.end());

    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    (void)script.IsTokenScript();
    (void)script.IsTokenScript(nType, fIsOwner);
    (void)script.IsTokenScript(nType, fIsOwner, nStartingIndex);
    (void)script.IsNewToken();
    (void)script.IsOwnerToken();
    (void)script.IsReissueToken();
    (void)script.IsTransferToken();

    int nIndex = 0;
    (void)IsScriptNewToken(script);
    (void)IsScriptNewToken(script, nIndex);
    (void)IsScriptNewUniqueToken(script);
    (void)IsScriptNewUniqueToken(script, nIndex);
    (void)IsScriptOwnerToken(script);
    (void)IsScriptOwnerToken(script, nIndex);
    (void)IsScriptReissueToken(script);
    (void)IsScriptReissueToken(script, nIndex);
    (void)IsScriptTransferToken(script);
    (void)IsScriptTransferToken(script, nIndex);

    const CTxOut txout(0, script);
    (void)CheckIssueDataTx(txout);
    (void)CheckOwnerDataTx(txout);
    (void)CheckReissueDataTx(txout);
    (void)CheckTransferOwnerTx(txout);

    CAmount nAmount = 0;
    (void)GetTokenAmountFromScript(script, nAmount);
    (void)AmountFromNewTokenScript(script, nAmount);
    (void)AmountFromTransferScript(script, nAmount);
    (void)AmountFromReissueScript(script, nAmount);
    (void)script.IsUnspendable();

    std::string strName;
    (void)GetTokenInfoFromScript(script, strName, nAmount); // through GetTokenData
    uint160 hashBytes;
    (void)ParseTokenScript(script, hashBytes, strName, nAmount);

    std::string strAddress;
    std::string strError;
    CNewToken token;
    if (TokenFromScript(script, token, strAddress)) {
        CheckTokenName(token.strName);
        (void)CheckNewToken(token, strError);
        if (token.nHasIPFS == 1) (void)CheckEncoded(token.strIPFSHash, strError);
    }
    std::string strOwnerName;
    if (OwnerTokenFromScript(script, strOwnerName, strAddress)) {
        CheckTokenName(strOwnerName);
    }
    CReissueToken reissue;
    if (ReissueTokenFromScript(script, reissue, strAddress)) {
        CheckTokenName(reissue.strName);
        (void)CheckReissueToken(reissue, strError);
        if (!reissue.strIPFSHash.empty()) (void)CheckEncoded(reissue.strIPFSHash, strError);
    }
    CTokenTransfer transfer;
    if (TransferTokenFromScript(script, transfer, strAddress)) {
        CheckTokenName(transfer.strName);
        (void)transfer.IsValid(strError);
    }
}
