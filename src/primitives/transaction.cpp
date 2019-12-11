// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "librustzcash.h"
#include <boost/foreach.hpp>

// static global check methods, now called by CTransaction instances
#include "main.h"
#include "sc/sidechain.h"
#include "consensus/validation.h"
#include "validationinterface.h"
#include "undo.h"
#include "core_io.h"

JSDescription JSDescription::getNewInstance(bool useGroth) {
	JSDescription js;

	if(useGroth) {
		js.proof = libzcash::GrothProof();
	} else {
		js.proof = libzcash::PHGRProof();
	}

	return js;
}

JSDescription::JSDescription(
    bool makeGrothProof,
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk // payment disclosure
) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor)
{
    std::array<libzcash::Note, ZC_NUM_JS_OUTPUTS> notes;

    proof = params.prove(
        makeGrothProof,
        inputs,
        outputs,
        notes,
        ciphertexts,
        ephemeralKey,
        joinSplitPubKey,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        anchor,
        computeProof,
        esk // payment disclosure
    );
}

JSDescription JSDescription::Randomized(
    bool makeGrothProof,
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    #ifdef __LP64__ // required to build on MacOS due to size_t ambiguity errors
    std::array<uint64_t, ZC_NUM_JS_INPUTS>& inputMap,
    std::array<uint64_t, ZC_NUM_JS_OUTPUTS>& outputMap,
    #else
    std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
    std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
    #endif
    
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk, // payment disclosure
    std::function<int(int)> gen
)
{
    // Randomize the order of the inputs and outputs
    inputMap = {0, 1};
    outputMap = {0, 1};

    assert(gen);

    MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, gen);
    MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, gen);

    return JSDescription(
        makeGrothProof,
        params, joinSplitPubKey, anchor, inputs, outputs,
        vpub_old, vpub_new, computeProof,
        esk // payment disclosure
    );
}

class SproutProofVerifier : public boost::static_visitor<bool>
{
    ZCJoinSplit& params;
    libzcash::ProofVerifier& verifier;
    const uint256& joinSplitPubKey;
    const JSDescription& jsdesc;

public:
    SproutProofVerifier(
        ZCJoinSplit& params,
        libzcash::ProofVerifier& verifier,
        const uint256& joinSplitPubKey,
        const JSDescription& jsdesc
        ) : params(params), jsdesc(jsdesc), verifier(verifier), joinSplitPubKey(joinSplitPubKey) {}

    bool operator()(const libzcash::PHGRProof& proof) const
    {
        return params.verify(
            proof,
            verifier,
            joinSplitPubKey,
            jsdesc.randomSeed,
            jsdesc.macs,
            jsdesc.nullifiers,
            jsdesc.commitments,
            jsdesc.vpub_old,
            jsdesc.vpub_new,
            jsdesc.anchor
        );
    }

    bool operator()(const libzcash::GrothProof& proof) const
    {
        uint256 h_sig = params.h_sig(jsdesc.randomSeed, jsdesc.nullifiers, joinSplitPubKey);

        return librustzcash_sprout_verify(
            proof.begin(),
            jsdesc.anchor.begin(),
            h_sig.begin(),
            jsdesc.macs[0].begin(),
            jsdesc.macs[1].begin(),
            jsdesc.nullifiers[0].begin(),
            jsdesc.nullifiers[1].begin(),
            jsdesc.commitments[0].begin(),
            jsdesc.commitments[1].begin(),
            jsdesc.vpub_old,
            jsdesc.vpub_new
        );
    }
};

bool JSDescription::Verify(
    ZCJoinSplit& params,
    libzcash::ProofVerifier& verifier,
    const uint256& joinSplitPubKey
) const {
    auto pv = SproutProofVerifier(params, verifier, joinSplitPubKey, *this);
    return boost::apply_visitor(pv, proof);
}

uint256 JSDescription::h_sig(ZCJoinSplit& params, const uint256& joinSplitPubKey) const
{
    return params.h_sig(randomSeed, nullifiers, joinSplitPubKey);
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

//----------------------------------------------------------------------------
uint256 CTxForwardTransferOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxForwardTransferOut::ToString() const
{
    return strprintf("CTxForwardTransferOut(nValue=%d.%08d, address=%s, scId=%s)",
        nValue / COIN, nValue % COIN, HexStr(address).substr(0, 30), scId.ToString() );
}

//----------------------------------------------------------------------------
uint256 CTxCertifierLockOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxCertifierLockOut::ToString() const
{
    return strprintf("CTxCertifierLockOut(nValue=%d.%08d, address=%s, scId=%s, activeFromWithdrawalEpoch=%lld",
        nValue / COIN, nValue % COIN, HexStr(address).substr(0, 30), scId.ToString(), activeFromWithdrawalEpoch);
}

//----------------------------------------------------------------------------
uint256 CTxScCreationOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxScCreationOut::ToString() const
{
    return strprintf("CTxScCreationOut(scId=%s, withdrawalEpochLength=%d",
        scId.ToString(), withdrawalEpochLength);
}


CMutableTransactionBase::CMutableTransactionBase() :
    nVersion(TRANSPARENT_TX_VERSION), vout() {}

CMutableTransaction::CMutableTransaction() : CMutableTransactionBase(), nLockTime(0) {}

CMutableTransaction::CMutableTransaction(const CTransaction& tx) :
    vsc_ccout(tx.vsc_ccout), vcl_ccout(tx.vcl_ccout), vft_ccout(tx.vft_ccout), nLockTime(tx.nLockTime),
    vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig)
{
    nVersion = tx.nVersion;
    vin = tx.vin;
    vout = tx.vout;
}
    
uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

//--------------------------------------------------------------------------------------------------------
CTransactionBase::CTransactionBase() :
    nVersion(TRANSPARENT_TX_VERSION), vout() {}

CTransactionBase& CTransactionBase::operator=(const CTransactionBase &tx) {
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    return *this;
}

CTransactionBase::CTransactionBase(const CTransactionBase &tx) : nVersion(TRANSPARENT_TX_VERSION) {
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
}

double CTransactionBase::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    // polymorphic call
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}


CTransaction::CTransaction() :
    CTransactionBase(), vin(),
    vsc_ccout(), vcl_ccout(), vft_ccout(),
    nLockTime(0), vjoinsplit(), joinSplitPubKey(), joinSplitSig() { }

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CTransaction::CTransaction(const CMutableTransaction &tx) :
    vin(tx.vin), vsc_ccout(tx.vsc_ccout), vcl_ccout(tx.vcl_ccout), vft_ccout(tx.vft_ccout),
    nLockTime(tx.nLockTime), vjoinsplit(tx.vjoinsplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig)
{
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    CTransactionBase::operator=(tx);
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxScCreationOut>*>(&vsc_ccout) = tx.vsc_ccout;
    *const_cast<std::vector<CTxCertifierLockOut>*>(&vcl_ccout) = tx.vcl_ccout;
    *const_cast<std::vector<CTxForwardTransferOut>*>(&vft_ccout) = tx.vft_ccout;
    *const_cast<uint32_t*>(&nLockTime) = tx.nLockTime;
    *const_cast<std::vector<JSDescription>*>(&vjoinsplit) = tx.vjoinsplit;
    *const_cast<uint256*>(&joinSplitPubKey) = tx.joinSplitPubKey;
    *const_cast<joinsplit_sig_t*>(&joinSplitSig) = tx.joinSplitSig;
//    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}

CTransaction::CTransaction(const CTransaction &tx) : nLockTime(0)
{
    // call explicitly the copy of members of virtual base class
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    //---
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxScCreationOut>*>(&vsc_ccout) = tx.vsc_ccout;
    *const_cast<std::vector<CTxCertifierLockOut>*>(&vcl_ccout) = tx.vcl_ccout;
    *const_cast<std::vector<CTxForwardTransferOut>*>(&vft_ccout) = tx.vft_ccout;
    *const_cast<uint32_t*>(&nLockTime) = tx.nLockTime;
    *const_cast<std::vector<JSDescription>*>(&vjoinsplit) = tx.vjoinsplit;
    *const_cast<uint256*>(&joinSplitPubKey) = tx.joinSplitPubKey;
    *const_cast<joinsplit_sig_t*>(&joinSplitSig) = tx.joinSplitSig;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
    {
        // polymorphic call
        nTxSize = CalculateSize();
    }
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    for (std::vector<JSDescription>::const_iterator it(vjoinsplit.begin()); it != vjoinsplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    nValueOut += (GetValueCertifierLockCcOut() + GetValueForwardTransferCcOut() );
    return nValueOut;
}

CAmount CTransaction::GetValueCertifierLockCcOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxCertifierLockOut>::const_iterator it(vcl_ccout.begin()); it != vcl_ccout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueCertifierLockCcOut(): value out of range");
    }
    return nValueOut;
}

CAmount CTransaction::GetValueForwardTransferCcOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxForwardTransferOut>::const_iterator it(vft_ccout.begin()); it != vft_ccout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueForwardTransferCcOut(): value out of range");
    }
    return nValueOut;
}

CAmount CTransaction::GetJoinSplitValueIn() const
{
    CAmount nValue = 0;
    for (std::vector<JSDescription>::const_iterator it(vjoinsplit.begin()); it != vjoinsplit.end(); ++it)
    {
        // NB: vpub_new "gives" money to the value pool just as inputs do
        nValue += it->vpub_new;

        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValue))
            throw std::runtime_error("CTransaction::GetJoinSplitValueIn(): value out of range");
    }

    return nValue;
}

bool CTransaction::IsValidLoose() const
{
    return !IsCoinBase();
}

unsigned int CTransaction::CalculateSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;

    if (IsScVersion())
    {
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, vsc_ccout.size=%u, vcl_ccout.size=%u, vft_ccout.size=%u, nLockTime=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            vin.size(),
            vout.size(),
            vsc_ccout.size(),
            vcl_ccout.size(),
            vft_ccout.size(),
            nLockTime);

        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        for (unsigned int i = 0; i < vsc_ccout.size(); i++)
            str += "    " + vsc_ccout[i].ToString() + "\n";
        for (unsigned int i = 0; i < vcl_ccout.size(); i++)
            str += "    " + vcl_ccout[i].ToString() + "\n";
        for (unsigned int i = 0; i < vft_ccout.size(); i++)
            str += "    " + vft_ccout[i].ToString() + "\n";
    }
    else
    {
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
    }
    return str;
}

void CTransaction::getCrosschainOutputs(std::map<uint256, std::vector<uint256> >& map) const
{
    if (!IsScVersion())
    {
        return;
    }

    unsigned int nIdx = 0;
    LogPrint("sc", "%s():%d -getting leaves for vsc out\n", __func__, __LINE__);
    fillCrosschainOutput(vsc_ccout, nIdx, map);

    LogPrint("sc", "%s():%d -getting leaves for vcl out\n", __func__, __LINE__);
    fillCrosschainOutput(vcl_ccout, nIdx, map);

    LogPrint("sc", "%s():%d -getting leaves for vft out\n", __func__, __LINE__);
    fillCrosschainOutput(vft_ccout, nIdx, map);

    LogPrint("sc", "%s():%d - nIdx[%d]\n", __func__, __LINE__, nIdx);
}

//--------------------------------------------------------------------------------------------
// binaries other than zend that are produced in the build, do not call these members and therefore do not
// need linking all of the related symbols. We use this macro as it is already defined with a similar purpose
// in zen-tx binary build configuration
#ifdef BITCOIN_TX
void CTransaction::AddToBlock(CBlock* pblock) const { return; }
CAmount CTransaction::GetValueIn(const CCoinsViewCache& view) const { return 0; }
int CTransaction::GetNumbOfInputs() const { return 0; }
bool CTransaction::CheckInputsLimit(size_t limit, size_t& n) const { return true; }
bool CTransaction::Check(CValidationState& state, libzcash::ProofVerifier& verifier) const { return true; }
bool CTransaction::ContextualCheck(CValidationState& state, int nHeight, int dosLevel) const { return true; }
bool CTransaction::IsStandard(std::string& reason, int nHeight) const { return true; }
bool CTransaction::CheckFinal(int flags) const { return true; }
bool CTransaction::IsApplicableToState() const { return true; }
bool CTransaction::IsAllowedInMempool(CValidationState& state, CTxMemPool& pool) const { return true; }
bool CTransaction::HasNoInputsInMempool(const CTxMemPool& pool) const { return true; }
bool CTransaction::HaveJoinSplitRequirements(const CCoinsViewCache& view) const { return true; }
void CTransaction::HandleJoinSplitCommittments(ZCIncrementalMerkleTree& tree) const { return; };
bool CTransaction::HaveInputs(const CCoinsViewCache& view) const { return true; }
void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache& view, int nHeight) const { return; }
void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache& view, CBlockUndo &undo, int nHeight) const { return; }
bool CTransaction::AreInputsStandard(CCoinsViewCache& view) const { return true; }
unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& view) const { return 0; }
unsigned int CTransaction::GetLegacySigOpCount() const { return 0; }
bool CTransaction::ContextualCheckInputs(CValidationState &state, const CCoinsViewCache &view, bool fScriptChecks,
          const CChain& chain, unsigned int flags, bool cacheStore, const Consensus::Params& consensusParams,
          std::vector<CScriptCheck> *pvChecks) const { return true;}
void CTransaction::SyncWithWallets(const CBlock* pblock) const { }
bool CTransaction::CheckMissingInputs(const CCoinsViewCache &view, bool* pfMissingInputs) const { return true; }
double CTransaction::GetPriority(const CCoinsViewCache &view, int nHeight) const { return 0.0; }
std::string CTransaction::EncodeHex() const { return ""; }

#else
//----- 
void CTransaction::AddToBlock(CBlock* pblock) const 
{
    pblock->vtx.push_back(*this);
}

CAmount CTransaction::GetValueIn(const CCoinsViewCache& view) const
{
    if (IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxIn& ctxin = vin[i];
        nResult += view.GetOutputFor(ctxin).nValue;
    }

    nResult += GetJoinSplitValueIn();

    return nResult;
}

int CTransaction::GetNumbOfInputs() const
{
    return vin.size();
}

bool CTransaction::CheckInputsLimit(size_t limit, size_t& n) const
{
    if (limit > 0) {
        n = vin.size();
        if (n > limit) {
            return false;
        }
    }
    return true;
}

bool CTransaction::Check(CValidationState& state, libzcash::ProofVerifier& verifier) const
{
    return ::CheckTransaction(*this, state, verifier);
}

bool CTransaction::ContextualCheck(CValidationState& state, int nHeight, int dosLevel) const
{
    return ::ContextualCheckTransaction(*this, state, nHeight, dosLevel);
}

bool CTransaction::IsStandard(std::string& reason, int nHeight) const
{
    return ::IsStandardTx(*this, reason, nHeight);
}

bool CTransaction::CheckFinal(int flags) const
{
    return ::CheckFinalTx(*this, flags);
}

bool CTransaction::IsApplicableToState() const
{
    return Sidechain::ScMgr::instance().IsTxApplicableToState(*this);
}
    
bool CTransaction::IsAllowedInMempool(CValidationState& state, CTxMemPool& pool) const
{
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (pool.mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return state.Invalid(error("conflict in mempool"),
                 REJECT_INVALID, "conflict-in-mempool");
        }
    }

    BOOST_FOREACH(const JSDescription &joinsplit, vjoinsplit) {
        BOOST_FOREACH(const uint256 &nf, joinsplit.nullifiers) {
            if (pool.mapNullifiers.count(nf))
            {
                return state.Invalid(error("invalid nullifier in mempool"),
                     REJECT_INVALID, "invalid-nullifier");
            }
        }
    }

    return Sidechain::ScMgr::instance().IsTxAllowedInMempool(pool, *this, state);
}
bool CTransaction::HasNoInputsInMempool(const CTxMemPool& pool) const
{
    for (unsigned int i = 0; i < vin.size(); i++)
        if (pool.exists(vin[i].prevout.hash))
            return false;
    return true;
}

bool CTransaction::HaveJoinSplitRequirements(const CCoinsViewCache& view) const
{
    return view.HaveJoinSplitRequirements(*this);
}

void CTransaction::HandleJoinSplitCommittments(ZCIncrementalMerkleTree& tree) const
{
    BOOST_FOREACH(const JSDescription &joinsplit, vjoinsplit) {
        BOOST_FOREACH(const uint256 &note_commitment, joinsplit.commitments) {
            // Insert the note commitments into our temporary tree.
            tree.append(note_commitment);
        }
    }
}

bool CTransaction::HaveInputs(const CCoinsViewCache& view) const
{
    return view.HaveInputs(*this);
}

void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache& view, int nHeight) const
{
    return ::UpdateCoins(*this, state, view, nHeight);
}

void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache& view, CBlockUndo& blockundo, int nHeight) const
{
    CTxUndo undoDummy;
    if (!IsCoinBase() ) {
        blockundo.vtxundo.push_back(CTxUndo());
    }
    return ::UpdateCoins(*this, state, view, (IsCoinBase() ? undoDummy : blockundo.vtxundo.back()), nHeight);
}

bool CTransaction::AreInputsStandard(CCoinsViewCache& view) const 
{
    return ::AreInputsStandard(*this, view); 
}

unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& view) const 
{
    return ::GetP2SHSigOpCount(*this, view);
}

unsigned int CTransaction::GetLegacySigOpCount() const 
{
    return ::GetLegacySigOpCount(*this);
}

bool CTransaction::ContextualCheckInputs(CValidationState &state, const CCoinsViewCache &view, bool fScriptChecks,
          const CChain& chain, unsigned int flags, bool cacheStore, const Consensus::Params& consensusParams,
          std::vector<CScriptCheck> *pvChecks) const
{
    return ::ContextualCheckInputs(*this, state, view, fScriptChecks, chain, flags, cacheStore, consensusParams, pvChecks);
}

void CTransaction::SyncWithWallets(const CBlock* pblock) const
{
    ::SyncWithWallets(*this, pblock);
}

bool CTransaction::CheckMissingInputs(const CCoinsViewCache &view, bool* pfMissingInputs) const
{
    BOOST_FOREACH(const CTxIn txin, vin)
    {
        if (!view.HaveCoins(txin.prevout.hash))
        {
            if (pfMissingInputs)
            {
                *pfMissingInputs = true;
            }
            LogPrint("mempool", "Dropping txid %s : no coins for vin\n", GetHash().ToString());
            return false;
        }
    }
    return true;
}

double CTransaction::GetPriority(const CCoinsViewCache &view, int nHeight) const
{
#if 0
    if (IsCoinBase())
    {
        return 0.0;
    }

    // Joinsplits do not reveal any information about the value or age of a note, so we
    // cannot apply the priority algorithm used for transparent utxos.  Instead, we just
    // use the maximum priority whenever a transaction contains any JoinSplits.
    // (Note that coinbase transactions cannot contain JoinSplits.)
    // FIXME: this logic is partially duplicated between here and CreateNewBlock in miner.cpp.

    if (getVjoinsplitSize() > 0) {
        return MAX_PRIORITY;
    }

    double dResult = 0.0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        assert(coins);
        if (!coins->IsAvailable(txin.prevout.n)) continue;
        if (coins->nHeight < nHeight) {
            dResult += coins->vout[txin.prevout.n].nValue * (nHeight-coins->nHeight);
        }
    }

    return ComputePriority(dResult);
#else
    return view.GetPriority(*this, nHeight);
#endif
}

std::string CTransaction::EncodeHex() const
{
    return EncodeHexTx(*this);
}

#endif // BITCOIN_TX
