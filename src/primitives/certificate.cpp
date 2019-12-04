#include "primitives/certificate.h"
#include "primitives/block.h"
#include "undo.h"
#include "coins.h"
#include "validationinterface.h"

CScCertificate::CScCertificate() : CTransactionBase(), scId(), totalAmount(), vbt_ccout(), nonce() { }

CScCertificate::CScCertificate(const CMutableScCertificate &cert) :
    scId(cert.scId), totalAmount(cert.totalAmount), vbt_ccout(cert.vbt_ccout), nonce(cert.nonce)
{
    *const_cast<int*>(&nVersion) = cert.nVersion;
    *const_cast<std::vector<CTxOut>*>(&vout) = cert.vout;
    UpdateHash();
}

CScCertificate& CScCertificate::operator=(const CScCertificate &cert) {
    CTransactionBase::operator=(cert);
    *const_cast<uint256*>(&scId) = cert.scId;
    *const_cast<CAmount*>(&totalAmount) = cert.totalAmount;
    *const_cast<std::vector<CTxBackwardTransferCrosschainOut>*>(&vbt_ccout) = cert.vbt_ccout;
    *const_cast<uint256*>(&nonce) = cert.nonce;
    *const_cast<uint256*>(&hash) = cert.hash;
    return *this;
}

void CScCertificate::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

std::string CScCertificate::ToString() const
{
    return strprintf("CScCertificate()");
}

CAmount CScCertificate::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CScCertificate::GetValueOut(): value out of range");
    }
    return nValueOut;
}

CAmount CScCertificate::GetValueBackwardTransferCcOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxBackwardTransferCrosschainOut>::const_iterator it(vbt_ccout.begin()); it != vbt_ccout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CScCertificate::GetValueBackwardTransferCcOut(): value out of range");
    }
    return nValueOut;
}

void CScCertificate::AddToBlock(CBlock* pblock) const
{
    LogPrint("cert", "%s():%d - adding to block cert %s\n",
        __func__, __LINE__, GetHash().ToString());

    pblock->vcert.push_back(*this);
}

CAmount CScCertificate::GetFeeAmount(CAmount /* unused */) const
{
    return (totalAmount - GetValueOut());
}

CMutableScCertificate::CMutableScCertificate() : totalAmount() {}

CMutableScCertificate::CMutableScCertificate(const CScCertificate& cert) :
    scId(cert.scId), totalAmount(cert.totalAmount), vbt_ccout(cert.vbt_ccout), nonce(cert.nonce)
{
    nVersion = cert.nVersion;
    vout = cert.vout;
}

unsigned int CScCertificate::CalculateModifiedSize(unsigned int /* unused nTxSize*/) const
{
    return CalculateSize();
}

unsigned int CScCertificate::CalculateSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

uint256 CMutableScCertificate::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxBackwardTransferCrosschainOut::ToString() const
{
    return strprintf("CTxBackwardTransferCrosschainOut()");
}

uint256 CTxBackwardTransferCrosschainOut::GetHash() const
{
    return SerializeHash(*this);
}

void CScCertificate::UpdateCoins(CValidationState &state, CCoinsViewCache& view, int nHeight) const
{
    CBlockUndo dum;
    UpdateCoins(state, view, dum, nHeight);
}

void CScCertificate::UpdateCoins(CValidationState &state, CCoinsViewCache& inputs, CBlockUndo& blockundo, int nHeight) const
{
    // TODO handle blockundo
    // add outputs
    LogPrint("cert", "%s():%d - adding coins for cert [%s]\n", __func__, __LINE__, GetHash().ToString());
    inputs.ModifyCoins(GetHash())->FromTx(*this, nHeight);
}

//--------------------------------------------------------------------------------------------
// binaries other than zend that are produced in the build, do not call these members and therefore do not
// need linking all of the related symbols. We use this macro as it is already defined with a similar purpose
// in zen-tx binary build configuration
#ifdef BITCOIN_TX
void CScCertificate::SyncWithWallets(const CBlock* pblock) const { return; }
#else
void CScCertificate::SyncWithWallets(const CBlock* pblock) const
{
    LogPrint("cert", "%s():%d - sync with wallet cert[%s]\n", __func__, __LINE__, GetHash().ToString());
    ::SyncWithWallets(*this, pblock);
}
#endif
