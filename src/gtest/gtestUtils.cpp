#include "gtestUtils.h"
#include <script/interpreter.h>

//Includes for semantics checks
//#include <gtest/gtest.h>
//#include "main.h"
//#include <consensus/validation.h>
//End of Includes for semantics checks

CMutableTransaction gtestUtils::populateTx(int txVersion, const uint256 & newScId, const CAmount & fwdTxAmount)
{
    CMutableTransaction mtx;
    mtx.nVersion = txVersion;

    mtx.vin.resize(2);
    mtx.vin[0].prevout.hash = uint256S("1");
    mtx.vin[0].prevout.n = 0;
    mtx.vin[1].prevout.hash = uint256S("2");
    mtx.vin[1].prevout.n = 0;

    mtx.vout.resize(2);
    mtx.vout[0].nValue = 0;
    mtx.vout[1].nValue = 0;

    mtx.vjoinsplit.push_back(
            JSDescription::getNewInstance(txVersion == GROTH_TX_VERSION));
    mtx.vjoinsplit.push_back(
            JSDescription::getNewInstance(txVersion == GROTH_TX_VERSION));
    mtx.vjoinsplit[0].nullifiers.at(0) = uint256S("0");
    mtx.vjoinsplit[0].nullifiers.at(1) = uint256S("1");
    mtx.vjoinsplit[1].nullifiers.at(0) = uint256S("2");
    mtx.vjoinsplit[1].nullifiers.at(1) = uint256S("3");

    mtx.vsc_ccout.resize(1);
    mtx.vsc_ccout[0].scId = newScId;

    mtx.vft_ccout.resize(1);
    mtx.vft_ccout[0].scId = mtx.vsc_ccout[0].scId;
    mtx.vft_ccout[0].nValue = fwdTxAmount;

    return mtx;
}

void gtestUtils::signTx(CMutableTransaction& mtx)
{
    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;
    // Compute the correct hSig.
    // TODO: #966.
    static const uint256 one(uint256S("1"));
    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL);
    if (dataToBeSigned == one) {
        throw std::runtime_error("SignatureHash failed");
    }
    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL, dataToBeSigned.begin(), 32, joinSplitPrivKey ) == 0);
}

CTransaction gtestUtils::createSidechainTxWith(const uint256 & newScId, const CAmount & fwdTxAmount)
{
    CMutableTransaction mtx = populateTx(SC_TX_VERSION, newScId, fwdTxAmount);
    mtx.vout.resize(0);
    mtx.vjoinsplit.resize(0);
    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

CTransaction gtestUtils::createFwdTransferTxWith(const uint256 & newScId, const CAmount & fwdTxAmount)
{
    CMutableTransaction mtx = populateTx(SC_TX_VERSION, newScId, fwdTxAmount);
    mtx.vout.resize(0);
    mtx.vjoinsplit.resize(0);
    mtx.vsc_ccout.resize(0);
    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

CTransaction gtestUtils::createSidechainTxWithNoFwdTransfer(const uint256 & newScId)
{
    CMutableTransaction mtx = populateTx(SC_TX_VERSION, newScId);
    mtx.vout.resize(0);
    mtx.vjoinsplit.resize(0);
    mtx.vft_ccout.resize(0);
    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

// Well-formatted transparent txs have no sc-related info. 
// ccisNull allow you to create a faulty transparent tx, for testing purposes.
CTransaction gtestUtils::createTransparentTx(bool ccIsNull, bool withJoinSplit)
{
    CMutableTransaction mtx = populateTx(TRANSPARENT_TX_VERSION);

    if (!withJoinSplit)
        mtx.vjoinsplit.resize(0);

    if (ccIsNull)
    {
        mtx.vsc_ccout.resize(0);
        mtx.vft_ccout.resize(0);
    }
    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

CTransaction gtestUtils::createSproutTx(bool ccIsNull)
{
    CMutableTransaction mtx;

    if (ccIsNull)
    {
        mtx = populateTx(PHGR_TX_VERSION);
        mtx.vsc_ccout.resize(0);
        mtx.vft_ccout.resize(0);
    } else
    {
        mtx = populateTx(SC_TX_VERSION);
    }
    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

CTransaction gtestUtils::createGrothTx()
{
    CMutableTransaction mtx;

    mtx = populateTx(GROTH_TX_VERSION);
    mtx.vsc_ccout.resize(0);
    mtx.vft_ccout.resize(0);

    signTx(mtx);

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return CTransaction(mtx);
}

void gtestUtils::extendTransaction(CTransaction & tx, const uint256 & scId, const CAmount & amount)
{
    CMutableTransaction mtx = tx;

    mtx.nVersion = SC_TX_VERSION;

    CTxScCreationOut aSidechainCreationTx;
    aSidechainCreationTx.scId = scId;
    mtx.vsc_ccout.push_back(aSidechainCreationTx);

    CTxForwardTransferOut aForwardTransferTx;
    aForwardTransferTx.scId = aSidechainCreationTx.scId;
    aForwardTransferTx.nValue = amount;
    mtx.vft_ccout.push_back(aForwardTransferTx);

    tx = mtx;

    //CValidationState txState;
    //assert(CheckTransactionWithoutProofVerification(mtx, txState));
    return;
}
