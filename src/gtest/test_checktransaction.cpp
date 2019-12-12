#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <sodium.h>

#include "main.h"
#include "primitives/transaction.h"
#include "consensus/validation.h"

TEST(checktransaction_tests, check_vpub_not_both_nonzero) {
    CMutableTransaction tx;
    tx.nVersion = PHGR_TX_VERSION;

    CMutableTransaction newTx(tx);
    CValidationState state;

    newTx.vjoinsplit.push_back(JSDescription());

    JSDescription *jsdesc = &newTx.vjoinsplit[0];
    jsdesc->vpub_old = 1;
    jsdesc->vpub_new = 1;

    EXPECT_FALSE(CheckTransactionWithoutProofVerification(newTx, state));
    EXPECT_EQ(state.GetRejectReason(), "bad-txns-vpubs-both-nonzero");
}

class MockCValidationState : public CValidationState {
public:
    MOCK_METHOD5(DoS, bool(int level, bool ret,
             unsigned char chRejectCodeIn, std::string strRejectReasonIn,
             bool corruptionIn));
    MOCK_METHOD3(Invalid, bool(bool ret,
                 unsigned char _chRejectCode, std::string _strRejectReason));
    MOCK_METHOD1(Error, bool(std::string strRejectReasonIn));
    MOCK_CONST_METHOD0(IsValid, bool());
    MOCK_CONST_METHOD0(IsInvalid, bool());
    MOCK_CONST_METHOD0(IsError, bool());
    MOCK_CONST_METHOD1(IsInvalid, bool(int &nDoSOut));
    MOCK_CONST_METHOD0(CorruptionPossible, bool());
    MOCK_CONST_METHOD0(GetRejectCode, unsigned char());
    MOCK_CONST_METHOD0(GetRejectReason, std::string());
};


CMutableTransaction GetValidTransaction(int txVersion) {
    CMutableTransaction mtx;
	mtx.nVersion = txVersion;
    mtx.vin.resize(2);
    mtx.vin[0].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000001"); //abenegia: are these zeros really necessary?
    mtx.vin[0].prevout.n = 0;
    mtx.vin[1].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    mtx.vin[1].prevout.n = 0;
    mtx.vout.resize(2);
    // mtx.vout[0].scriptPubKey = 
    mtx.vout[0].nValue = 0;
    mtx.vout[1].nValue = 0;

	mtx.vjoinsplit.clear();
	mtx.vjoinsplit.push_back(JSDescription::getNewInstance(txVersion == GROTH_TX_VERSION));
	mtx.vjoinsplit.push_back(JSDescription::getNewInstance(txVersion == GROTH_TX_VERSION));

    mtx.vjoinsplit[0].nullifiers.at(0) = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    mtx.vjoinsplit[0].nullifiers.at(1) = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    mtx.vjoinsplit[1].nullifiers.at(0) = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    mtx.vjoinsplit[1].nullifiers.at(1) = uint256S("0000000000000000000000000000000000000000000000000000000000000003");


    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;

    // Compute the correct hSig.
    // TODO: #966.
    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL);
    if (dataToBeSigned == one) {
        throw std::runtime_error("SignatureHash failed");
    }

    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                         dataToBeSigned.begin(), 32,
                         joinSplitPrivKey
                        ) == 0);
    return mtx;
}

CMutableTransaction GetValidTransaction() {
	return GetValidTransaction(PHGR_TX_VERSION);
}

TEST(checktransaction_tests, valid_transparent_transaction) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit.resize(0);
    mtx.nVersion = 1;
    CTransaction tx(mtx);
    MockCValidationState state;
    EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
}

TEST(checktransaction_tests, valid_sprout_transaction) {
    CMutableTransaction mtx = GetValidTransaction();
    CTransaction tx(mtx);
    MockCValidationState state;
    EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
}

TEST(checktransaction_tests, BadVersionTooLow) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.nVersion = 0;

    CTransaction tx(mtx);
    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-version-too-low", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vin_empty) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit.resize(0);
    mtx.vin.resize(0);

    CTransaction tx(mtx);
    MockCValidationState state;
    EXPECT_CALL(state, DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vout_empty) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit.resize(0);
    mtx.vout.resize(0);

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_oversize) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.nVersion = 1;
    mtx.vjoinsplit.resize(0);
    mtx.vin[0].scriptSig = CScript();
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 190; ++i)
        mtx.vin[0].scriptSig << vchData << OP_DROP;
    mtx.vin[0].scriptSig << OP_1;

    {
        // Transaction is just under the limit...
        CTransaction tx(mtx);
        CValidationState state;
        ASSERT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
    }

    // Not anymore!
    mtx.vin[1].scriptSig << vchData << OP_DROP;
    mtx.vin[1].scriptSig << OP_1;

    {
        CTransaction tx(mtx);
        ASSERT_EQ(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), 100202);
    
        MockCValidationState state;
        EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-oversize", false)).Times(1);
        CheckTransactionWithoutProofVerification(tx, state);
    }
}

TEST(checktransaction_tests, bad_txns_vout_negative) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vout[0].nValue = -1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vout_toolarge) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vout[0].nValue = MAX_MONEY + 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_txouttotal_toolarge_outputs) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vout[0].nValue = MAX_MONEY;
    mtx.vout[1].nValue = 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_txouttotal_toolarge_joinsplit) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vout[0].nValue = 1;
    mtx.vjoinsplit[0].vpub_old = MAX_MONEY;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_txintotal_toolarge_joinsplit) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_new = MAX_MONEY - 1;
    mtx.vjoinsplit[1].vpub_new = MAX_MONEY - 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-txintotal-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vpub_old_negative) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_old = -1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vpub_old-negative", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vpub_new_negative) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_new = -1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vpub_new-negative", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vpub_old_toolarge) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_old = MAX_MONEY + 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vpub_old-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vpub_new_toolarge) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_new = MAX_MONEY + 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vpub_new-toolarge", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_vpubs_both_nonzero) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].vpub_old = 1;
    mtx.vjoinsplit[0].vpub_new = 1;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-vpubs-both-nonzero", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_inputs_duplicate) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vin[1].prevout.hash = mtx.vin[0].prevout.hash;
    mtx.vin[1].prevout.n = mtx.vin[0].prevout.n;

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_joinsplits_nullifiers_duplicate_same_joinsplit) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].nullifiers.at(0) = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    mtx.vjoinsplit[0].nullifiers.at(1) = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_joinsplits_nullifiers_duplicate_different_joinsplit) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit[0].nullifiers.at(0) = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    mtx.vjoinsplit[1].nullifiers.at(0) = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_cb_has_joinsplits) {
    CMutableTransaction mtx = GetValidTransaction();
    // Make it a coinbase.
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    mtx.vjoinsplit.resize(1);

    CTransaction tx(mtx);
    EXPECT_TRUE(tx.IsCoinBase());

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-cb-has-joinsplits", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_cb_empty_scriptsig) {
    CMutableTransaction mtx = GetValidTransaction();
    // Make it a coinbase.
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    mtx.vjoinsplit.resize(0);

    CTransaction tx(mtx);
    EXPECT_TRUE(tx.IsCoinBase());

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-cb-length", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_prevout_null) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vin[1].prevout.SetNull();

    CTransaction tx(mtx);
    EXPECT_FALSE(tx.IsCoinBase());

    MockCValidationState state;
    EXPECT_CALL(state, DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, bad_txns_invalid_joinsplit_signature) {
    CMutableTransaction mtx = GetValidTransaction();
    mtx.joinSplitSig[0] += 1;
    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-invalid-joinsplit-signature", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, non_canonical_ed25519_signature) {
    CMutableTransaction mtx = GetValidTransaction();

    // Check that the signature is valid before we add L
    {
        CTransaction tx(mtx);
        MockCValidationState state;
        EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
    }

    // Copied from libsodium/crypto_sign/ed25519/ref10/open.c
    static const unsigned char L[32] =
      { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

    // Add L to S, which starts at mtx.joinSplitSig[32].
    unsigned int s = 0;
    for (size_t i = 0; i < 32; i++) {
        s = mtx.joinSplitSig[32 + i] + L[i] + (s >> 8);
        mtx.joinSplitSig[32 + i] = s & 0xff;
    }

    CTransaction tx(mtx);

    MockCValidationState state;
    EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-invalid-joinsplit-signature", false)).Times(1);
    CheckTransactionWithoutProofVerification(tx, state);
}

// Test that a Sprout tx with a negative version number is detected
// given the new Overwinter logic
TEST(checktransaction_tests, SproutTxVersionTooLow) {
	SelectParams(CBaseChainParams::REGTEST);
    CMutableTransaction mtx = GetValidTransaction();
    mtx.vjoinsplit.resize(0);
    mtx.nVersion = -1;

    CTransaction tx(mtx);
    MockCValidationState state;

	EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-version-too-low", false)).Times(1);
	CheckTransactionWithoutProofVerification(tx, state);
}

TEST(checktransaction_tests, TransparentTxVersionWithJoinsplit) {
	SelectParams(CBaseChainParams::REGTEST);
	CMutableTransaction mtx = GetValidTransaction(TRANSPARENT_TX_VERSION);
	CTransaction tx(mtx);
	MockCValidationState state;
	EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
	EXPECT_TRUE(ContextualCheckTransaction(tx, state, 1, 100));
	EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-txns-transparent-jsnotempty", false)).Times(1);
	EXPECT_FALSE(ContextualCheckTransaction(tx, state, 200, 100));
}

TEST(checktransaction_tests, GrothTxVersion) {
	SelectParams(CBaseChainParams::REGTEST);
	CMutableTransaction mtx = GetValidTransaction(GROTH_TX_VERSION);
	CTransaction tx(mtx);
	MockCValidationState state;
	EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
	EXPECT_CALL(state, DoS(0, false, REJECT_INVALID, "bad-tx-version-unexpected", false)).Times(1);
	EXPECT_FALSE(ContextualCheckTransaction(tx, state, 1, 100));
	EXPECT_TRUE(ContextualCheckTransaction(tx, state, 200, 100));
}

TEST(checktransaction_tests, PhgrTxVersion) {
	SelectParams(CBaseChainParams::REGTEST);
	CMutableTransaction mtx = GetValidTransaction(PHGR_TX_VERSION);
	CTransaction tx(mtx);
	MockCValidationState state;
	EXPECT_TRUE(CheckTransactionWithoutProofVerification(tx, state));
	EXPECT_TRUE(ContextualCheckTransaction(tx, state, 1, 100));
	EXPECT_CALL(state, DoS(100, false, REJECT_INVALID, "bad-tx-version-unexpected", false)).Times(1);
	EXPECT_FALSE(ContextualCheckTransaction(tx, state, 200, 100));
}

///////////////////////////////////////////////////////////////////////////////
/////////////////////////// SideChain-related tests ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

class CheckSidechainTxTestSuite: public ::testing::Test {

public:
    CheckSidechainTxTestSuite() {};

    ~CheckSidechainTxTestSuite() {};

    void SetUp() override {};

    void TearDown() override {};
};


TEST_F(CheckSidechainTxTestSuite, SideChain_CMutableTransaction_CopyCtor_ScOutputsAreCopied) {
    CMutableTransaction aMutableTx;
    aMutableTx.nVersion = SC_TX_VERSION;

    CTxScCreationOut aSideChainCreationTx;
    aSideChainCreationTx.scId = uint256S("1987");
    aMutableTx.vsc_ccout.push_back(aSideChainCreationTx);

    //prerequisites
    ASSERT_TRUE(aMutableTx.IsScVersion())<<"Test requires at least a side chain tx";
    ASSERT_TRUE(aMutableTx.vsc_ccout.size() != 0)<<"Test requires at least a ScCreationOut inserted";

    //test
    CMutableTransaction aCopyOfMutableTx(aMutableTx);

    //checks
    EXPECT_TRUE(aCopyOfMutableTx.IsScVersion());
    EXPECT_TRUE(aCopyOfMutableTx.vsc_ccout == aMutableTx.vsc_ccout);
}

TEST_F(CheckSidechainTxTestSuite, SideChain_CMutableTransaction_CopyCtor_FwdTransferOutputsAreCopied) {
    CMutableTransaction aMutableTx;
    aMutableTx.nVersion = SC_TX_VERSION;

    CTxForwardTransferOut aForwardTransferTx;
    aForwardTransferTx.scId = uint256S("1987");
    aForwardTransferTx.nValue = CAmount(1999);
    aMutableTx.vft_ccout.push_back(aForwardTransferTx);

    //prerequisites
    ASSERT_TRUE(aMutableTx.IsScVersion())<<"Test requires at least a side chain tx";
    ASSERT_TRUE(aMutableTx.vft_ccout.size() != 0)<<"Test requires at least a CTxForwardTransferOut inserted";

    //test
    CMutableTransaction aCopyOfMutableTx(aMutableTx);

    //checks
    EXPECT_TRUE(aCopyOfMutableTx.IsScVersion());
    EXPECT_TRUE(aCopyOfMutableTx.vft_ccout == aMutableTx.vft_ccout);
}

TEST_F(CheckSidechainTxTestSuite, SideChain_CTransaction_AssignmentOp_ScOutputsAreCopied) {
    CMutableTransaction aMutableTx;
    aMutableTx.nVersion = SC_TX_VERSION;

    CTxScCreationOut aSideChainCreationTx;
    aSideChainCreationTx.scId = uint256S("1987");
    aMutableTx.vsc_ccout.push_back(aSideChainCreationTx);

    CTransaction aTx(aMutableTx);
    CTransaction aCopyOfTx;

    //prerequisites
    ASSERT_TRUE(aTx.IsScVersion())<<"Test requires at least a side chain tx";
    ASSERT_TRUE(aTx.vsc_ccout.size() != 0)<<"Test requires at least a CTxForwardTransferOut inserted";

    //test
    aCopyOfTx = aTx;

    //checks
    EXPECT_TRUE(aCopyOfTx.IsScVersion());
    EXPECT_TRUE(aCopyOfTx.vft_ccout == aTx.vft_ccout);
}

TEST_F(CheckSidechainTxTestSuite, SideChain_CTransaction_AssignmentOp_FwdTransferOutputsAreCopied) {
    CMutableTransaction aMutableTx;
    aMutableTx.nVersion = SC_TX_VERSION;

    CTxForwardTransferOut aForwardTransferTx;
    aForwardTransferTx.scId = uint256S("1987");
    aForwardTransferTx.nValue = CAmount(1999);
    aMutableTx.vft_ccout.push_back(aForwardTransferTx);

    CTransaction aTx(aMutableTx);
    CTransaction aCopyOfTx;

    //prerequisites
    ASSERT_TRUE(aTx.IsScVersion())<<"Test requires at least a side chain tx";
    ASSERT_TRUE(aTx.vft_ccout.size() != 0)<<"Test requires at least a CTxForwardTransferOut inserted";

    //test
    aCopyOfTx = aTx;

    //checks
    EXPECT_TRUE(aCopyOfTx.IsScVersion());
    EXPECT_TRUE(aCopyOfTx.vft_ccout == aTx.vft_ccout);
}

/////////////////////////// CTxForwardTransferOut
TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_DefaultCtorCreatesNullOutput) {
    //test
    CTxForwardTransferOut aNullFwrTransferOutput;

    //checks
    EXPECT_TRUE(aNullFwrTransferOutput.IsNull());
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_AmountSetToMinus1MakesOutputNull) {
    CTxForwardTransferOut aNullFwrTransferOutput(CAmount(-1), uint256S("1989"), uint256S("2008"));

    //prerequisites
    ASSERT_TRUE(aNullFwrTransferOutput.nValue == CAmount(-1))<<"Test requires amount set to -1";
    ASSERT_FALSE(aNullFwrTransferOutput.scId.IsNull())<<"Test requires not null scId";
    ASSERT_FALSE(aNullFwrTransferOutput.address.IsNull())<<"Test requires not null address";


    //test
    bool res = aNullFwrTransferOutput.IsNull();

    //checks
    EXPECT_TRUE(res);
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_NoNegativeAmountMakeOutputNotNull) {
    CTxForwardTransferOut aNullFwrTransferOutput(CAmount(0), uint256S(""), uint256S(""));

    //prerequisites
    ASSERT_TRUE(aNullFwrTransferOutput.nValue > CAmount(-1))<<"Test requires amount set to non negative value";
    ASSERT_TRUE(aNullFwrTransferOutput.scId.IsNull())<<"Test requires null scId";
    ASSERT_TRUE(aNullFwrTransferOutput.address.IsNull())<<"Test requires null address";

    //test
    bool res = aNullFwrTransferOutput.IsNull();

    //checks
    EXPECT_FALSE(res);
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_NegativeAmountMakeOutputNotNull) {
    CTxForwardTransferOut aNullFwrTransferOutput(CAmount(-2), uint256S(""), uint256S(""));

    //prerequisites
    ASSERT_TRUE(aNullFwrTransferOutput.nValue < CAmount(-1))<<"Test requires amount set to negative value different from -1";
    ASSERT_TRUE(aNullFwrTransferOutput.scId.IsNull())<<"Test requires null scId";
    ASSERT_TRUE(aNullFwrTransferOutput.address.IsNull())<<"Test requires null address";

    //test
    bool res = aNullFwrTransferOutput.IsNull();

    //checks
    EXPECT_FALSE(res);
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_CmpOp_ValueAddressAndScIdAreEvaluatedForEqualityAndInequality) {
    CTxForwardTransferOut lhsOut(CAmount(10), uint256S("1912"), uint256S("1789"));
    CTxForwardTransferOut rhsOut(CAmount(10), uint256S("1912"), uint256S("1789"));

    CTxForwardTransferOut rhsOut_OddAmount (CAmount(20), uint256S("1912"), uint256S("1789"));
    CTxForwardTransferOut rhsOut_OddAddress(CAmount(10), uint256S(""),     uint256S("1789"));
    CTxForwardTransferOut rhsOut_OddScId   (CAmount(10), uint256S("1912"), uint256S("1815"));

    //Prerequisites
    ASSERT_TRUE(lhsOut.nValue != rhsOut_OddAmount.nValue);
    ASSERT_TRUE(lhsOut.address != rhsOut_OddAddress.address);
    ASSERT_TRUE(lhsOut.scId != rhsOut_OddScId.scId);

    //test
    bool resEq          = lhsOut == rhsOut;
    bool res_OddAmount  = lhsOut == rhsOut_OddAmount;
    bool res_OddAddress = lhsOut != rhsOut_OddAddress;
    bool res_OddScId    = lhsOut != rhsOut_OddScId;

    //checks
    EXPECT_TRUE(resEq)          <<"Outputs with same amount, address and ScId do not compare equal";
    EXPECT_FALSE(res_OddAmount) <<"Outputs different amounts do compare equal";
    EXPECT_TRUE(res_OddAddress) <<"Outputs different address do compare equal";
    EXPECT_TRUE(res_OddScId)    <<"Outputs different ScId    do compare equal";
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_NonZeroFeeRate_DustThresholdIsThreeTimesFeeForMinimalTxSize) {
    CTxForwardTransferOut anOutput;
    CFeeRate theMinimalFeeRate(CAmount(1000));

    unsigned int minimalOutputSize = GetSerializeSize(SER_DISK,0);
    unsigned int minimalInputSize  = 148u;

    CAmount expectedDustThreshold = 3 * theMinimalFeeRate.GetFee(minimalInputSize + minimalOutputSize);

    //prerequisites
    ASSERT_TRUE(theMinimalFeeRate.GetFeePerK() != 0)<<"Test requires non-zero feeRate";

     //test
    CAmount dustThreshold = anOutput.GetDustThreshold(theMinimalFeeRate);

    //checks
    EXPECT_TRUE(dustThreshold == expectedDustThreshold)
        <<"expected dust threshold was "<< expectedDustThreshold
        <<", while return value is "<<dustThreshold;
}

TEST_F(CheckSidechainTxTestSuite, CTxForwardTransferOut_ZeroFeeRate_DustThresholdIsThreeTimesFeeForMinimalTxSize) {
    CTxForwardTransferOut anOutput;
    CFeeRate theMinimalFeeRate;

    unsigned int minimalOutputSize = GetSerializeSize(SER_DISK,0);
    unsigned int minimalInputSize  = 148u;

    CAmount expectedDustThreshold = 3 * theMinimalFeeRate.GetFee(minimalInputSize + minimalOutputSize);

    //prerequisites
    ASSERT_TRUE(theMinimalFeeRate.GetFeePerK() == 0)<<"Test requires zero feeRate";

     //test
    CAmount dustThreshold = anOutput.GetDustThreshold(theMinimalFeeRate);

    //checks
    EXPECT_TRUE(dustThreshold == expectedDustThreshold)
        <<"expected dust threshold was "<< expectedDustThreshold
        <<", while return value is "<<dustThreshold;
}

//TEST_F(CheckSidechainTxTestSuite, IsDustCompareAmountWithDustThreshold) {
//    CFeeRate targetFeeRate(14);
//    CTxForwardTransferOut anOutputAboveDust(CAmount(7), uint256S(""), uint256S(""));
//    CTxForwardTransferOut anOutputAtDust(CAmount(6), uint256S(""), uint256S(""));
//    CTxForwardTransferOut anOutputBelowDust(CAmount(5), uint256S(""), uint256S(""));
//
//    //prerequisites
//    ASSERT_TRUE(anOutputAboveDust.nValue > targetFeeRate.GetFeePerK());
//    ASSERT_TRUE(anOutputAtDust.nValue == targetFeeRate.GetFeePerK());
//    ASSERT_TRUE(anOutputBelowDust.nValue < targetFeeRate.GetFeePerK());
//
//    //test
//    bool resAbove = anOutputAboveDust.IsDust(targetFeeRate);
//    bool resAt = anOutputAtDust.IsDust(targetFeeRate);
//    bool resBelow = anOutputBelowDust.IsDust(targetFeeRate);
//
//    //checks
//    EXPECT_FALSE(resAbove);
//    EXPECT_TRUE(resAt);
//    EXPECT_TRUE(resBelow);
//}

