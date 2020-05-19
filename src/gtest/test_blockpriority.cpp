#include <gtest/gtest.h>
#include "tx_creation_utils.h"
#include <coins.h>
#include <consensus/validation.h>
#include <main.h>
#include <undo.h>
#include <miner.h>

#include <librustzcash.h>
#include <key.h>
#include <zcash/Zcash.h>
#include <zcash/JoinSplit.hpp>
#include <sodium.h>
#include <script/interpreter.h>
#include <init.h>

extern ZCJoinSplit *pzcashParams;

class BlockPriorityTestSuite: public ::testing::Test {
public:
    BlockPriorityTestSuite(): dummyBackingView() /*,view(&dummyBackingView)*/ ,dummyState(), dummyTxundo(),
                              k(libzcash::SpendingKey::random()),
                              addr(k.address()),
                              note(addr.a_pk, 100, uint256(), uint256())
                              {};

    void SetUp() override {
        SelectParams(CBaseChainParams::REGTEST);

        chainSettingUtils::GenerateChainActive(201);

        pcoinsTip = new CCoinsViewCache(&dummyBackingView);

        uint256 commitment = note.cm();
        merkleTree.append(commitment);
        pcoinsTip->PushAnchor(merkleTree);

        pcoinsTip->SetBestBlock(chainActive.Tip()->GetBlockHash());
        pindexBestHeader = chainActive.Tip();

        fDebug = true;
        fPrintToConsole = true;
        mapMultiArgs["-debug"].push_back("sc");
        mapMultiArgs["-debug"].push_back("mempool");
        mapArgs["-allownonstandardtx"] = "1";
        mapArgs["-deprecatedgetblocktemplate"] = "1";

        //Joinsplit
        boost::filesystem::path pk_path = ZC_GetParamsDir() / "sprout-proving.key";
        boost::filesystem::path vk_path = ZC_GetParamsDir() / "sprout-verifying.key";
        pzcashParams = ZCJoinSplit::Prepared(vk_path.string(), pk_path.string());
        boost::filesystem::path sapling_spend = ZC_GetParamsDir() / "sapling-spend.params";
        boost::filesystem::path sapling_output = ZC_GetParamsDir() / "sapling-output.params";
        boost::filesystem::path sprout_groth16 = ZC_GetParamsDir() / "sprout-groth16.params";

        std::string sapling_spend_str = sapling_spend.string();
        std::string sapling_output_str = sapling_output.string();
        std::string sprout_groth16_str = sprout_groth16.string();

        librustzcash_init_zksnark_params(
            sapling_spend_str.c_str(),
            "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
            sapling_output_str.c_str(),
            "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
            sprout_groth16_str.c_str(),
            "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a"
        );
    };

    void TearDown() override {
        mempool.clear();

        delete pcoinsTip;
        pcoinsTip = nullptr;
    };

    ~BlockPriorityTestSuite() = default;

protected:
    CCoinsView      dummyBackingView;
//    CCoinsViewCache view;

    CValidationState dummyState;
    CTxUndo dummyTxundo;

    CTransaction makeTransparentTx(const CTxIn& input1, const CTxIn& input2, const CTxOut& output1, const CTxOut& output2);

    CTransaction makeJoinSplit(const uint256& jsPubKey);
    ZCIncrementalMerkleTree merkleTree;
    libzcash::SpendingKey k;
    libzcash::PaymentAddress addr;
    libzcash::Note note;
    uint256 commitment;
};

TEST_F(BlockPriorityTestSuite, ShieldedTxFaultyPriorityInBlockFormation)
{
    //Generate coins in Mempool, enough to fill a block
    unsigned int txCounter = 0;
    unsigned int txTotalSize = 0;
    for(unsigned int round = 1; ; ++round)
    {
        //Generate input coin
        CTransaction inputTx = makeTransparentTx(CTxIn(), CTxIn(), CTxOut(CAmount(300000000), CScript()<<round<< OP_ADD<< round+1<< OP_EQUAL), CTxOut());
        UpdateCoins(inputTx, dummyState, *pcoinsTip, /*inputHeight*/100);
        ASSERT_TRUE(pcoinsTip->HaveCoins(inputTx.GetHash()));

        //Add Tx in mempool spending it
        CTransaction txForBlock = makeTransparentTx(CTxIn(inputTx.GetHash(), 0, CScript() << 1), CTxIn(), CTxOut(CAmount(100000000), CScript()<<OP_TRUE), CTxOut());
        if (txTotalSize + ::GetSerializeSize(txForBlock, SER_NETWORK, PROTOCOL_VERSION) > DEFAULT_BLOCK_MAX_SIZE -2000)
            break;

        ASSERT_TRUE(AcceptToMemoryPool(mempool, dummyState, txForBlock, false, nullptr));

        txTotalSize += ::GetSerializeSize(txForBlock, SER_NETWORK, PROTOCOL_VERSION);
        ++txCounter;
    }

    //Try push a max priority joinsplit
    unsigned char joinSplitPrivKey_[crypto_sign_SECRETKEYBYTES];
    uint256 joinSplitPubKey;
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey_);
    CMutableTransaction joinpsplitTx = makeJoinSplit(joinSplitPubKey);
    joinpsplitTx.joinSplitPubKey = joinSplitPubKey;

    CScript scriptCode;
    CTransaction signTx(joinpsplitTx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL);

    if (!(crypto_sign_detached(&joinpsplitTx.joinSplitSig[0], NULL,
           dataToBeSigned.begin(), 32,
           joinSplitPrivKey_
           ) == 0))
    {
       throw std::runtime_error("crypto_sign_detached failed");
    }

    // Sanity check
    if (!(crypto_sign_verify_detached(&joinpsplitTx.joinSplitSig[0],
           dataToBeSigned.begin(), 32,
           joinpsplitTx.joinSplitPubKey.begin()
           ) == 0))
    {
       throw std::runtime_error("crypto_sign_verify_detached failed");
    }
    ASSERT_TRUE(AcceptToMemoryPool(mempool, dummyState, joinpsplitTx, false, nullptr));



    //Try to create the block and check if it is filled
    CBlockTemplate* res = CreateNewBlock(/*scriptPubKeyIn*/CScript());
    ASSERT_TRUE(res != nullptr);
    EXPECT_FALSE(res->block.vtx.size() == txCounter + 1)<<res->block.vtx.size() <<" at txCounter " << txCounter;
    EXPECT_TRUE(std::find(res->block.vtx.begin(),res->block.vtx.end(),CTransaction(joinpsplitTx)) != res->block.vtx.end());
    delete res;
    res = nullptr;
}

CTransaction BlockPriorityTestSuite::makeJoinSplit(const uint256& jsPubKey) {
    uint256 rt = merkleTree.root();
    auto witness = merkleTree.witness();

    // create JSDescription
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs = {
        libzcash::JSInput(witness, note, k),
        libzcash::JSInput() // dummy input of zero value
    };
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs = {
        libzcash::JSOutput(addr, 50),
        libzcash::JSOutput(addr, 50)
    };

    auto verifier = libzcash::ProofVerifier::Strict();
    JSDescription jsdesc(/*isGroth*/true, *pzcashParams, jsPubKey, rt, inputs, outputs, 0, 0);
    jsdesc.Verify(*pzcashParams, verifier, jsPubKey);

    CMutableTransaction joinsplitTx;
    joinsplitTx.nVersion = GROTH_TX_VERSION;
    joinsplitTx.vjoinsplit.push_back(jsdesc);

    return joinsplitTx;
}

CTransaction BlockPriorityTestSuite::makeTransparentTx(const CTxIn& input1, const CTxIn& input2, const CTxOut& output1, const CTxOut& output2)
{
    static CTxIn dummyInput  = CTxIn();
    static CTxOut dummyOutput = CTxOut();

    CMutableTransaction res;
    res.nVersion = TRANSPARENT_TX_VERSION;

    if (input1 != dummyInput)
        res.vin.push_back(input1);

    if (input2 != dummyInput)
        res.vin.push_back(input2);

    if (output1 != dummyOutput)
        res.vout.push_back(output1);

    if (output2 != dummyOutput)
        res.vout.push_back(output2);

    return res;
}
