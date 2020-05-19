#include "tx_creation_utils.h"
#include <main.h>

void chainSettingUtils::GenerateChainActive(int targetHeight) {
    chainActive.SetTip(nullptr);
    mapBlockIndex.clear();

    static std::vector<uint256> blockHashes;
    blockHashes.clear();
    blockHashes.resize(targetHeight);
    std::vector<CBlockIndex> blocks(targetHeight);

    ZCIncrementalMerkleTree dummyTree;
    dummyTree.append(GetRandHash());

    for (unsigned int height=0; height<blocks.size(); ++height) {
        blockHashes[height] = ArithToUint256(height);

        blocks[height].nHeight = height+1;
        blocks[height].pprev = height == 0? nullptr : mapBlockIndex[blockHashes[height-1]];
        blocks[height].phashBlock = &blockHashes[height];
        blocks[height].nTime = 1269211443 + height * Params().GetConsensus().nPowTargetSpacing;
        blocks[height].nBits = 0x1e7fffff;
        blocks[height].nChainWork = height == 0 ? arith_uint256(0) : blocks[height - 1].nChainWork + GetBlockProof(blocks[height - 1]);

        blocks[height].hashAnchor = dummyTree.root();

        mapBlockIndex[blockHashes[height]] = new CBlockIndex(blocks[height]);
        mapBlockIndex[blockHashes[height]]->phashBlock = &blockHashes[height];
        chainActive.SetTip(mapBlockIndex[blockHashes[height]]);
    }
}
