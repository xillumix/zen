#ifndef GTESTUTILS_H
#define GTESTUTILS_H

#include <primitives/transaction.h>

namespace gtestUtils {

CMutableTransaction populateTx(int txVersion, const uint256 & newScId = uint256S("0"), const CAmount & fwdTxAmount = CAmount(0));

void signTx(CMutableTransaction& mtx);

CTransaction createSidechainTxWith(const uint256 & newScId, const CAmount & fwdTxAmount);

CTransaction createFwdTransferTxWith(const uint256 & newScId, const CAmount & fwdTxAmount);

CTransaction createSidechainTxWithNoFwdTransfer(const uint256 & newScId);

CTransaction createTransparentTx(bool ccIsNull = true); //ccIsNull = false allows generation of faulty tx with non-empty cross chain output

CTransaction createSproutTx(bool ccIsNull = true); //ccIsNull = false allows generation of faulty tx with non-empty cross chain output

void extendTransaction(CTransaction & tx, const uint256 & scId, const CAmount & amount);

};

#endif

