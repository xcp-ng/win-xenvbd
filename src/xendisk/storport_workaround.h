#ifndef _XENDISK_STORPORT_FIX_H
#define _XENDISK_STORPORT_FIX_H

// Ugly workaround for Storport.h and Ntddstor.h not being in sync:
// error C2365: 'StorCryptoAlgorithmUnknown': redefinition

// Take definitions from Ntddstor.h

#ifndef STORAGE_CRYPTO_ALGORITHMS_DEFINED
#define STORAGE_CRYPTO_ALGORITHMS_DEFINED

//
// Output buffer for StorageAdapterCryptoProperty & PropertyStandardQuery
//

typedef enum _STORAGE_CRYPTO_ALGORITHM_ID {

    StorageCryptoAlgorithmUnknown = 0,
    StorageCryptoAlgorithmXTSAES = 1,
    StorageCryptoAlgorithmBitlockerAESCBC,
    StorageCryptoAlgorithmAESECB,
    StorageCryptoAlgorithmESSIVAESCBC,
    StorageCryptoAlgorithmMax,

    //
    // Legacy compatibility algorithm names.
    // Use the names above.
    //

    StorCryptoAlgorithmUnknown = StorageCryptoAlgorithmUnknown,
    StorCryptoAlgorithmXTSAES = StorageCryptoAlgorithmXTSAES,
    StorCryptoAlgorithmBitlockerAESCBC = StorageCryptoAlgorithmBitlockerAESCBC,
    StorCryptoAlgorithmAESECB = StorageCryptoAlgorithmAESECB,
    StorCryptoAlgorithmESSIVAESCBC = StorageCryptoAlgorithmESSIVAESCBC,
} STORAGE_CRYPTO_ALGORITHM_ID,
    *PSTORAGE_CRYPTO_ALGORITHM_ID;

typedef enum _STORAGE_CRYPTO_KEY_SIZE {

    StorageCryptoKeySizeUnknown = 0,
    StorageCryptoKeySize128Bits = 1,
    StorageCryptoKeySize192Bits,
    StorageCryptoKeySize256Bits,
    StorageCryptoKeySize512Bits,
    StorageCryptoKeySizeMax,

    //
    // Legacy compatibility key size names.
    // Use the names above.
    //
    StorCryptoKeySizeUnknown = StorageCryptoKeySizeUnknown,
    StorCryptoKeySize128Bits = StorageCryptoKeySize128Bits,
    StorCryptoKeySize192Bits = StorageCryptoKeySize192Bits,
    StorCryptoKeySize256Bits = StorageCryptoKeySize256Bits,
    StorCryptoKeySize512Bits = StorageCryptoKeySize512Bits,
} STORAGE_CRYPTO_KEY_SIZE,
    *PSTORAGE_CRYPTO_KEY_SIZE;

#endif // STORAGE_CRYPTO_ALGORITHMS_DEFINED

// Then suppress the old definitions from Storport.h

#define StorCryptoAlgorithmUnknown backup_StorCryptoAlgorithmUnknown##__LINE__
#define StorCryptoAlgorithmXTSAES backup_StorCryptoAlgorithmXTSAES##__LINE__
#define StorCryptoAlgorithmBitlockerAESCBC backup_StorCryptoAlgorithmBitlockerAESCBC##__LINE__
#define StorCryptoAlgorithmAESECB backup_StorCryptoAlgorithmAESECB##__LINE__
#define StorCryptoAlgorithmESSIVAESCBC backup_StorCryptoAlgorithmESSIVAESCBC##__LINE__

#define StorCryptoKeySizeUnknown backup_StorCryptoKeySizeUnknown##__LINE__
#define StorCryptoKeySize128Bits backup_StorCryptoKeySize128Bits##__LINE__
#define StorCryptoKeySize192Bits backup_StorCryptoKeySize192Bits##__LINE__
#define StorCryptoKeySize256Bits backup_StorCryptoKeySize256Bits##__LINE__
#define StorCryptoKeySize512Bits backup_StorCryptoKeySize512Bits##__LINE__

#define _STOR_CRYPTO_ALGORITHM_ID backup__STOR_CRYPTO_ALGORITHM_ID##__LINE__
#define STOR_CRYPTO_ALGORITHM_ID backup_STOR_CRYPTO_ALGORITHM_ID##__LINE__
#define PSTOR_CRYPTO_ALGORITHM_ID backup_PSTOR_CRYPTO_ALGORITHM_ID##__LINE__
#define _STOR_CRYPTO_KEY_SIZE backup__STOR_CRYPTO_KEY_SIZE##__LINE__
#define STOR_CRYPTO_KEY_SIZE backup_STOR_CRYPTO_KEY_SIZE##__LINE__
#define PSTOR_CRYPTO_KEY_SIZE backup_PSTOR_CRYPTO_KEY_SIZE##__LINE__

#include <storport.h>

#undef StorCryptoAlgorithmUnknown
#undef StorCryptoAlgorithmXTSAES
#undef StorCryptoAlgorithmBitlockerAESCBC
#undef StorCryptoAlgorithmAESECB
#undef StorCryptoAlgorithmESSIVAESCBC

#undef StorCryptoKeySizeUnknown
#undef StorCryptoKeySize128Bits
#undef StorCryptoKeySize192Bits
#undef StorCryptoKeySize256Bits
#undef StorCryptoKeySize512Bits

#undef _STOR_CRYPTO_ALGORITHM_ID
#define _STOR_CRYPTO_ALGORITHM_ID _STORAGE_CRYPTO_ALGORITHM_ID

#undef STOR_CRYPTO_ALGORITHM_ID
#define STOR_CRYPTO_ALGORITHM_ID STORAGE_CRYPTO_ALGORITHM_ID

#undef PSTOR_CRYPTO_ALGORITHM_ID
#define PSTOR_CRYPTO_ALGORITHM_ID PSTORAGE_CRYPTO_ALGORITHM_ID

#undef _STOR_CRYPTO_KEY_SIZE
#define _STOR_CRYPTO_KEY_SIZE _STORAGE_CRYPTO_KEY_SIZE

#undef STOR_CRYPTO_KEY_SIZE
#define STOR_CRYPTO_KEY_SIZE STORAGE_CRYPTO_KEY_SIZE

#undef PSTOR_CRYPTO_KEY_SIZE
#define PSTOR_CRYPTO_KEY_SIZE PSTORAGE_CRYPTO_KEY_SIZE

#undef STOR_CRYPTO_ALGORITHM_ID_OFFSET
#define STOR_CRYPTO_ALGORITHM_ID_OFFSET StorCryptoAlgorithmXTSAES

#endif
