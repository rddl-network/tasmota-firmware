#pragma once

#define FROMHEX_MAXLEN 512

#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

#define BDB_VERSION_PUBLIC 0x02d41400   //0x03A3FDC2
#define BDB_VERSION_PRIVATE 0x02d40fc0   //0x03A3F988

#define PLANET_VERSION_PUBLIC 0x03e25d83
#define PLANET_VERSION_PRIVATE 0x03e25944 

#define LIQUIDBTC_VERSION_PUBLIC 0X76067358
#define LIQUIDBTC_VERSION_PRIVATE 0x76066276

#define ETHEREUM_VERSION_PUBLIC 0x0488b21e
#define ETHEREUM_VERSION_PRIVATE 0x0488ade4

extern char* g_mnemonic;
#define SEED_SIZE 64
#define SEED_SIZE_DEFAULT 32

extern uint8_t secret_seed[SEED_SIZE];

const uint8_t *fromhex2(const char *str);
void toHexString(char *hexbuf, uint8_t *str, int strlen);

const char* getMnemonic();
const char* setMnemonic( char* pMnemonic, size_t len );

const char* getMnemonicFromSeed( const uint8_t* seed, size_t length );
bool getSeedFromMnemonic( const char* pMnemonic, size_t len, uint8_t* seedbuffer );

int validateSignature();

bool SignDataHash(int json_data_start, int current_length, const char* data_str, char* pubkey_out, char* sig_out, char* hash_out);

