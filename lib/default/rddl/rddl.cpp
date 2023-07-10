#include <stdio.h>
#include <sys/random.h>

#include "address.h"
#include "options.h"
#include "aes/aes.h"
#include "base32.h"
#include "base58.h"
#include "bignum.h"
#include "bip32.h"
#include "bip39.h"
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519-donna.h"
#include "curve25519-donna-scalarmult-base.h"
#include "ed25519-keccak.h"
#include "ed25519.h"
#include "hmac.h"
#include "memzero.h"
#include "nist256p1.h"
#include "pbkdf2.h"
#include "rand.h"
#include "rc4.h"
#include "rfc6979.h"
#include "script.h"
#include "secp256k1.h"
#include "sha2.h"
#include "sha3.h"

#include "rddl.h"
#include "esp_random.h"

char* g_mnemonic = NULL;
uint8_t secret_seed[SEED_SIZE] = {0};

static bool bIsDynamicallyAllocated = false;

const uint8_t *fromhex2(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

// convert byte array  hexadeciaml values of length strlen into string represetning the hexv values (thus doubling the size)
void toHexString(char *hexbuf, uint8_t *str, int strlen){
   // char hexbuf[strlen];
    for (int i = 0 ; i < strlen/2 ; i++) {
        sprintf(&hexbuf[2*i], "%02X", str[i]);
    }
  hexbuf[strlen-2] = '\0';
}


const char* getMnemonic()
{
  // Generate a random master seed
  uint8_t master_seed[SEED_SIZE];
  esp_fill_random( master_seed, SEED_SIZE_DEFAULT);
  // Generate a 12-word mnemonic phrase from the master seed
  const char * mnemonic_phrase = mnemonic_from_data(master_seed, SEED_SIZE_DEFAULT);

  g_mnemonic = (char*) mnemonic_phrase;
  // printf("%s\n", mnemonic_phrase);
  return mnemonic_phrase;
}

const char* setMnemonic( char* pMnemonic, size_t len )
{
  uint8_t seed[SEED_SIZE] = {0};

  if( !mnemonic_check( pMnemonic ) )
    return "";

  mnemonic_to_seed(pMnemonic, "TREZOR", seed, 0);
  if( g_mnemonic && bIsDynamicallyAllocated )
  {
    delete g_mnemonic;
  }
  g_mnemonic= new char[len+1];
  memset( g_mnemonic,0, len+1 );
  memcpy_P(g_mnemonic,pMnemonic, len);
  bIsDynamicallyAllocated = true;

  return (const char*)g_mnemonic;
    
}



const char* getMnemonicFromSeed( const uint8_t* seed, size_t length )
{
  // Generate a 12-word mnemonic phrase from the master seed
  const char * mnemonic_phrase = mnemonic_from_data(seed, length);

  printf("%s\n", mnemonic_phrase);
  return mnemonic_phrase;
}

bool getSeedFromMnemonic( const char* pMnemonic, size_t len, uint8_t* seedbuffer )
{
  if( !mnemonic_check( pMnemonic ) )
    return false;
  
  mnemonic_to_seed(pMnemonic, "TREZOR", seedbuffer, NULL);
  return true;  
}

int validateSignature() {
  const ecdsa_curve *curve = &secp256k1;
  uint8_t pub_key[33] = {0};
  uint8_t hash[32] = {0};
  uint8_t computed_sig[64] = {0};

  const char pub_key_str[] = "02F8BC8B413BF803EA1DA9BE0FBFF4ED23FEED17A859187242007544F8535D3457";
  const char hash_str[] = "83EC230810630863EEB5C873206F45E60D5FB9EA3F5241EEECFB514F261A57DF";
  const char sig_str[] = "F551CDF6156FD2A8CC29428B61FDB9F5224928D5A5937E38F36D2D566C11B1DF13CD12E3BA2DAE6A33F091C549A5ADE537A5F07121AA1F4D4286B51260B228DE";


  memcpy(pub_key, fromhex2(pub_key_str), 33);
  memcpy(hash, fromhex2(hash_str), 32);
  memcpy(computed_sig, fromhex2(sig_str), 64);

  int verified = ecdsa_verify_digest(curve, pub_key, computed_sig, hash);
  return verified;
}

bool SignDataHash(int json_data_start, int current_length, const char* data_str, char* pubkey_out, char* sig_out, char* hash_out)
{
  uint8_t seed[64] = {0};
  uint8_t hash[32] = {0};
  uint8_t priv_key[32] = {0};
  uint8_t pub_key[33] = {0};
  uint8_t signature[64] = {0};
  HDNode node2;
  SHA256_CTX ctx;
  const ecdsa_curve *curve = &secp256k1;
  
  if( !g_mnemonic ){
    return false;
  }
  mnemonic_to_seed(g_mnemonic, "TREZOR", seed, 0);

  hdnode_from_seed( seed, SEED_SIZE, SECP256K1_NAME, &node2);
  hdnode_fill_public_key(&node2);
  memcpy(priv_key, node2.private_key, 32);
  memcpy(pub_key, node2.public_key, 33);

  size_t p2bsigned_length = current_length - json_data_start;
  const char* p2Bsigned = data_str + json_data_start;

  // Initialize the SHA-256 hasher

  sha256_Init(&ctx);
  // Hash the string
  sha256_Update(&ctx, (const uint8_t*) p2Bsigned, p2bsigned_length);
  sha256_Final(&ctx, hash);

  int res = ecdsa_sign_digest(curve, priv_key, hash, signature, NULL, NULL);
  int verified = ecdsa_verify_digest(curve, pub_key, signature, hash);

  // prepare and convert outputs to hex-strings
  toHexString( pubkey_out, pub_key, 68);
  toHexString( sig_out, signature, 130);
  toHexString( hash_out, hash, 66);

  return verified;
}
