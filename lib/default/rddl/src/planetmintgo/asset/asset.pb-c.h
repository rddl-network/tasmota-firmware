/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: planetmintgo/asset/asset.proto */

#ifndef PROTOBUF_C_planetmintgo_2fasset_2fasset_2eproto__INCLUDED
#define PROTOBUF_C_planetmintgo_2fasset_2fasset_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct Planetmintgo__Asset__Asset Planetmintgo__Asset__Asset;


/* --- enums --- */


/* --- messages --- */

struct  Planetmintgo__Asset__Asset
{
  ProtobufCMessage base;
  char *hash;
  char *signature;
  char *pubkey;
};
#define PLANETMINTGO__ASSET__ASSET__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&planetmintgo__asset__asset__descriptor) \
    , (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


/* Planetmintgo__Asset__Asset methods */
void   planetmintgo__asset__asset__init
                     (Planetmintgo__Asset__Asset         *message);
size_t planetmintgo__asset__asset__get_packed_size
                     (const Planetmintgo__Asset__Asset   *message);
size_t planetmintgo__asset__asset__pack
                     (const Planetmintgo__Asset__Asset   *message,
                      uint8_t             *out);
size_t planetmintgo__asset__asset__pack_to_buffer
                     (const Planetmintgo__Asset__Asset   *message,
                      ProtobufCBuffer     *buffer);
Planetmintgo__Asset__Asset *
       planetmintgo__asset__asset__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   planetmintgo__asset__asset__free_unpacked
                     (Planetmintgo__Asset__Asset *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Planetmintgo__Asset__Asset_Closure)
                 (const Planetmintgo__Asset__Asset *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor planetmintgo__asset__asset__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_planetmintgo_2fasset_2fasset_2eproto__INCLUDED */