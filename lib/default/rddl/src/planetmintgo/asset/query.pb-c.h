/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: planetmintgo/asset/query.proto */

#ifndef PROTOBUF_C_planetmintgo_2fasset_2fquery_2eproto__INCLUDED
#define PROTOBUF_C_planetmintgo_2fasset_2fquery_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "gogoproto/gogo.pb-c.h"
#include "google/api/annotations.pb-c.h"
#include "cosmos/base/query/v1beta1/pagination.pb-c.h"
#include "planetmintgo/asset/params.pb-c.h"

typedef struct Planetmintgo__Asset__QueryParamsRequest Planetmintgo__Asset__QueryParamsRequest;
typedef struct Planetmintgo__Asset__QueryParamsResponse Planetmintgo__Asset__QueryParamsResponse;


/* --- enums --- */


/* --- messages --- */

/*
 * QueryParamsRequest is request type for the Query/Params RPC method.
 */
struct  Planetmintgo__Asset__QueryParamsRequest
{
  ProtobufCMessage base;
};
#define PLANETMINTGO__ASSET__QUERY_PARAMS_REQUEST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&planetmintgo__asset__query_params_request__descriptor) \
     }


/*
 * QueryParamsResponse is response type for the Query/Params RPC method.
 */
struct  Planetmintgo__Asset__QueryParamsResponse
{
  ProtobufCMessage base;
  /*
   * params holds all the parameters of this module.
   */
  Planetmintgo__Asset__Params *params;
};
#define PLANETMINTGO__ASSET__QUERY_PARAMS_RESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&planetmintgo__asset__query_params_response__descriptor) \
    , NULL }


/* Planetmintgo__Asset__QueryParamsRequest methods */
void   planetmintgo__asset__query_params_request__init
                     (Planetmintgo__Asset__QueryParamsRequest         *message);
size_t planetmintgo__asset__query_params_request__get_packed_size
                     (const Planetmintgo__Asset__QueryParamsRequest   *message);
size_t planetmintgo__asset__query_params_request__pack
                     (const Planetmintgo__Asset__QueryParamsRequest   *message,
                      uint8_t             *out);
size_t planetmintgo__asset__query_params_request__pack_to_buffer
                     (const Planetmintgo__Asset__QueryParamsRequest   *message,
                      ProtobufCBuffer     *buffer);
Planetmintgo__Asset__QueryParamsRequest *
       planetmintgo__asset__query_params_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   planetmintgo__asset__query_params_request__free_unpacked
                     (Planetmintgo__Asset__QueryParamsRequest *message,
                      ProtobufCAllocator *allocator);
/* Planetmintgo__Asset__QueryParamsResponse methods */
void   planetmintgo__asset__query_params_response__init
                     (Planetmintgo__Asset__QueryParamsResponse         *message);
size_t planetmintgo__asset__query_params_response__get_packed_size
                     (const Planetmintgo__Asset__QueryParamsResponse   *message);
size_t planetmintgo__asset__query_params_response__pack
                     (const Planetmintgo__Asset__QueryParamsResponse   *message,
                      uint8_t             *out);
size_t planetmintgo__asset__query_params_response__pack_to_buffer
                     (const Planetmintgo__Asset__QueryParamsResponse   *message,
                      ProtobufCBuffer     *buffer);
Planetmintgo__Asset__QueryParamsResponse *
       planetmintgo__asset__query_params_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   planetmintgo__asset__query_params_response__free_unpacked
                     (Planetmintgo__Asset__QueryParamsResponse *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Planetmintgo__Asset__QueryParamsRequest_Closure)
                 (const Planetmintgo__Asset__QueryParamsRequest *message,
                  void *closure_data);
typedef void (*Planetmintgo__Asset__QueryParamsResponse_Closure)
                 (const Planetmintgo__Asset__QueryParamsResponse *message,
                  void *closure_data);

/* --- services --- */

typedef struct Planetmintgo__Asset__Query_Service Planetmintgo__Asset__Query_Service;
struct Planetmintgo__Asset__Query_Service
{
  ProtobufCService base;
  void (*params)(Planetmintgo__Asset__Query_Service *service,
                 const Planetmintgo__Asset__QueryParamsRequest *input,
                 Planetmintgo__Asset__QueryParamsResponse_Closure closure,
                 void *closure_data);
};
typedef void (*Planetmintgo__Asset__Query_ServiceDestroy)(Planetmintgo__Asset__Query_Service *);
void planetmintgo__asset__query__init (Planetmintgo__Asset__Query_Service *service,
                                       Planetmintgo__Asset__Query_ServiceDestroy destroy);
#define PLANETMINTGO__ASSET__QUERY__BASE_INIT \
    { &planetmintgo__asset__query__descriptor, protobuf_c_service_invoke_internal, NULL }
#define PLANETMINTGO__ASSET__QUERY__INIT(function_prefix__) \
    { PLANETMINTGO__ASSET__QUERY__BASE_INIT,\
      function_prefix__ ## params  }
void planetmintgo__asset__query__params(ProtobufCService *service,
                                        const Planetmintgo__Asset__QueryParamsRequest *input,
                                        Planetmintgo__Asset__QueryParamsResponse_Closure closure,
                                        void *closure_data);

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor planetmintgo__asset__query_params_request__descriptor;
extern const ProtobufCMessageDescriptor planetmintgo__asset__query_params_response__descriptor;
extern const ProtobufCServiceDescriptor planetmintgo__asset__query__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_planetmintgo_2fasset_2fquery_2eproto__INCLUDED */
