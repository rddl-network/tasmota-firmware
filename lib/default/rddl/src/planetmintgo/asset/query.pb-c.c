/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: planetmintgo/asset/query.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "planetmintgo/asset/query.pb-c.h"
void   planetmintgo__asset__query_params_request__init
                     (Planetmintgo__Asset__QueryParamsRequest         *message)
{
  static const Planetmintgo__Asset__QueryParamsRequest init_value = PLANETMINTGO__ASSET__QUERY_PARAMS_REQUEST__INIT;
  *message = init_value;
}
size_t planetmintgo__asset__query_params_request__get_packed_size
                     (const Planetmintgo__Asset__QueryParamsRequest *message)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t planetmintgo__asset__query_params_request__pack
                     (const Planetmintgo__Asset__QueryParamsRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t planetmintgo__asset__query_params_request__pack_to_buffer
                     (const Planetmintgo__Asset__QueryParamsRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Planetmintgo__Asset__QueryParamsRequest *
       planetmintgo__asset__query_params_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Planetmintgo__Asset__QueryParamsRequest *)
     protobuf_c_message_unpack (&planetmintgo__asset__query_params_request__descriptor,
                                allocator, len, data);
}
void   planetmintgo__asset__query_params_request__free_unpacked
                     (Planetmintgo__Asset__QueryParamsRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &planetmintgo__asset__query_params_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   planetmintgo__asset__query_params_response__init
                     (Planetmintgo__Asset__QueryParamsResponse         *message)
{
  static const Planetmintgo__Asset__QueryParamsResponse init_value = PLANETMINTGO__ASSET__QUERY_PARAMS_RESPONSE__INIT;
  *message = init_value;
}
size_t planetmintgo__asset__query_params_response__get_packed_size
                     (const Planetmintgo__Asset__QueryParamsResponse *message)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t planetmintgo__asset__query_params_response__pack
                     (const Planetmintgo__Asset__QueryParamsResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t planetmintgo__asset__query_params_response__pack_to_buffer
                     (const Planetmintgo__Asset__QueryParamsResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &planetmintgo__asset__query_params_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Planetmintgo__Asset__QueryParamsResponse *
       planetmintgo__asset__query_params_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Planetmintgo__Asset__QueryParamsResponse *)
     protobuf_c_message_unpack (&planetmintgo__asset__query_params_response__descriptor,
                                allocator, len, data);
}
void   planetmintgo__asset__query_params_response__free_unpacked
                     (Planetmintgo__Asset__QueryParamsResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &planetmintgo__asset__query_params_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
#define planetmintgo__asset__query_params_request__field_descriptors NULL
#define planetmintgo__asset__query_params_request__field_indices_by_name NULL
#define planetmintgo__asset__query_params_request__number_ranges NULL
const ProtobufCMessageDescriptor planetmintgo__asset__query_params_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "planetmintgo.asset.QueryParamsRequest",
  "QueryParamsRequest",
  "Planetmintgo__Asset__QueryParamsRequest",
  "planetmintgo.asset",
  sizeof(Planetmintgo__Asset__QueryParamsRequest),
  0,
  planetmintgo__asset__query_params_request__field_descriptors,
  planetmintgo__asset__query_params_request__field_indices_by_name,
  0,  planetmintgo__asset__query_params_request__number_ranges,
  (ProtobufCMessageInit) planetmintgo__asset__query_params_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor planetmintgo__asset__query_params_response__field_descriptors[1] =
{
  {
    "params",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Planetmintgo__Asset__QueryParamsResponse, params),
    &planetmintgo__asset__params__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned planetmintgo__asset__query_params_response__field_indices_by_name[] = {
  0,   /* field[0] = params */
};
static const ProtobufCIntRange planetmintgo__asset__query_params_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor planetmintgo__asset__query_params_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "planetmintgo.asset.QueryParamsResponse",
  "QueryParamsResponse",
  "Planetmintgo__Asset__QueryParamsResponse",
  "planetmintgo.asset",
  sizeof(Planetmintgo__Asset__QueryParamsResponse),
  1,
  planetmintgo__asset__query_params_response__field_descriptors,
  planetmintgo__asset__query_params_response__field_indices_by_name,
  1,  planetmintgo__asset__query_params_response__number_ranges,
  (ProtobufCMessageInit) planetmintgo__asset__query_params_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCMethodDescriptor planetmintgo__asset__query__method_descriptors[1] =
{
  { "Params", &planetmintgo__asset__query_params_request__descriptor, &planetmintgo__asset__query_params_response__descriptor },
};
const unsigned planetmintgo__asset__query__method_indices_by_name[] = {
  0         /* Params */
};
const ProtobufCServiceDescriptor planetmintgo__asset__query__descriptor =
{
  PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC,
  "planetmintgo.asset.Query",
  "Query",
  "Planetmintgo__Asset__Query",
  "planetmintgo.asset",
  1,
  planetmintgo__asset__query__method_descriptors,
  planetmintgo__asset__query__method_indices_by_name
};
void planetmintgo__asset__query__params(ProtobufCService *service,
                                        const Planetmintgo__Asset__QueryParamsRequest *input,
                                        Planetmintgo__Asset__QueryParamsResponse_Closure closure,
                                        void *closure_data)
{
  assert(service->descriptor == &planetmintgo__asset__query__descriptor);
  service->invoke(service, 0, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void planetmintgo__asset__query__init (Planetmintgo__Asset__Query_Service *service,
                                       Planetmintgo__Asset__Query_ServiceDestroy destroy)
{
  protobuf_c_service_generated_init (&service->base,
                                     &planetmintgo__asset__query__descriptor,
                                     (ProtobufCServiceDestroy) destroy);
}
