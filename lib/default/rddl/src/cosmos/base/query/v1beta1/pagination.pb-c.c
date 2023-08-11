/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: cosmos/base/query/v1beta1/pagination.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "cosmos/base/query/v1beta1/pagination.pb-c.h"
void   cosmos__base__query__v1beta1__page_request__init
                     (Cosmos__Base__Query__V1beta1__PageRequest         *message)
{
  static const Cosmos__Base__Query__V1beta1__PageRequest init_value = COSMOS__BASE__QUERY__V1BETA1__PAGE_REQUEST__INIT;
  *message = init_value;
}
size_t cosmos__base__query__v1beta1__page_request__get_packed_size
                     (const Cosmos__Base__Query__V1beta1__PageRequest *message)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cosmos__base__query__v1beta1__page_request__pack
                     (const Cosmos__Base__Query__V1beta1__PageRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cosmos__base__query__v1beta1__page_request__pack_to_buffer
                     (const Cosmos__Base__Query__V1beta1__PageRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Cosmos__Base__Query__V1beta1__PageRequest *
       cosmos__base__query__v1beta1__page_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Cosmos__Base__Query__V1beta1__PageRequest *)
     protobuf_c_message_unpack (&cosmos__base__query__v1beta1__page_request__descriptor,
                                allocator, len, data);
}
void   cosmos__base__query__v1beta1__page_request__free_unpacked
                     (Cosmos__Base__Query__V1beta1__PageRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cosmos__base__query__v1beta1__page_response__init
                     (Cosmos__Base__Query__V1beta1__PageResponse         *message)
{
  static const Cosmos__Base__Query__V1beta1__PageResponse init_value = COSMOS__BASE__QUERY__V1BETA1__PAGE_RESPONSE__INIT;
  *message = init_value;
}
size_t cosmos__base__query__v1beta1__page_response__get_packed_size
                     (const Cosmos__Base__Query__V1beta1__PageResponse *message)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cosmos__base__query__v1beta1__page_response__pack
                     (const Cosmos__Base__Query__V1beta1__PageResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cosmos__base__query__v1beta1__page_response__pack_to_buffer
                     (const Cosmos__Base__Query__V1beta1__PageResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Cosmos__Base__Query__V1beta1__PageResponse *
       cosmos__base__query__v1beta1__page_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Cosmos__Base__Query__V1beta1__PageResponse *)
     protobuf_c_message_unpack (&cosmos__base__query__v1beta1__page_response__descriptor,
                                allocator, len, data);
}
void   cosmos__base__query__v1beta1__page_response__free_unpacked
                     (Cosmos__Base__Query__V1beta1__PageResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &cosmos__base__query__v1beta1__page_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor cosmos__base__query__v1beta1__page_request__field_descriptors[5] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageRequest, key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "offset",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageRequest, offset),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "limit",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageRequest, limit),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "count_total",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageRequest, count_total),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "reverse",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageRequest, reverse),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cosmos__base__query__v1beta1__page_request__field_indices_by_name[] = {
  3,   /* field[3] = count_total */
  0,   /* field[0] = key */
  2,   /* field[2] = limit */
  1,   /* field[1] = offset */
  4,   /* field[4] = reverse */
};
static const ProtobufCIntRange cosmos__base__query__v1beta1__page_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor cosmos__base__query__v1beta1__page_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cosmos.base.query.v1beta1.PageRequest",
  "PageRequest",
  "Cosmos__Base__Query__V1beta1__PageRequest",
  "cosmos.base.query.v1beta1",
  sizeof(Cosmos__Base__Query__V1beta1__PageRequest),
  5,
  cosmos__base__query__v1beta1__page_request__field_descriptors,
  cosmos__base__query__v1beta1__page_request__field_indices_by_name,
  1,  cosmos__base__query__v1beta1__page_request__number_ranges,
  (ProtobufCMessageInit) cosmos__base__query__v1beta1__page_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cosmos__base__query__v1beta1__page_response__field_descriptors[2] =
{
  {
    "next_key",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageResponse, next_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "total",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Cosmos__Base__Query__V1beta1__PageResponse, total),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cosmos__base__query__v1beta1__page_response__field_indices_by_name[] = {
  0,   /* field[0] = next_key */
  1,   /* field[1] = total */
};
static const ProtobufCIntRange cosmos__base__query__v1beta1__page_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor cosmos__base__query__v1beta1__page_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cosmos.base.query.v1beta1.PageResponse",
  "PageResponse",
  "Cosmos__Base__Query__V1beta1__PageResponse",
  "cosmos.base.query.v1beta1",
  sizeof(Cosmos__Base__Query__V1beta1__PageResponse),
  2,
  cosmos__base__query__v1beta1__page_response__field_descriptors,
  cosmos__base__query__v1beta1__page_response__field_indices_by_name,
  1,  cosmos__base__query__v1beta1__page_response__number_ranges,
  (ProtobufCMessageInit) cosmos__base__query__v1beta1__page_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};