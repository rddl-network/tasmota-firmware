/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: tendermint/types/block.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "tendermint/types/block.pb-c.h"
void   tendermint__types__block__init
                     (Tendermint__Types__Block         *message)
{
  static const Tendermint__Types__Block init_value = TENDERMINT__TYPES__BLOCK__INIT;
  *message = init_value;
}
size_t tendermint__types__block__get_packed_size
                     (const Tendermint__Types__Block *message)
{
  assert(message->base.descriptor == &tendermint__types__block__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tendermint__types__block__pack
                     (const Tendermint__Types__Block *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tendermint__types__block__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tendermint__types__block__pack_to_buffer
                     (const Tendermint__Types__Block *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tendermint__types__block__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Tendermint__Types__Block *
       tendermint__types__block__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Tendermint__Types__Block *)
     protobuf_c_message_unpack (&tendermint__types__block__descriptor,
                                allocator, len, data);
}
void   tendermint__types__block__free_unpacked
                     (Tendermint__Types__Block *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tendermint__types__block__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor tendermint__types__block__field_descriptors[4] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Tendermint__Types__Block, header),
    &tendermint__types__header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "data",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Tendermint__Types__Block, data),
    &tendermint__types__data__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "evidence",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Tendermint__Types__Block, evidence),
    &tendermint__types__evidence_list__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "last_commit",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Tendermint__Types__Block, last_commit),
    &tendermint__types__commit__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tendermint__types__block__field_indices_by_name[] = {
  1,   /* field[1] = data */
  2,   /* field[2] = evidence */
  0,   /* field[0] = header */
  3,   /* field[3] = last_commit */
};
static const ProtobufCIntRange tendermint__types__block__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor tendermint__types__block__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tendermint.types.Block",
  "Block",
  "Tendermint__Types__Block",
  "tendermint.types",
  sizeof(Tendermint__Types__Block),
  4,
  tendermint__types__block__field_descriptors,
  tendermint__types__block__field_indices_by_name,
  1,  tendermint__types__block__number_ranges,
  (ProtobufCMessageInit) tendermint__types__block__init,
  NULL,NULL,NULL    /* reserved[123] */
};
