/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: planetmintgo/asset/params.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "planetmintgo/asset/params.pb-c.h"
void   planetmintgo__asset__params__init
                     (Planetmintgo__Asset__Params         *message)
{
  static const Planetmintgo__Asset__Params init_value = PLANETMINTGO__ASSET__PARAMS__INIT;
  *message = init_value;
}
size_t planetmintgo__asset__params__get_packed_size
                     (const Planetmintgo__Asset__Params *message)
{
  assert(message->base.descriptor == &planetmintgo__asset__params__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t planetmintgo__asset__params__pack
                     (const Planetmintgo__Asset__Params *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &planetmintgo__asset__params__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t planetmintgo__asset__params__pack_to_buffer
                     (const Planetmintgo__Asset__Params *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &planetmintgo__asset__params__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Planetmintgo__Asset__Params *
       planetmintgo__asset__params__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Planetmintgo__Asset__Params *)
     protobuf_c_message_unpack (&planetmintgo__asset__params__descriptor,
                                allocator, len, data);
}
void   planetmintgo__asset__params__free_unpacked
                     (Planetmintgo__Asset__Params *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &planetmintgo__asset__params__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
#define planetmintgo__asset__params__field_descriptors NULL
#define planetmintgo__asset__params__field_indices_by_name NULL
#define planetmintgo__asset__params__number_ranges NULL
const ProtobufCMessageDescriptor planetmintgo__asset__params__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "planetmintgo.asset.Params",
  "Params",
  "Planetmintgo__Asset__Params",
  "planetmintgo.asset",
  sizeof(Planetmintgo__Asset__Params),
  0,
  planetmintgo__asset__params__field_descriptors,
  planetmintgo__asset__params__field_indices_by_name,
  0,  planetmintgo__asset__params__number_ranges,
  (ProtobufCMessageInit) planetmintgo__asset__params__init,
  NULL,NULL,NULL    /* reserved[123] */
};
