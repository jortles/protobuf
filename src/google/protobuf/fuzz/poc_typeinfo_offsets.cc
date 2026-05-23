// Probe: determine TypeInfo layout by examining the pointer chain from
// a DynamicMessage instance, before and after factory destruction.
//
// We can't access TypeInfo directly (it's private), but we can:
// 1. Observe the relationship between known pointers
// 2. Use the ASan crash offsets to confirm

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"

int main() {
  using namespace google::protobuf;

  DescriptorPool pool;
  FileDescriptorProto file_proto;
  file_proto.set_name("test.proto");
  file_proto.set_syntax("proto3");
  DescriptorProto* msg_proto = file_proto.add_message_type();
  msg_proto->set_name("T");
  FieldDescriptorProto* f = msg_proto->add_field();
  f->set_name("x");
  f->set_number(1);
  f->set_type(FieldDescriptorProto::TYPE_INT32);
  f->set_label(FieldDescriptorProto::LABEL_OPTIONAL);

  const FileDescriptor* fd = pool.BuildFile(file_proto);
  const Descriptor* desc = fd->FindMessageTypeByName("T");

  DynamicMessageFactory factory(&pool);
  const Message* proto = factory.GetPrototype(desc);
  Message* instance = proto->New();

  // DynamicMessage has type_info_ as its first member after the Message base.
  // Message base class layout (approx):
  //   - vtable pointer (8 bytes) -- but this might be from ClassData in new design
  //   - InternalMetadata (8 or 16 bytes)
  // DynamicMessage adds:
  //   - type_info_ (8 bytes)
  //   - cached_byte_size_ (4 bytes)
  //   - [field data...]

  // Let's just dump the raw bytes of the instance to find the type_info_ pointer.
  // We know that type_info_ points to a heap allocation.
  // The factory and pool are stack/heap addresses we can recognize.

  const Reflection* refl = instance->GetReflection();
  const Descriptor* inst_desc = instance->GetDescriptor();

  fprintf(stderr, "=== Known Addresses ===\n");
  fprintf(stderr, "instance       = %p\n", static_cast<void*>(instance));
  fprintf(stderr, "factory        = %p\n", static_cast<const void*>(&factory));
  fprintf(stderr, "pool           = %p\n", static_cast<const void*>(&pool));
  fprintf(stderr, "descriptor     = %p\n", static_cast<const void*>(inst_desc));
  fprintf(stderr, "reflection     = %p\n", static_cast<const void*>(refl));
  fprintf(stderr, "prototype      = %p\n", static_cast<const void*>(proto));

  // Dump first 128 bytes of the instance
  fprintf(stderr, "\n=== Raw Instance Bytes ===\n");
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(instance);
  for (int i = 0; i < 128; i += 8) {
    uint64_t val;
    memcpy(&val, raw + i, 8);
    fprintf(stderr, "  +%3d: 0x%016lx", i, val);
    // Try to identify known pointers
    if (val == reinterpret_cast<uint64_t>(&factory))
      fprintf(stderr, "  ← &factory");
    if (val == reinterpret_cast<uint64_t>(&pool))
      fprintf(stderr, "  ← &pool");
    if (val == reinterpret_cast<uint64_t>(inst_desc))
      fprintf(stderr, "  ← descriptor");
    if (val == reinterpret_cast<uint64_t>(refl))
      fprintf(stderr, "  ← reflection");
    if (val == reinterpret_cast<uint64_t>(proto))
      fprintf(stderr, "  ← prototype");
    fprintf(stderr, "\n");
  }

  // Now get the type_info_ pointer. It should be one of the first pointers
  // in the instance after the base class. Follow it and dump TypeInfo.
  // DynamicMessage layout:
  //   Message base (has _internal_metadata_ which is typically 8 bytes)
  //   type_info_ pointer
  //   cached_byte_size_
  //
  // The first qword is typically ClassData* or vtable related.
  // Let's try offset 8 and 16 as type_info_ candidates.

  fprintf(stderr, "\n=== Probing type_info_ ===\n");
  for (int off = 0; off <= 24; off += 8) {
    uint64_t ptr_val;
    memcpy(&ptr_val, raw + off, 8);
    if (ptr_val == 0) continue;

    // Try to read 160 bytes from this pointer (TypeInfo is 152 bytes)
    const uint8_t* ti = reinterpret_cast<const uint8_t*>(ptr_val);
    // Basic validity check - is this a reasonable heap pointer?
    if (ptr_val < 0x1000 || ptr_val > 0x7fffffffffff) continue;

    fprintf(stderr, "  Candidate type_info_ at instance+%d = %p\n", off,
            reinterpret_cast<void*>(ptr_val));

    // Dump TypeInfo contents
    for (int j = 0; j < 160; j += 8) {
      uint64_t v;
      memcpy(&v, ti + j, 8);
      fprintf(stderr, "    TI+%3d: 0x%016lx", j, v);
      if (v == reinterpret_cast<uint64_t>(&factory))
        fprintf(stderr, "  ← &factory (factory member)");
      if (v == reinterpret_cast<uint64_t>(&pool))
        fprintf(stderr, "  ← &pool (pool member)");
      if (v == reinterpret_cast<uint64_t>(inst_desc))
        fprintf(stderr, "  ← descriptor");
      if (v == reinterpret_cast<uint64_t>(refl))
        fprintf(stderr, "  ← reflection");
      if (v == reinterpret_cast<uint64_t>(proto))
        fprintf(stderr, "  ← prototype");
      fprintf(stderr, "\n");
    }
  }

  // Also print ClassData offsets using sizeof
  fprintf(stderr, "\n=== Struct Sizes ===\n");
  fprintf(stderr, "sizeof(internal::ClassData)     = %zu\n",
          sizeof(internal::ClassData));
  fprintf(stderr, "sizeof(internal::ClassDataFull) = %zu\n",
          sizeof(internal::ClassDataFull));
#ifdef PROTOBUF_MESSAGE_GLOBALS
  fprintf(stderr, "PROTOBUF_MESSAGE_GLOBALS = DEFINED\n");
  fprintf(stderr, "sizeof(MessageGlobalsBase)      = %zu\n",
          sizeof(internal::MessageGlobalsBase));
#else
  fprintf(stderr, "PROTOBUF_MESSAGE_GLOBALS = NOT DEFINED\n");
#endif

  delete instance;
  return 0;
}
