// PoC: DynamicMessageFactory use-after-free.
//
// When a DynamicMessageFactory is destroyed, it frees all TypeInfo objects,
// deletes the Reflection, and scribbles field offsets with 0xCDCDCDCD.
// Any DynamicMessage instances that survive the factory destruction hold
// dangling pointers to freed TypeInfo/Reflection/offsets. Subsequent
// operations on these instances (serialize, merge, access fields, destructor)
// access freed memory.
//
// Bug location:
//   dynamic_message.cc:455-478 -- TypeInfo destructor frees Reflection,
//                                  scribbles offsets
//   dynamic_message.cc:868-872 -- ~DynamicMessageFactory deletes all TypeInfo
//   dynamic_message.cc:484     -- DynamicMessage holds raw type_info_ pointer
//
// The code's own comments acknowledge this is a "common bug" (line 470).
// The scribble is a detection aid, not a fix -- it causes crashes with
// recognizable patterns but does not prevent the UAF.

#include <cstdio>
#include <memory>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"

int main() {
  using namespace google::protobuf;

  // Step 1: Create a DescriptorPool with a simple message type.
  DescriptorPool pool;
  FileDescriptorProto file_proto;
  file_proto.set_name("test.proto");
  file_proto.set_syntax("proto3");

  DescriptorProto* msg_proto = file_proto.add_message_type();
  msg_proto->set_name("TestMsg");

  // Add several fields to create a non-trivial layout.
  auto add_field = [&](const char* name, int number,
                       FieldDescriptorProto::Type type) {
    FieldDescriptorProto* f = msg_proto->add_field();
    f->set_name(name);
    f->set_number(number);
    f->set_type(type);
    f->set_label(FieldDescriptorProto::LABEL_OPTIONAL);
  };

  add_field("id", 1, FieldDescriptorProto::TYPE_INT32);
  add_field("name", 2, FieldDescriptorProto::TYPE_STRING);
  add_field("value", 3, FieldDescriptorProto::TYPE_DOUBLE);
  add_field("flag", 4, FieldDescriptorProto::TYPE_BOOL);
  add_field("data", 5, FieldDescriptorProto::TYPE_BYTES);

  const FileDescriptor* file = pool.BuildFile(file_proto);
  if (!file) {
    fprintf(stderr, "FAIL: BuildFile returned nullptr\n");
    return 1;
  }

  const Descriptor* desc = file->FindMessageTypeByName("TestMsg");
  fprintf(stderr, "Descriptor: %.*s (%d fields)\n",
          static_cast<int>(desc->full_name().size()),
          desc->full_name().data(), desc->field_count());

  // Step 2: Create a DynamicMessageFactory and get a prototype.
  auto* factory = new DynamicMessageFactory(&pool);
  const Message* prototype = factory->GetPrototype(desc);

  // Step 3: Create message instances from the prototype.
  Message* msg1 = prototype->New();
  Message* msg2 = prototype->New();

  // Populate msg1 via Reflection.
  const Reflection* refl = msg1->GetReflection();
  refl->SetInt32(msg1, desc->FindFieldByName("id"), 42);
  refl->SetString(msg1, desc->FindFieldByName("name"), "test");
  refl->SetDouble(msg1, desc->FindFieldByName("value"), 3.14);
  refl->SetBool(msg1, desc->FindFieldByName("flag"), true);

  std::string serialized;
  (void)msg1->SerializeToString(&serialized);
  fprintf(stderr, "Serialized msg1: %zu bytes\n", serialized.size());

  // Step 4: DESTROY THE FACTORY while instances survive.
  // This frees TypeInfo, deletes Reflection, scribbles offsets with 0xCDCDCDCD.
  fprintf(stderr, "Destroying factory...\n");
  delete factory;
  factory = nullptr;

  // Step 5: USE-AFTER-FREE -- any operation on msg1/msg2 accesses freed memory.
  fprintf(stderr, "Attempting operations on surviving instances...\n");

  // UAF 1: GetReflection() returns freed Reflection pointer.
  fprintf(stderr, "  GetReflection()...\n");
  const Reflection* freed_refl = msg1->GetReflection();
  fprintf(stderr, "  Got reflection at %p (this is freed memory)\n",
          static_cast<const void*>(freed_refl));

  // UAF 2: GetDescriptor() accesses freed class_data.
  fprintf(stderr, "  GetDescriptor()...\n");
  const Descriptor* freed_desc = msg1->GetDescriptor();
  fprintf(stderr, "  Got descriptor at %p\n",
          static_cast<const void*>(freed_desc));

  // UAF 3: SerializeToString uses freed Reflection and scribbled offsets.
  // The offsets are now 0xCDCDCDCD, so field access reads from
  // offset 0xCDCDCDCD within the message -- far past the allocation.
  fprintf(stderr, "  SerializeToString() -- will access scribbled offsets...\n");
  std::string s;
  (void)msg1->SerializeToString(&s);
  fprintf(stderr, "  Serialized: %zu bytes\n", s.size());

  // UAF 4: Destructor accesses freed type_info_.
  fprintf(stderr, "  Deleting msg1...\n");
  delete msg1;
  fprintf(stderr, "  Deleting msg2...\n");
  delete msg2;

  fprintf(stderr, "DONE (if we got here without ASan error, scribble saved us)\n");
  return 0;
}
