// PoC: ExtensionRange::options() nullptr dereference on placeholder messages.
//
// When AllowUnknownDependencies() is enabled and a FileDescriptorProto
// references an unknown extendee type, the DescriptorPool creates a
// placeholder extendable message with extension_ranges_[0].options_ = nullptr.
// Calling DebugString() on the resulting descriptor dereferences this nullptr
// via ExtensionRange::options() which returns *options_.
//
// Bug location:
//   descriptor.cc:5796 -- options_ = nullptr for placeholder extension ranges
//   descriptor.h:591   -- return *options_  (null dereference)
//   descriptor.cc:3976 -- DebugString() calls extension_range(i)->options()

#include <cstdio>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"

int main() {
  using namespace google::protobuf;

  // Create a pool that allows unknown dependencies.
  // This is a public API used by dynamic schema loading tools.
  DescriptorPool pool;
  pool.AllowUnknownDependencies();

  // Build a FileDescriptorProto with an extension that references
  // an unknown extendee type. This forces creation of a placeholder
  // extendable message with options_ = nullptr.
  FileDescriptorProto file_proto;
  file_proto.set_name("test.proto");
  file_proto.set_syntax("proto2");

  // Add an extension field that extends an unknown type.
  FieldDescriptorProto* ext = file_proto.add_extension();
  ext->set_name("my_ext");
  ext->set_number(100);
  ext->set_type(FieldDescriptorProto::TYPE_INT32);
  ext->set_label(FieldDescriptorProto::LABEL_OPTIONAL);
  ext->set_extendee("UnknownMessage");  // This type doesn't exist

  const FileDescriptor* file = pool.BuildFile(file_proto);
  if (file == nullptr) {
    fprintf(stderr, "FAIL: BuildFile returned nullptr\n");
    return 1;
  }

  fprintf(stderr, "BuildFile succeeded. File has %d extensions.\n",
          file->extension_count());

  // The extendee "UnknownMessage" was resolved as a placeholder extendable
  // message. Get it.
  const FieldDescriptor* ext_field = file->extension(0);
  const Descriptor* extendee = ext_field->containing_type();

  fprintf(stderr, "Extendee: %.*s (placeholder=%d)\n",
          static_cast<int>(extendee->full_name().size()),
          extendee->full_name().data(), extendee->is_placeholder());
  fprintf(stderr, "Extension range count: %d\n",
          extendee->extension_range_count());

  if (extendee->extension_range_count() > 0) {
    fprintf(stderr, "Extension range [0]: start=%d, end=%d\n",
            extendee->extension_range(0)->start_number(),
            extendee->extension_range(0)->end_number());

    // THIS CRASHES: extension_range(0)->options() dereferences nullptr
    fprintf(stderr, "About to call DebugString() -- this will crash...\n");
    std::string debug = extendee->DebugString();
    fprintf(stderr, "DebugString (should not reach here): %s\n",
            debug.c_str());
  }

  fprintf(stderr, "FAIL: Did not crash (unexpected)\n");
  return 1;
}
