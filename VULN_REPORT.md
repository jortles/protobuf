# Google OSS VRP: protobuf C++ Runtime Vulnerabilities

**Reporter:** Anthony Hurtado (amhurtado@pm.me)
**Date:** 2026-05-23
**Project:** protocolbuffers/protobuf (C++ runtime)
**Tested version:** upstream `main` commit `128dee159` (May 23 2026)
**PR with PoCs:** https://github.com/jortles/protobuf/pull/1

---

## Finding 1: CWE-416 — DynamicMessageFactory Use-After-Free → Arbitrary Code Execution

### Summary

Destroying a `DynamicMessageFactory` while `DynamicMessage` instances created from it still exist causes a use-after-free. The freed memory contains function pointers that are subsequently called through normal message operations. An attacker who can reclaim the freed heap allocation controls the function pointer targets, achieving arbitrary code execution.

### Severity

**Critical** — The UAF leads to a controlled indirect call (`call *0x10(%rax)` where the target is attacker-supplied data from reclaimed heap memory). This is not a data-only UAF or a simple crash; it is a proven control-flow hijack primitive.

### Root Cause

`DynamicMessage` stores a raw `type_info_` pointer (at instance offset +16) to a `TypeInfo` struct (152 bytes) owned by its `DynamicMessageFactory`. When the factory is destroyed:

1. `~DynamicMessageFactory` iterates all `TypeInfo` objects and deletes them (`dynamic_message.cc:868-872`)
2. `~TypeInfo` frees the `Reflection` object, scribbles `offsets[]` and `has_bits_indices[]` with `0xCDCDCDCD`, then the `TypeInfo` struct itself is freed (`dynamic_message.cc:455-478`)
3. Surviving `DynamicMessage` instances retain the now-dangling `type_info_` pointer

The `TypeInfo` struct contains an embedded `ClassDataFull` (96 bytes starting at offset +56) with function pointers:

| Offset | Field | Purpose |
|--------|-------|---------|
| +72 | `is_initialized` | Called by `IsInitialized()`, `SerializeToString()` |
| +80 | `merge_to_from` | Called by `MergeFrom()` |
| +88 | `message_creator` | Called by `New()` |

The existing scribble mitigation **only covers `offsets[]` and `has_bits_indices[]`** — it does NOT scribble the `TypeInfo` struct itself or the `ClassDataFull` function pointers.

### Attack Chain (proven in poc_dynamic_factory_uaf_v3.cc)

```
1. Create DynamicMessageFactory + DynamicMessage instance
2. delete factory → frees 152-byte TypeInfo (glibc tcache)
3. Spray malloc(152) with controlled data → reclaims freed chunk (LIFO)
4. Place 0xdeadbeefcafebabe at offset +72 (is_initialized fptr)
5. Call victim->IsInitialized()
   → GetClassData() computes type_info_+56 (pointer arithmetic, no read)
   → reads data->is_initialized from reclaimed memory (type_info_+72)
   → calls 0xdeadbeefcafebabe(*this)
6. CPU executes: call *0x10(%rax) where *(rax+0x10) = 0xdeadbeefcafebabe
   → SIGSEGV (unmapped address; real exploit would use a valid gadget)
```

### PoC Output (upstream main, 128dee159)

```
[1] Factory at    0x562a14df8530
[2] Message at    0x562a14e07eb0
[3] type_info_ at 0x0000562a14e07670
[4] Destroyed factory, sprayed 2048 × 152 bytes
[5] Verifying: *(type_info_+72) = 0xdeadbeefcafebabe
    RECLAIM CONFIRMED: is_initialized = controlled value
[6] Final verify: *(type_info_+72) = 0xdeadbeefcafebabe
[7] Calling victim->IsInitialized()...

======== CRASH CAPTURED ========
  Signal:            SIGSEGV
  RIP:               0x00005629f3674dc1
  RAX:               0x0000562a14e076a8
  RDI (this):        0x0000562a14e07eb0
  si_addr:           (nil)
  *(RAX+0x10):       0xdeadbeefcafebabe  (indirect call target)
  Expected target:   0xdeadbeefcafebabe

  >>> CALL TARGET == CONTROLLED ADDRESS <<<
  >>> The CPU executed: call *0x10(%rax)
  >>>   where *(RAX+0x10) = 0xdeadbeefcafebabe
  >>> PROVES: UAF → heap reclaim → function pointer control
  >>>         → arbitrary code execution <<<
================================
```

### Independent UAF Access Paths (6 total, poc_dynamic_factory_uaf_v2.cc)

All confirmed under ASan:

| Variant | Operation | What's read from freed memory | Impact |
|---------|-----------|-------------------------------|--------|
| 1 | `GetReflection()` | ClassDataFull at type_info_+108 | Returns freed Reflection* — vtable/schema_ under attacker control |
| 2 | `GetInt32(field)` | offsets[] (scribbled 0xCDCDCDCD) | OOB read at msg+0xCDCDCDCC (~3.4GB) |
| 3 | `MergeFrom()` | merge_to_from fptr at type_info_+80 | Controlled function pointer call |
| 4 | `New()` | message_creator at type_info_+88 | Controlled function pointer call |
| 5 | `SerializeToString()` | is_initialized fptr at type_info_+72 | Controlled function pointer call |
| 6 | `~DynamicMessage()` | descriptor_ptr at type_info_+120 | Freed pointer dereference |

### Affected Code

- `dynamic_message.cc:484` — `DynamicMessage` stores raw `type_info_` pointer
- `dynamic_message.cc:855-857` — `GetClassData()` dereferences freed `type_info_`
- `dynamic_message.cc:868-872` — `~DynamicMessageFactory` deletes all TypeInfo
- `dynamic_message.cc:455-478` — `~TypeInfo` incomplete scribble mitigation
- `message_lite.cc:99-101` — `IsInitialized()` calls `data->is_initialized(*this)`

### Reproduce

```bash
# Build WITHOUT sanitizers (ASan quarantines freed memory, preventing reclamation)
CC=clang CXX=clang++ bazelisk build \
  --action_env=CC=clang --action_env=CXX=clang++ \
  src/google/protobuf/fuzz:poc_dynamic_factory_uaf_v3
./bazel-bin/src/google/protobuf/fuzz/poc_dynamic_factory_uaf_v3

# ASan confirmation of UAF (all 6 variants)
CC=clang CXX=clang++ bazelisk build \
  --copt=-fsanitize=address --linkopt=-fsanitize=address \
  --action_env=CC=clang --action_env=CXX=clang++ \
  src/google/protobuf/fuzz:poc_dynamic_factory_uaf_v2
./bazel-bin/src/google/protobuf/fuzz/poc_dynamic_factory_uaf_v2 --variant=1
```

### Suggested Fix

The factory should either prevent destruction while messages exist (reference counting on TypeInfo) or copy the required ClassData into each DynamicMessage instance so it doesn't depend on the factory's lifetime.

---

## Finding 2: CWE-476 — Placeholder ExtensionRange Null Pointer Dereference

### Summary

When `DescriptorPool::AllowUnknownDependencies()` is enabled and a `FileDescriptorProto` declares an extension that references an unknown extendee type, the pool creates a placeholder extendable message with `extension_ranges_[0].options_ = nullptr`. Calling `DebugString()` on this placeholder dereferences the null `options_` pointer, causing a segfault.

### Severity

**Medium** — Denial of service via null pointer dereference. Reachable through the public `DescriptorPool` API in any application that uses `AllowUnknownDependencies()` for dynamic schema loading (gRPC reflection, plugin systems, schema registries).

### Root Cause

- `descriptor.cc:5796` — placeholder extension ranges are created with `options_ = nullptr`
- `descriptor.h:591` — `ExtensionRange::options()` returns `*options_` without null check
- `descriptor.cc:3976` — `DebugString()` calls `extension_range(i)->options()` for formatting

### PoC Output

```
BuildFile succeeded. File has 1 extensions.
Extendee: UnknownMessage (placeholder=1)
Extension range count: 1
Extension range [0]: start=1, end=536870912
About to call DebugString() -- this will crash...
Segmentation fault
```

### Reproduce

```bash
bazelisk build src/google/protobuf/fuzz:poc_placeholder_nullptr
./bazel-bin/src/google/protobuf/fuzz/poc_placeholder_nullptr
```

### Suggested Fix

Initialize `options_` to `&ExtensionRangeOptions::default_instance()` for placeholder extension ranges, or add a null check in `ExtensionRange::options()`.

---

## Finding 3: CWE-476 — map_entry Field Count Null Dereference in TextFormat

### Summary

`TextFormat::PrintMessage()` unconditionally accesses `field(0)` and `field(1)` for messages with `map_entry: true`, without checking `field_count()`. A malformed `map_entry` descriptor with fewer than 2 fields causes an out-of-bounds access.

### Severity

**Low-Medium** — Denial of service. Requires constructing a malformed descriptor via `DescriptorPool` API.

### Root Cause

`ValidateMapEntry` (descriptor.cc:9388) correctly checks that a `map_entry` message has exactly 2 fields. However, it is only called from `ValidateField` (descriptor.cc:8924), which runs per-field on messages that reference the map entry as a field type. If no parent field references the map entry message, `ValidateField` is never invoked for that relationship, and the `map_entry` message passes through `BuildFile` without error.

`TextFormat::Printer::PrintMessage` (text_format.cc:2585-2587) then assumes any descriptor with `options().map_entry() == true` has at least 2 fields and unconditionally accesses `field(0)` and `field(1)`.

### Fix Included

The second commit in the PR adds:

1. **Root cause fix** in `descriptor.cc:CrossLinkMessage` — reject `map_entry` messages with != 2 fields unconditionally:
```cpp
if (message->options().map_entry() && message->field_count() != 2) {
  AddError(message->full_name(), proto, DescriptorPool::ErrorCollector::NAME,
           "Messages with map_entry set must have exactly 2 fields.");
}
```

2. **Defense in depth** in `text_format.cc:PrintMessage` — guard the field access:
```cpp
if (descriptor->options().map_entry() && descriptor->field_count() >= 2) {
```

### Reproduce

```bash
# Build the fuzzer reproducer
bazelisk build -c opt --copt=-fsanitize=address --linkopt=-fsanitize=address \
  src/google/protobuf/fuzz:repro_descriptor_database

echo 'LB8ACgp0ZXN0LnByb3RvIhEKA01zZzoKCgJmMTgBKAUgAh8ACnJydGUucm90' \
  | base64 -d > /tmp/crash-minimized

bazel-bin/src/google/protobuf/fuzz/repro_descriptor_database /tmp/crash-minimized
# SEGV on unknown address 0x00000000000c
```

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-23 | Vulnerabilities discovered via structure-aware fuzzing |
| 2026-05-23 | All PoCs confirmed on upstream main (128dee159) |
| 2026-05-23 | PR with PoCs and partial fix: https://github.com/jortles/protobuf/pull/1 |
| 2026-05-23 | OSS VRP report submitted |
