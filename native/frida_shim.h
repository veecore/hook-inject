#ifndef HOOK_INJECT_FRIDA_SHIM_H
#define HOOK_INJECT_FRIDA_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HookFridaCtx HookFridaCtx;

// Error kinds mirrored into Rust for stable error categorization.
typedef enum {
  HOOK_FRIDA_ERROR_NONE = 0,
  HOOK_FRIDA_ERROR_INVALID_ARGUMENT = 1,
  HOOK_FRIDA_ERROR_NOT_SUPPORTED = 2,
  HOOK_FRIDA_ERROR_PERMISSION_DENIED = 3,
  HOOK_FRIDA_ERROR_PROCESS_NOT_FOUND = 4,
  HOOK_FRIDA_ERROR_RUNTIME = 5
} HookFridaErrorKind;

// Create a Frida injector context for the local device.
HookFridaCtx * hook_frida_new(int32_t * error_kind_out, char ** error_out);
// Release all Frida resources held by the context.
void hook_frida_free(HookFridaCtx * ctx);

// Inject a library file into an existing process.
int hook_frida_inject_process(HookFridaCtx * ctx,
    int32_t pid,
    const char * library_path,
    const char * entrypoint,
    const char * data,
    uint32_t * out_id,
    int32_t * error_kind_out,
    char ** error_out);

// Inject an in-memory library blob into an existing process.
int hook_frida_inject_blob(HookFridaCtx * ctx,
    int32_t pid,
    const uint8_t * blob,
    size_t blob_len,
    const char * entrypoint,
    const char * data,
    uint32_t * out_id,
    int32_t * error_kind_out,
    char ** error_out);

// Spawn a process suspended, inject, then resume it.
int hook_frida_inject_launch(HookFridaCtx * ctx,
    const char * program,
    const char * const * argv,
    const char * const * envp,
    const char * cwd,
    int32_t stdio,
    const char * library_path,
    const char * entrypoint,
    const char * data,
    uint32_t * out_pid,
    uint32_t * out_id,
    int32_t * error_kind_out,
    char ** error_out);

// Spawn a process suspended without injecting.
int hook_frida_spawn(HookFridaCtx * ctx,
    const char * program,
    const char * const * argv,
    const char * const * envp,
    const char * cwd,
    int32_t stdio,
    uint32_t * out_pid,
    int32_t * error_kind_out,
    char ** error_out);

// Resume a suspended process previously spawned by Frida.
int hook_frida_resume(HookFridaCtx * ctx,
    uint32_t pid,
    int32_t * error_kind_out,
    char ** error_out);

// Stop monitoring a previously injected library.
int hook_frida_demonitor(HookFridaCtx * ctx,
    uint32_t id,
    int32_t * error_kind_out,
    char ** error_out);

// Free error strings returned by this shim.
void hook_frida_string_free(char * s);

#ifdef __cplusplus
}
#endif

#endif
