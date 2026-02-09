#include "frida_shim.h"
#include <stdlib.h>
#include <string.h>

// Tiny strdup replacement for the stub build (no glib dependency).
static char * hook_stub_strdup(const char * msg) {
  size_t len = strlen(msg) + 1;
  char * out = (char *) malloc(len);
  if (out == NULL)
    return NULL;
  memcpy(out, msg, len);
  return out;
}

// Fill the error outputs with a simple runtime-unavailable message.
static void hook_stub_set_error(int32_t * error_kind_out, char ** error_out, const char * msg) {
  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_RUNTIME;

  if (error_out == NULL)
    return;

  if (msg == NULL)
    msg = "frida runtime unavailable";

  *error_out = hook_stub_strdup(msg);
}

HookFridaCtx *
hook_frida_new(int32_t * error_kind_out, char ** error_out) {
  // Stub build always fails to initialize.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return NULL;
}

void
hook_frida_free(HookFridaCtx * ctx) {
  // Nothing to free in the stub build.
  (void) ctx;
}

int
hook_frida_inject_process(HookFridaCtx * ctx,
    int32_t pid,
    const char * library_path,
    const char * entrypoint,
    const char * data,
    uint32_t * out_id,
    int32_t * error_kind_out,
    char ** error_out) {
  (void) ctx;
  (void) pid;
  (void) library_path;
  (void) entrypoint;
  (void) data;
  (void) out_id;
  // Injection is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

int
hook_frida_inject_blob(HookFridaCtx * ctx,
    int32_t pid,
    const uint8_t * blob,
    size_t blob_len,
    const char * entrypoint,
    const char * data,
    uint32_t * out_id,
    int32_t * error_kind_out,
    char ** error_out) {
  (void) ctx;
  (void) pid;
  (void) blob;
  (void) blob_len;
  (void) entrypoint;
  (void) data;
  (void) out_id;
  // Injection is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

int
hook_frida_inject_launch(HookFridaCtx * ctx,
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
    char ** error_out) {
  (void) ctx;
  (void) program;
  (void) argv;
  (void) envp;
  (void) cwd;
  (void) stdio;
  (void) library_path;
  (void) entrypoint;
  (void) data;
  (void) out_pid;
  (void) out_id;
  // Launch+inject is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

int
hook_frida_spawn(HookFridaCtx * ctx,
    const char * program,
    const char * const * argv,
    const char * const * envp,
    const char * cwd,
    int32_t stdio,
    uint32_t * out_pid,
    int32_t * error_kind_out,
    char ** error_out) {
  (void) ctx;
  (void) program;
  (void) argv;
  (void) envp;
  (void) cwd;
  (void) stdio;
  (void) out_pid;
  // Spawn is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

int
hook_frida_resume(HookFridaCtx * ctx,
    uint32_t pid,
    int32_t * error_kind_out,
    char ** error_out) {
  (void) ctx;
  (void) pid;
  // Resume is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

int
hook_frida_demonitor(HookFridaCtx * ctx,
    uint32_t id,
    int32_t * error_kind_out,
    char ** error_out) {
  (void) ctx;
  (void) id;
  // Uninject is unavailable in the stub build.
  hook_stub_set_error(error_kind_out, error_out, "frida runtime unavailable (stub)");
  return 0;
}

void
hook_frida_string_free(char * s) {
  // Free strings allocated by hook_stub_strdup.
  free(s);
}
