#include "frida_shim.h"
#include <frida-core.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

// Context owned by the Rust side; wraps Frida device + injector handles.
struct HookFridaCtx {
  FridaDeviceManager * manager;
  FridaDevice * device;
  FridaInjector * injector;
};

static gboolean
hook_debug_enabled(void) {
  return getenv("HOOK_INJECT_DEBUG") != NULL;
}

static void
hook_debug(const char * message) {
  if (hook_debug_enabled())
    g_printerr("%s\n", message);
}

// Map Frida/GLib errors into the small enum we expose to Rust.
static HookFridaErrorKind hook_error_kind_from_gerror(GError * err) {
  if (err == NULL)
    return HOOK_FRIDA_ERROR_RUNTIME;

  if (g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT))
    return HOOK_FRIDA_ERROR_INVALID_ARGUMENT;
  if (g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_PERMISSION_DENIED))
    return HOOK_FRIDA_ERROR_PERMISSION_DENIED;
  if (g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_PROCESS_NOT_FOUND))
    return HOOK_FRIDA_ERROR_PROCESS_NOT_FOUND;
  if (g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_NOT_SUPPORTED) ||
      g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED) ||
      g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_INVALID_OPERATION))
    return HOOK_FRIDA_ERROR_NOT_SUPPORTED;

  return HOOK_FRIDA_ERROR_RUNTIME;
}

// Store an error kind + a copied message for the Rust side.
static void hook_set_error(GError * err, int32_t * error_kind_out, char ** error_out) {
  if (error_kind_out != NULL) {
    if (err == NULL)
      *error_kind_out = HOOK_FRIDA_ERROR_NONE;
    else
      *error_kind_out = (int32_t) hook_error_kind_from_gerror(err);
  }

  if (error_out == NULL) {
    return;
  }

  if (err == NULL || err->message == NULL) {
    *error_out = g_strdup("unknown error");
  } else {
    *error_out = g_strdup(err->message);
  }
}

static gboolean
hook_should_try_device_fallback(GError * err) {
  if (err == NULL)
    return FALSE;

  return g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_NOT_SUPPORTED) ||
      g_error_matches(err, FRIDA_ERROR, FRIDA_ERROR_PERMISSION_DENIED);
}

HookFridaCtx *
hook_frida_new(int32_t * error_kind_out, char ** error_out) {
  // Initialize Frida and create a local-device injector.
  frida_init();
  hook_debug("hook-frida: frida_init done");

  HookFridaCtx * ctx = g_new0(HookFridaCtx, 1);
  ctx->manager = frida_device_manager_new();
  hook_debug("hook-frida: device manager created");
  // Prefer the helper injector for broader macOS compatibility.
  const char * mode = getenv("HOOK_INJECT_INJECTOR");
  if (mode != NULL && g_strcmp0(mode, "inprocess") == 0) {
    ctx->injector = frida_injector_new_inprocess();
  } else {
    ctx->injector = frida_injector_new();
  }
  hook_debug("hook-frida: injector created");

  GError * error = NULL;
  ctx->device = frida_device_manager_get_device_by_type_sync(
      ctx->manager,
      FRIDA_DEVICE_TYPE_LOCAL,
      0,
      NULL,
      &error);
  hook_debug("hook-frida: device lookup finished");
  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    hook_frida_free(ctx);
    return NULL;
  }

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return ctx;
}

void
hook_frida_free(HookFridaCtx * ctx) {
  // Release Frida objects and shut down the library.
  if (ctx == NULL)
    return;

  if (ctx->device != NULL)
    g_object_unref(ctx->device);
  if (ctx->manager != NULL)
    g_object_unref(ctx->manager);
  if (ctx->injector != NULL)
    g_object_unref(ctx->injector);

  g_free(ctx);
  frida_shutdown();
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
  if (ctx == NULL || ctx->injector == NULL)
    return 0;

  hook_debug("hook-frida: inject_process starting");
  // Inject the library into an existing process.
  GError * error = NULL;
  guint id = frida_injector_inject_library_file_sync(
      ctx->injector,
      (guint) pid,
      library_path,
      entrypoint,
      data,
      NULL,
      &error);

  if (error != NULL && hook_should_try_device_fallback(error) && ctx->device != NULL) {
    hook_debug("hook-frida: inject_process helper failed, trying device fallback");
    g_error_free(error);
    error = NULL;
    id = frida_device_inject_library_file_sync(
        ctx->device,
        (guint) pid,
        library_path,
        entrypoint,
        data,
        NULL,
        &error);
  }

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (out_id != NULL)
    *out_id = id;

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
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
  if (ctx == NULL || ctx->injector == NULL)
    return 0;

  // Inject from an in-memory library blob.
  GError * error = NULL;
  GBytes * bytes = g_bytes_new(blob, blob_len);

  guint id = frida_injector_inject_library_blob_sync(
      ctx->injector,
      (guint) pid,
      bytes,
      entrypoint,
      data,
      NULL,
      &error);

  if (error != NULL && hook_should_try_device_fallback(error) && ctx->device != NULL) {
    g_error_free(error);
    error = NULL;
    id = frida_device_inject_library_blob_sync(
        ctx->device,
        (guint) pid,
        bytes,
        entrypoint,
        data,
        NULL,
        &error);
  }

  g_bytes_unref(bytes);

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (out_id != NULL)
    *out_id = id;

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
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
  if (ctx == NULL || ctx->device == NULL || ctx->injector == NULL)
    return 0;

  // Spawn the process suspended, inject, and resume.
  FridaSpawnOptions * options = frida_spawn_options_new();
  if (argv != NULL)
    g_object_set(options, "argv", argv, NULL);
  if (envp != NULL)
    g_object_set(options, "envp", envp, NULL);
  if (cwd != NULL)
    g_object_set(options, "cwd", cwd, NULL);
  g_object_set(options, "stdio", stdio, NULL);

  GError * error = NULL;
  guint pid = frida_device_spawn_sync(ctx->device, program, options, NULL, &error);
  g_object_unref(options);

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  guint id = frida_injector_inject_library_file_sync(
      ctx->injector,
      pid,
      library_path,
      entrypoint,
      data,
      NULL,
      &error);

  if (error != NULL && hook_should_try_device_fallback(error) && ctx->device != NULL) {
    g_error_free(error);
    error = NULL;
    id = frida_device_inject_library_file_sync(
        ctx->device,
        pid,
        library_path,
        entrypoint,
        data,
        NULL,
        &error);
  }

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  frida_device_resume_sync(ctx->device, pid, NULL, &error);
  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (out_pid != NULL)
    *out_pid = pid;
  if (out_id != NULL)
    *out_id = id;

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
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
  if (ctx == NULL || ctx->device == NULL)
    return 0;

  // Spawn the process suspended; caller is responsible for resuming.
  FridaSpawnOptions * options = frida_spawn_options_new();
  if (argv != NULL)
    g_object_set(options, "argv", argv, NULL);
  if (envp != NULL)
    g_object_set(options, "envp", envp, NULL);
  if (cwd != NULL)
    g_object_set(options, "cwd", cwd, NULL);
  g_object_set(options, "stdio", stdio, NULL);

  GError * error = NULL;
  guint pid = frida_device_spawn_sync(ctx->device, program, options, NULL, &error);
  g_object_unref(options);

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (out_pid != NULL)
    *out_pid = pid;

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
}

int
hook_frida_resume(HookFridaCtx * ctx,
    uint32_t pid,
    int32_t * error_kind_out,
    char ** error_out) {
  if (ctx == NULL || ctx->device == NULL)
    return 0;

  // Resume a process spawned in suspended mode.
  GError * error = NULL;
  frida_device_resume_sync(ctx->device, pid, NULL, &error);

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
}

int
hook_frida_demonitor(HookFridaCtx * ctx,
    uint32_t id,
    int32_t * error_kind_out,
    char ** error_out) {
  if (ctx == NULL || ctx->injector == NULL)
    return 0;

  // Stop monitoring the injection.
  GError * error = NULL;
  frida_injector_demonitor_sync(ctx->injector, id, NULL, &error);

  if (error != NULL) {
    hook_set_error(error, error_kind_out, error_out);
    g_error_free(error);
    return 0;
  }

  if (error_kind_out != NULL)
    *error_kind_out = HOOK_FRIDA_ERROR_NONE;
  return 1;
}

void
hook_frida_string_free(char * s) {
  // Free strings returned to Rust.
  if (s != NULL)
    g_free(s);
}
