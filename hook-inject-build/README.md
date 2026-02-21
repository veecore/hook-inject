# hook-inject-build

Build-time and packaging helpers used by the `hook-inject` crate.

## What it provides

- Frida devkit platform and version resolution.
- Frida devkit download and extraction utilities.
- cdylib metadata discovery and build helpers.

This crate is primarily intended for internal use by `hook-inject` but is
published so `hook-inject` can depend on it in released builds.
