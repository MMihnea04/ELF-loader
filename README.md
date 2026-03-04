# ELF Loader, a minimal ELF loader for Linux

This project implements a compact, educational ELF loader for Linux systems. It is designed to demonstrate how the kernel loads and prepares statically linked ELF executables for execution, rather than to provide a production-ready loader. The focus is correctness and understanding of ELF internals, virtual memory, and process initialization, not performance or feature completeness.

The loader supports loading and executing statically linked ELF binaries by manually mapping their segments into memory, setting correct permissions, constructing a valid process stack, and transferring control to the program entry point.

---

## Overview

The loader works directly with ELF files and reimplements, in user space, a subset of the functionality normally handled by the Linux kernel. It parses ELF headers, maps loadable segments, applies memory protections, prepares the initial stack layout expected by libc, and finally jumps to the executable’s entry point.

The implementation is incremental and closely follows the structure of a typical operating systems assignment, with clearly separated stages for validation, loading, stack setup, and PIE handling.

---

## Supported Executable Types

The loader currently supports the following types of executables:

Minimal statically linked ELF binaries that perform direct Linux syscalls and do not rely on libc.

Statically linked non-PIE executables built with libc, for example using `gcc -static`.

Statically linked PIE (Position Independent Executable) binaries, which are loaded at a random base address.

Dynamically linked executables and runtime dynamic linking are not supported.

---

## How It Works

The loader reads the ELF file into memory and validates its header to ensure it is a valid 64-bit ELF file. It then iterates over the program headers and maps each `PT_LOAD` segment into memory using `mmap`, taking care to align mappings to page boundaries and to correctly handle the difference between `p_filesz` and `p_memsz`.

For minimal syscall-only binaries, all segments can initially be mapped with read, write, and execute permissions. For more complete executables, the loader applies the correct memory protections based on the `p_flags` field of each program header.

When loading executables that depend on libc, the loader constructs a new process stack from scratch. This includes placing `argc`, the `argv` pointers, environment variables, and a correctly formed auxiliary vector on the stack. Special care is taken to provide required auxiliary vector entries such as `AT_PAGESZ`, `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`, and `AT_RANDOM`, as missing or incorrect values will cause libc startup to fail.

For PIE executables, the loader chooses a random load base and adjusts all virtual addresses, including the entry point and auxiliary vector values, accordingly.

Once memory mapping and stack setup are complete, the loader switches the stack pointer to the newly constructed stack and transfers execution to the ELF entry point.

---

## Usage

The loader is invoked from the command line and receives the path to a static ELF binary, followed by optional arguments that will be passed to the loaded program.

Example usage:

    ./elf-loader ./tests/snippets/no_pie arg1 arg2 arg3

The arguments provided after the ELF path are placed on the new stack and become the `argv` of the loaded executable.

---

## Project Structure

The main implementation resides in the `src` directory and consists of a single C source file implementing the loader logic. The `tests` directory contains a collection of small C and assembly programs used to validate the loader’s functionality, along with a Makefile and helper scripts for running the checker.

---

## Building and Testing

Test binaries can be built by running `make` inside the `tests` directory. To validate the loader in an environment similar to the automated grading system, a checker script is provided and can be executed using `./local.sh checker`.

Manual testing can also be performed by directly invoking the loader with one of the compiled test binaries.

---

## Debugging

Debugging is typically done using `gdb`, combined with tools such as `readelf`, `objdump`, and `pmap`. When debugging code inside the loaded ELF binary, symbols can be attached manually using `add-symbol-file` with the correct `.text` base address.

Crashes inside `__libc_start_main` usually indicate problems with stack layout, auxiliary vector entries, or incorrect memory mapping sizes.

---

## Memory Management

The loader itself does not maintain a global allocator for loaded segments. All memory mappings are created explicitly using `mmap`, and any additional heap allocations performed by the loader are the responsibility of the loader code. No automatic cleanup is performed after transferring control to the loaded program.

---

## Limitations

Only statically linked ELF binaries are supported. There is no support for dynamic linking, symbol resolution, or interpreters such as `ld.so`. The loader is intended purely for learning and experimentation and is not suitable for running large or complex applications.
