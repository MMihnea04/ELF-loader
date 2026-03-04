// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <errno.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	// create pointer to the ELF header
	Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *)elf_contents;

	// verify indices for the first 4 bytes of the file (magic bytes)
	if (elf_hdr->e_ident[EI_MAG0] != ELFMAG0 || elf_hdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    elf_hdr->e_ident[EI_MAG2] != ELFMAG2 || elf_hdr->e_ident[EI_MAG3] != ELFMAG3) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	// verify if the ELF file is 64-bit
	if (elf_hdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */

	uintptr_t load_base = 0;

	// allocate memory for PIE, verify it didn't fail and save address in load_base
	if (elf_hdr->e_type == ET_DYN) {
		void *pie_mem = mmap(NULL, 0x100000000UL, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (pie_mem == MAP_FAILED) {
			perror("mmap PIE base");
			exit(1);
		}

		load_base = (uintptr_t)pie_mem;
	}

	// pointer to the first program header
	Elf64_Phdr *prg_hdr = (Elf64_Phdr *)((char *)elf_contents + elf_hdr->e_phoff);

	// obtain page size, if not assume standard value
	long pg_size = sysconf(_SC_PAGESIZE);

	if (pg_size <= 0)
		pg_size = 4096;

	// iterate through all headers and if it's not PT_LOAD, ignore it
	for (int i = 0; i < elf_hdr->e_phnum; i++) {
		if (prg_hdr[i].p_type != PT_LOAD)
			continue;

		// calculate virtual address, align to page start,
		// the offset and adjust length to multiple of pg_size
		uintptr_t vr_addr = load_base + prg_hdr[i].p_vaddr;
		uintptr_t align_addr = vr_addr & ~(pg_size - 1);
		size_t pg_off = vr_addr - align_addr;
		size_t len = pg_off + prg_hdr[i].p_memsz;

		if (len % pg_size)
			len = ((len / pg_size) + 1) * pg_size;

		// map segment in memory with RWX permissions and verify it didn't fail
		void *mem_segm = mmap((void *)align_addr, len, PROT_READ | PROT_WRITE | PROT_EXEC,
					   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (mem_segm == MAP_FAILED) {
			perror("mmap PT_LOAD");
			exit(1);
		}

		// copy from file to mapped memory
		if (prg_hdr[i].p_filesz > 0)
			memcpy((char *)mem_segm + pg_off, (char *)elf_contents + prg_hdr[i].p_offset, prg_hdr[i].p_filesz);

		// fill with 0 the memory area not covered by the file
		if (prg_hdr[i].p_memsz > prg_hdr[i].p_filesz)
			memset((char *)mem_segm + pg_off + prg_hdr[i].p_filesz, 0, prg_hdr[i].p_memsz - prg_hdr[i].p_filesz);
	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	// iterate through all headers and if it's not PT_LOAD, ignore it
	for (int i = 0; i < elf_hdr->e_phnum; i++) {
		if (prg_hdr[i].p_type != PT_LOAD)
			continue;

		// calculate virtual address and segment length aligned to page start
		uintptr_t vr_addr = load_base + prg_hdr[i].p_vaddr;
		uintptr_t align_addr = vr_addr & ~(pg_size - 1);
		size_t pg_off = vr_addr - align_addr;
		size_t len = pg_off + prg_hdr[i].p_memsz;

		if (len % pg_size)
			len = ((len / pg_size) + 1) * pg_size;

		// set permissions based on flags
		int prot = 0;

		if (prg_hdr[i].p_flags & PF_R)
			prot |= PROT_READ;
		if (prg_hdr[i].p_flags & PF_W)
			prot |= PROT_WRITE;
		if (prg_hdr[i].p_flags & PF_X)
			prot |= PROT_EXEC;

		// apply the above permissions to mapped memory
		if (mprotect((void *)align_addr, len, prot) < 0) {
			perror("mprotect");
			exit(1);
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *sp = NULL;

	// count environment variables
	int env_cnt = 0;

	for (char **e = envp; e && *e; ++e)
		env_cnt++;

	// create the process stack of 8MB and verify it didn't fail
	size_t stack_sz = 8 * 1024 * 1024;
	char *stack_base = mmap(NULL, stack_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (stack_base == MAP_FAILED) {
		perror("mmap stack");
		exit(1);
	}

	// set cursor for writing in the stack
	char *stack_ptr = stack_base + stack_sz;

	// store address of each argument in the pointer vector
	char **argv_ptrs = malloc(sizeof(char *) * argc);

	if (!argv_ptrs) {
		perror("malloc");
		exit(1);
	}

	// copy arguments to stack and save address in argv_ptrs
	for (int i = argc - 1; i >= 0; i--) {
		size_t l = strlen(argv[i]) + 1;

		stack_ptr -= l;
		memcpy(stack_ptr, argv[i], l);
		argv_ptrs[i] = stack_ptr;
	}

	// same procedure, but for environment variables
	char **env_ptrs = NULL;

	if (env_cnt) {
		env_ptrs = malloc(sizeof(char *) * env_cnt);
		if (!env_ptrs) {
			perror("malloc");
			exit(1);
		}
		for (int i = env_cnt - 1; i >= 0; i--) {
			size_t l = strlen(envp[i]) + 1;

			stack_ptr -= l;
			memcpy(stack_ptr, envp[i], l);
			env_ptrs[i] = stack_ptr;
		}
	}

	// reserve 16 bytes for AT_RANDOM and initialize with random value
	stack_ptr -= 16;
	unsigned char *rnd = (unsigned char *)stack_ptr;

	for (int i = 0; i < 16; i++)
		rnd[i] = (unsigned char)(rand() & 0xff);

	// align stack to 16 bytes
	stack_ptr = (char *)((uintptr_t)stack_ptr & ~0xFUL);

	// find the address of the program header in memory
	Elf64_Addr at_phdr = 0;

	for (int i = 0; i < elf_hdr->e_phnum; i++) {
		if (prg_hdr[i].p_type != PT_LOAD)
			continue;
		if (elf_hdr->e_phoff >= prg_hdr[i].p_offset && elf_hdr->e_phoff < prg_hdr[i].p_offset + prg_hdr[i].p_filesz) {
			at_phdr = load_base + prg_hdr[i].p_vaddr + (elf_hdr->e_phoff - prg_hdr[i].p_offset);
			break;
		}
	}

	// create key vectors and set auxv vector for execution
	Elf64_Addr keys[] = {AT_RANDOM, AT_PAGESZ, AT_PHNUM, AT_PHENT, AT_PHDR, AT_ENTRY};
	Elf64_Addr vals[] = {(Elf64_Addr)rnd, (Elf64_Addr)pg_size, (Elf64_Addr)elf_hdr->e_phnum,
						(Elf64_Addr)sizeof(Elf64_Phdr), at_phdr, load_base + elf_hdr->e_entry};

	// add terminators for auxv to the stack
	stack_ptr -= sizeof(Elf64_Addr);
	*(Elf64_Addr *)stack_ptr = 0;
	stack_ptr -= sizeof(Elf64_Addr);
	*(Elf64_Addr *)stack_ptr = AT_NULL;

	// put key-value pairs for auxv on the stack
	for (int i = 5; i >= 0; i--) {
		stack_ptr -= sizeof(Elf64_Addr);
		*(Elf64_Addr *)stack_ptr = vals[i];
		stack_ptr -= sizeof(Elf64_Addr);
		*(Elf64_Addr *)stack_ptr = keys[i];
	}

	// put NULL terminator for envp
	stack_ptr -= sizeof(char *);
	*(char **)stack_ptr = NULL;

	// put environment variable pointers on the stack
	for (int i = env_cnt - 1; i >= 0; i--) {
		stack_ptr -= sizeof(char *);
		*(char **)stack_ptr = env_ptrs[i];
	}

	// put NULL terminator for argv
	stack_ptr -= sizeof(char *);
	*(char **)stack_ptr = NULL;

	// put argument pointers on the stack
	for (int i = argc - 1; i >= 0; i--) {
		stack_ptr -= sizeof(char *);
		*(char **)stack_ptr = argv_ptrs[i];
	}

	// put argc on the stack, on top of the argv list
	stack_ptr -= sizeof(uint64_t);
	*(uint64_t *)stack_ptr = (uint64_t)argc;

	sp = stack_ptr;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	typedef void (*entry_func)(void);
	entry_func entry = (entry_func)(uintptr_t)(load_base + elf_hdr->e_entry);

	// Transfer control
	__asm__ __volatile__(
		"mov %0, %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"jmp *%1\n"
		:
		: "r"(sp), "r"(entry)
		: "memory"
		);

}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
