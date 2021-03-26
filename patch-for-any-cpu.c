/* Copyright (C) 2008-2011 Ricardo Catalinas Jiménez <jimenezrick@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * It removes the `cmp/cmpl' instructions near a `cpuid' one used to test
 * the vendor string of the CPU. Works on ELF binaries and shared libraries.
 *
 * Tested with Intel C Compiler 16.0.8.266. It might also work with
 * next versions of the compiler.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <gelf.h>

#define PRINT_ERROR_MESSAGE(message, print_help_message) print_error_message(__LINE__, message, print_help_message)
#define PRINT_ERRNO() print_errno(__LINE__)
#define PRINT_ELF_ERRNO() print_elf_errno(__LINE__)

/* The compiler always uses a CPUID instruction before the string comparison. */
#define CPUID_BYTES_DISTANCE 2048

/* The instruction used to test the CPU string depends on the version of the compiler:
 * - Until ICC 10.x the instruction was `cmp $value,%eax' with opcode
 *   `0x3d, value'.
 *
 * - From ICC 11.x and onwards the instruction is `cmpl $value,disp(%rbp)'
 *   with opcode `0x81, 0x7d, disp, value'.
 *
 * - For at least 16.0.x the instruction becomes `cmpl $value,disp(%rsp)'
 *   with opcode `0x81, 0x7c, disp, value'
 */
enum {
	CMP_OPCODE = 0x3d,
	CMPL_OPCODE1 = 0x81,
	CMPL_OPCODE2 = 0x7d,
};

char *PROGRAM_NAME;

struct {
	bool verbose;
	bool analyze_elf;
	bool read_only;
	bool replace_complete_string;
	bool patch_all_sections;
	int cpuid_bytes_distance;
} options;

void print_help(void)
{
	printf("Usage: patch-for-any-cpu [-e] [-c] [-d <bytes_distance>] [-a] [-r] [-v] <executable_to_patch> | -h\n\n"
			"The executable to patch must be an\n"
			"ELF program or an ELF shared library.\n\n"
			"-e:\tdon't analyze the ELF structure, just do the substitutions in all the binary\n"
			"\tfile. By default the substitutions are done only in executable sections of the binary.\n"
			"-c: don't replace the complete vendor string, just any partial occurrence of it.\n"
			"-d: set the max number of bytes between a CPUID instruction and a substitution.\n"
			"\tThe default value is %i. A zero value disables this check.\n"
			"-a: patch all sections of the ELF executable, even if these sections aren't\n"
			"\tmachine code. By default only patch executable sections.\n"
			"-r: work on read-only mode. Try to use in conjunction with the \"-v\" option.\n"
			"-v: give verbose output.\n"
			"-h: print this help.\n", CPUID_BYTES_DISTANCE);
}

void print_error_message(int line_number, char *message, bool print_help_message)
{
	fprintf(stderr, "%s (line %i): %s\n", PROGRAM_NAME, line_number, message);
	if (print_help_message)
		print_help();
	exit(1);
}

void print_errno(int line_number)
{
	char str[100];

	snprintf(str, 100, "%s (line %i)", PROGRAM_NAME, line_number);
	perror(str);
	exit(2);
}

void print_elf_errno(int line_number)
{
	int err;

	if ((err = elf_errno()) != 0) {
		fprintf(stderr, "%s (line %i): %s\n", PROGRAM_NAME, line_number, elf_errmsg(err));
		exit(3);
	}
}

/* `start_address' contains NULL when called with `mmap', so we can calculate the address
 * in the file of the interesting byte. But when called with `libelf', `start_address'
 * has each time is called the real start address of the section in the executable
 * when this is loaded to memory by the operating system.
 */
int nop_patch(unsigned char *data, GElf_Xword data_size, unsigned char *start_address)
{
	int substitutions = 0;
	size_t cpuid_occurrence = SSIZE_MAX;

	size_t i = 0;
	while (i < data_size) {
		unsigned char *p;
		static const unsigned char cpuid_bytes[2] = { 0x0f, 0xa2 };
		p = memmem(data+i, data_size - i, cpuid_bytes, sizeof(cpuid_bytes));
		if (!p || p == data+data_size-2)
			goto end_of_cpuid_search;
		i = (size_t)(p - data);
		cpuid_occurrence = i;
		if (options.verbose)
			printf("\t---> CPUID instruction found at %p\n",
				   start_address + cpuid_occurrence);
		i+=2;

		/*
		 * In a typical binary, the following 4 byte sequences
		 * static const char search_words[3][4] = {"Genu", "ineI" ,"ntel"};
		 * are compared against the result of cpuid by instructions like
		 * 0x81, 0x7c, 0x24, 0xfc, 0x69, 0x6e, 0x65, 0x49
		 * which translates to
		 * cmpl   $0x49656e69,-0x4(%rsp)
		 * this compare is followed by a conditional jump
		 * to disable that superfluous check, both are replaced by a nop
		 */
		uint64_t mask_cmpl = UINT64_C(0xffffffff0000ffff),
			ptrn_cmpl_ineI = UINT64_C(0x49656e6900007c81),
			ptrn_cmpl_Genu = UINT64_C(0x756e654700007c81),
			ptrn_cmpl_ntel = UINT64_C(0x6c65746e00007c81),
			mask_cmp =      UINT64_C(0x000000ffffffffff),
			ptrn_cmp_ineI = UINT64_C(0x00000049656e693d),
			ptrn_cmp_Genu = UINT64_C(0x000000756e65473d),
			ptrn_cmp_ntel = UINT64_C(0x0000006c65746e3d);
		/* position at maximal distance from cpuid */
		size_t m = i + options.cpuid_bytes_distance < data_size
			? i + options.cpuid_bytes_distance : data_size - 1;
		uint64_t accum = 0;
		for (size_t j = m; j >= i; --j) {
			accum = (accum << 8) | data[j];
			static const unsigned char
				nop10[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00,
							0x0f, 0x1f, 0x44, 0x00, 0x00 },
				nop7[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x66, 0x90 };
			const unsigned char *nop_src;
			size_t nop_size, cmp_size;
			if ((accum & mask_cmpl) == ptrn_cmpl_ineI
				|| (accum & mask_cmpl) == ptrn_cmpl_Genu
				|| (accum & mask_cmpl) == ptrn_cmpl_ntel) {
				nop_src = nop10;
				nop_size = sizeof(nop10);
				cmp_size = 8;
			} else if ((accum & mask_cmp) == ptrn_cmp_ineI
					   || (accum & mask_cmp) == ptrn_cmp_Genu
					   || (accum & mask_cmp) == ptrn_cmp_ntel) {
				nop_src = nop7;
				nop_size = sizeof(nop7);
				cmp_size = 5;
			} else {
				/* jump to next byte if no match is found */
				continue;
			}
			if (data[j+cmp_size] != 0x75)
				continue;
			if (options.verbose) {
				printf("\t---> Patching out test instructions at %p\n",
					   start_address + j);
				char sbuf[nop_size*6+2];
				for (size_t k = 0; k < nop_size; ++k)
					sprintf(sbuf+k*6, "%s0x%02x", k > 0 ? ", " : "\t\t",
							data[j+k]);
				sbuf[nop_size*6] = '\n', sbuf[nop_size*6+1] = '\0';
				fputs(sbuf, stdout);
			}
			if (!options.read_only) {
				/* replace cmpl/cmp and jne following it */
				assert(data_size-j >= nop_size);
				++substitutions;
				memcpy(data+j, nop_src, nop_size);
			}
		}
	}
end_of_cpuid_search:
	return substitutions;
}

int analyze_elf_binary(int file_descriptor, unsigned char *file_data)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		PRINT_ELF_ERRNO();
	Elf *elf_handle = elf_begin(file_descriptor, ELF_C_READ, NULL);
	if (!elf_handle)
		PRINT_ELF_ERRNO();
	GElf_Ehdr elf_executable_header;
	if (gelf_getehdr(elf_handle, &elf_executable_header) == NULL)
		PRINT_ELF_ERRNO();

	switch(elf_kind(elf_handle)) {
		case ELF_K_NUM:
		case ELF_K_NONE:
			PRINT_ERROR_MESSAGE("file type unknown", false);
			break;
		case ELF_K_COFF:
			PRINT_ERROR_MESSAGE("COFF binaries not supported", false);
			break;
		case ELF_K_AR:
			PRINT_ERROR_MESSAGE("AR archives not supported", false);
			break;
		case ELF_K_ELF:
			if (options.verbose) {
				if (gelf_getclass(elf_handle) == ELFCLASS32)
					printf("Reading 32-bit ELF binary");
				else
					printf("Reading 64-bit ELF binary");

				if (options.read_only)
					printf(" in read-only mode\n");
				else
					printf("\n");
			}
			break;
	}

	int replacements = 0;
	Elf_Scn *section = NULL;
	while ((section = elf_nextscn(elf_handle, section)) != NULL) {
		GElf_Shdr section_header;
		if (gelf_getshdr(section, &section_header) != &section_header)
			PRINT_ELF_ERRNO();

		const char *section_name
			= elf_strptr(elf_handle, elf_executable_header.e_shstrndx,
						 section_header.sh_name);
		if (!section_name)
			PRINT_ELF_ERRNO();

		if (options.verbose && !(section_header.sh_flags & SHF_EXECINSTR))
			printf("* Section %s\n", section_name);
		else if (options.verbose)
			printf("* Section %s is executable\n", section_name);

		if (section_header.sh_flags & SHF_EXECINSTR || options.patch_all_sections) {
			/* Avoid the `.bss' section, it doesn't exist in the binary file. */
			if (strcmp(section_name, ".bss")) {
				replacements += nop_patch(file_data + section_header.sh_offset,
						section_header.sh_size,
						(unsigned char *) section_header.sh_addr);
			}
		}
	}
	PRINT_ELF_ERRNO(); /* If there isn't elf_errno set, nothing will happen. */

	elf_end(elf_handle);

	return replacements;
}

int main(int argc, char *argv[])
{
	int option, file_descriptor;
	char *file_name;
	struct stat file_information;
	unsigned char *file_data;
	int replacements;

	PROGRAM_NAME = argv[0];
	if (argc < 2)
		PRINT_ERROR_MESSAGE("you must specify an executable to patch", true);

	options.verbose = false;
	options.analyze_elf = true;
	options.read_only = false;
	options.replace_complete_string = true;
	options.patch_all_sections = false;
	options.cpuid_bytes_distance = CPUID_BYTES_DISTANCE;

	while ((option = getopt(argc, argv, "ecd:ars:vh")) != -1) {
		switch(option) {
			case 'e':
				options.analyze_elf = false;
				break;
			case 'c':
				options.replace_complete_string = false;
				break;
			case 'd':
				options.cpuid_bytes_distance = atoi(optarg);
				break;
			case 'a':
				options.patch_all_sections = true;
				break;
			case 'r':
				options.read_only = true;
				break;
			case 'v':
				options.verbose = true;
				break;
			case 'h':
				print_help();
				return 0;
			default:
				PRINT_ERROR_MESSAGE("unknown option\n", true);
				break;
		}
	}
	file_name = argv[argc - 1];

	if (options.read_only) {
		if ((file_descriptor = open(file_name, O_RDONLY)) == -1)
			PRINT_ERRNO();
	} else {
		if ((file_descriptor = open(file_name, O_RDWR)) == -1)
			PRINT_ERRNO();
	}

	if (fstat(file_descriptor, &file_information) == -1)
		PRINT_ERRNO();

	if (options.read_only) {
		if ((file_data = mmap(NULL, file_information.st_size, PROT_READ, MAP_PRIVATE,
						file_descriptor, 0)) == MAP_FAILED)
			PRINT_ERRNO();
	} else {
		if ((file_data = mmap(NULL, file_information.st_size, PROT_READ | PROT_WRITE,
						MAP_SHARED, file_descriptor, 0)) == MAP_FAILED)
			PRINT_ERRNO();
	}

	if (options.analyze_elf) {
		/*
		 * Here we use `libelf' to look at the ELF structure to find the executable
		 * sections where the machine code is located (sections like `.text'). Then
		 * we do the substitutions only on that sections through the mmaped file.
		 * So what we need is look for the offset where those sections start and also
		 * get their lenghts.
		 */
		replacements = analyze_elf_binary(file_descriptor, file_data);
	} else {
		/*
		 * Here we just mmap the file and search in all its content in order to do
		 * the substitutions.
		 */
		replacements = nop_patch(file_data, file_information.st_size, NULL);
	}

	if (options.verbose && !options.read_only && replacements)
		printf("Writing changes to the binary\n");
	munmap(file_data, file_information.st_size);
	close(file_descriptor);

	return 0;
}

/**
 * Local Variables:
 * indent-tabs-mode: t
 * tab-width: 4
 * c-basic-offset: 4
 * c-file-style: "k&r"
 * End:
 */
