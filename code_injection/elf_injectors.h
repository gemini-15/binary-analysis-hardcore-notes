#ifndef ELF_INJECTORS_H
#define ELF_INJECTORS_H


#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>


#define ABITAG_NAME ".note.ABI-tag"
#define SHSTRTAB_NAME ".shstrtab"


/**
 *  elf_data_t structure  
 *  Keeps track of data needed to manipulate the ELF binary in which the
 *  code section is to be injected. 
*/
typedef struct {
    int fd;         // File descriptor
    Elf *e;         // elf descriptor used to read and write data to an ELF file
    int bits;       // 32bit or 64 bit 
    GElf_Ehdr ehdr; // Executable header

} elf_data_t;


/**
 * inject_data_t structure 
 * Tracks information about the code to inject and where and how to inject
 * into the binary. 
*/
typedef struct {
    size_t pidx;    // index of the program header to be overwrite
    GElf_Phdr phdr; // Program header to overwrite (PT_NOTE)
    size_t sidx;    // index of section header to overwrite
    Elf_Scn *scn;   // Section to overwrite
    GElf_Shdr shdr; // Section header to overwrite
    off_t shstroff; // Offset to section to overwrite
    char *code;     // code to inject
    size_t len;     // number of bytes
    long entry;     // Code buffer to entry point 
    off_t off;      // file offset to injected code 
    size_t secaddr; // Section address for injected code
    char *secname;  // Section name for injected code
} inject_data_t;


int rewrite_entry_point(elf_data_t *elf, inject_data_t *inject);

int rewrite_code_segment(elf_data_t *elf, inject_data_t *inject);

int write_phdr(elf_data_t *elf, inject_data_t *inject);


int write_secname(elf_data_t *elf, inject_data_t *inject);


int reorder_shdrs(elf_data_t *elf, inject_data_t *inject);
/**
 * Write section header into elf object. 
*/
int write_section_header(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *section_header, size_t sidx);


/**
 * Rewrite the ABITAG_NAME section
 *
*/
int rewrite_section(elf_data_t *elf, inject_data_t *inject);


/**
 * add inject code into the elf binary. 
*/
int write_inject(elf_data_t *elf, inject_data_t *inject);


/**
 * Search for the PT_NOTE segment in the elf and adds the 
 * program header into inject.
*/
int find_pt_note_segment(elf_data_t *elf, inject_data_t *inject);


/**
 *  Section PT_NOTE injector
*/
int inject_code_section(int fd, inject_data_t *inject);


#endif