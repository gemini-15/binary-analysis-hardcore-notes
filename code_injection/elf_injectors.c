#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>

#include "elf_injectors.h"





int find_pt_note_segment(elf_data_t *elf, inject_data_t *inject) {
    int ret; 
    size_t number_headers;

    ret = elf_getphdrnum(elf->e, &number_headers);
    if (ret != 0) {
        fprintf(stderr, "[x] Can't find any program header.\n");
        return -1;
    }

    for (size_t i = 0; i<number_headers; i++) {
        if (!gelf_getphdr(elf->e, i, &inject->phdr)) {
            fprintf(stderr, "[x] Can't get program header.\n");
            return -1;
        }

        if (inject->phdr.p_type == PT_NOTE) {
            printf("[+] Segment PT_NOTE found.");
            inject->pidx = i;
            return 0;
        }
    }

    fprintf(stderr, "[x] Segment PT_NOTE not found in binary.\n");
    return -1;
}


int write_inject(elf_data_t *elf, inject_data_t *inject) {
    off_t off;
    size_t num_bytes_written; 

    // We go to the end of the file and get the last offset
    off = lseek(elf->fd, 0, SEEK_END);
    if (off < 0) {
        fprintf(stderr, "[x] lseek failed.\n");
    }

    // we write the buffer code into the file descriptor of elf.
    num_bytes_written = write(elf->fd, inject->code, inject->len);
    if ( num_bytes_written != inject->len ) {
        fprintf(stderr, "[x] Failed to inject code.\n");
        return -1;
    }
    printf("[+] Number of bytes written : %d \n", num_bytes_written);

    // the offset of the inject code begins at the end of the binary
    inject->off = off;
    printf("[+] Offset of the injected code at : %x \n", off);
    
    return 0;
}   

int write_section_header(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *section_header, size_t sidx) {
    off_t off;
    size_t n, shdr_size;
    void *shdr_buf; 

    if (!gelf_update_shdr(scn, section_header)) {
        fprintf(stderr, "[x] Failed to update section header.\n");
        return -1; 
    }

    if (elf->bits == 32) {
        shdr_buf = elf32_getshdr(scn);
        shdr_size = sizeof(Elf32_Shdr);
    } else {
        shdr_buf = elf64_getshdr(scn);
        shdr_size = sizeof(Elf64_Shdr);
    }
    
    if (!shdr_buf) {
        fprintf(stderr, "[x] Failed to get section header.\n");
        return -1; 
    }

    off = lseek(elf->fd, elf->ehdr.e_shoff + sidx*elf->ehdr.e_shentsize, SEEK_SET);
    if (off < 0) {
        fprintf(stderr, "[x] Lseek failed.\n");
        return -1;
    }

    n = write(elf->fd, shdr_buf, shdr_size);
    if (n != shdr_size) {
        fprintf(stderr, "[x] Failed to write section header.\n");
        return -1;
    }

    return 0; 

}

int reorder_shdrs(elf_data_t *elf, inject_data_t *inject) {
    int direction, skip;
    size_t i; 
    Elf_Scn *scn; 
    GElf_Shdr shdr; 

    direction = 0;

    scn = elf_getscn(elf->e, inject->sidx -1); 
    if (scn && !gelf_getshdr(scn , &shdr))
    {
        fprintf(stderr, "[x] Failed to get section header.\n");
        return -1;
    }

 if(scn && shdr.sh_addr > inject->shdr.sh_addr) {
    /* Injected section header must be moved left */
    direction = -1;
  }

  scn = elf_getscn(elf->e, inject->sidx + 1);
  if(scn && !gelf_getshdr(scn, &shdr)) {
    fprintf(stderr, "Failed to get section header\n");
    return -1;
  }

  if(scn && shdr.sh_addr < inject->shdr.sh_addr) {
    /* Injected section header must be moved right */
    direction = 1;
  }

  if(direction == 0) {
    /* Section headers are already in order */
    return 0;
  }

  i = inject->sidx;

  /* Order section headers by increasing address */
  skip = 0;
  for(scn = elf_getscn(elf->e, inject->sidx + direction); 
      scn != NULL;
      scn = elf_getscn(elf->e, inject->sidx + direction + skip)) {

    if(!gelf_getshdr(scn, &shdr)) {
      fprintf(stderr, "Failed to get section header\n");
      return -1;
    }

    if((direction < 0 && shdr.sh_addr <= inject->shdr.sh_addr)
       || (direction > 0 && shdr.sh_addr >= inject->shdr.sh_addr)) {
      /* The order is okay from this point on */
      break;
    }

    /* Only reorder code section headers */
    if(shdr.sh_type != SHT_PROGBITS) {
      skip += direction;
      continue;
    }

    /* Swap the injected shdr with its neighbor PROGBITS header */
    if(write_shdr(elf, scn, &inject->shdr, elf_ndxscn(scn)) < 0) {
      return -1;
    }

    if(write_shdr(elf, inject->scn, &shdr, inject->sidx) < 0) {
      return -1;
    }

    inject->sidx += direction + skip;
    inject->scn = elf_getscn(elf->e, inject->sidx);
    skip = 0;
  }

  return 0;
}


int rewrite_section(elf_data_t *elf, inject_data_t *inject) {
    Elf_Scn *scn; // Elf_Scn descriptors represent sections in an ELF object.
    GElf_Shdr section_header; // Section header
    char *s; 
    size_t shstrndx;

    // retrieve the section index of the section name string table in a ELF Object. 
    if (elf_getshdrstrndx(elf->e, &shstrndx) < 0){
        fprintf(stderr, "[x] Failed to get string table section index.\n");
        return -1; 
    }

    scn = NULL; 

    while ((scn = elf_nextscn(elf->e, scn))) {
        if (!gelf_getshdr(scn, &section_header)) {
            fprintf(stderr, "[x] Failed to get section header.\n");
            return -1; 
        }   
        s = elf_strptr(elf->e, shstrndx, section_header.sh_name);
        if (!s) {
            fprintf(stderr, '[x] Failed to get section name.\n');
            return -1;
        }
        
        if (!strcmp(s, ABITAG_NAME)) {
            section_header.sh_name      = section_header.sh_name;       // Offset to string table
            section_header.sh_type      = SHT_PROGBITS;                 // Changing type to PROGBITS
            section_header.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;    // Flags
            section_header.sh_addr      = inject->secaddr;              // Address to load section
            section_header.sh_offset    = inject->off;                  // file offset to start of the section
            section_header.sh_size      = inject->len;
            section_header.sh_link      = 0;
            section_header.sh_info      = 0;
            section_header.sh_addralign = 16;
            section_header.sh_entsize   = 0;

            inject->sidx = elf_ndxscn(scn);
            inject->scn = scn;

            memcpy(&inject->shdr, &section_header, sizeof(section_header));
             
            if (write_section_header(elf, scn, &section_header, elf_ndxscn(scn))<0){
                return -1;
            }

            if(reorder_shdrs(elf, inject) < 0) {
                return -1;
            }

            break;
        }
    }
    if(!scn) {
        fprintf(stderr, "Cannot find section to rewrite\n");
        return -1;
    }

    return 0;

}

int write_secname(elf_data_t *elf, inject_data_t *inject) {
  off_t off;
  size_t n;

  off = lseek(elf->fd, inject->shstroff, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }
  
  n = write(elf->fd, inject->secname, strlen(inject->secname));
  if(n != strlen(inject->secname)) {
    fprintf(stderr, "Failed to write section name\n");
    return -1;
  }

  n = strlen(ABITAG_NAME) - strlen(inject->secname);
  while(n > 0) {
    if(!write(elf->fd, "\0", 1)) {
      fprintf(stderr, "Failed to write section name\n");
      return -1;
    }
    n--;
  }

  return 0;
}

int rewrite_entry_point(elf_data_t *elf, inject_data_t *inject) {
  elf->ehdr.e_entry = inject->phdr.p_vaddr + inject->entry;
  return write_ehdr(elf);
}

int rewrite_section_name(elf_data_t *elf, inject_data_t *inject) {
  Elf_Scn *scn;
  GElf_Shdr shdr;
  char *s;
  size_t shstrndx, stroff, strbase;

  if(strlen(inject->secname) > strlen(ABITAG_NAME)) {
    fprintf(stderr, "Section name too long\n");
    return -1;
  }

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    fprintf(stderr, "Failed to get string table section index\n");
    return -1;
  }

  stroff = 0;
  strbase = 0;
  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      fprintf(stderr, "Failed to get section header\n");
      return -1;
    }
    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      fprintf(stderr, "Failed to get section name\n");
      return -1;
    }

    if(!strcmp(s, ABITAG_NAME)) {
      stroff = shdr.sh_name;    /* offset into shstrtab */
    } else if(!strcmp(s, SHSTRTAB_NAME)) {
      strbase = shdr.sh_offset; /* offset to start of shstrtab */
    }
  }

  if(stroff == 0) {
    fprintf(stderr, "Cannot find shstrtab entry for injected section\n");
    return -1;
  } else if(strbase == 0) {
    fprintf(stderr, "Cannot find shstrtab\n");
    return -1;
  }

  inject->shstroff = strbase + stroff;

  if(write_secname(elf, inject) < 0) {
    return -1;
  }

  return 0;
}

int rewrite_code_segment(elf_data_t *elf, inject_data_t *inject) {
  inject->phdr.p_type   = PT_LOAD;         /* type */
  inject->phdr.p_offset = inject->off;     /* file offset to start of segment */
  inject->phdr.p_vaddr  = inject->secaddr; /* virtual address to load segment at */
  inject->phdr.p_paddr  = inject->secaddr; /* physical address to load segment at */
  inject->phdr.p_filesz = inject->len;     /* byte size in file */
  inject->phdr.p_memsz  = inject->len;     /* byte size in memory */
  inject->phdr.p_flags  = PF_R | PF_X;     /* flags */
  inject->phdr.p_align  = 0x1000;          /* alignment in memory and file */

  if(write_phdr(elf, inject) < 0) {
    return -1;
  }

  return 0;
}

int write_phdr(elf_data_t *elf, inject_data_t *inject) {
  off_t off;
  size_t n, phdr_size;
  Elf32_Phdr *phdr_list32;
  Elf64_Phdr *phdr_list64;
  void *phdr_buf;

  if(!gelf_update_phdr(elf->e, inject->pidx, &inject->phdr)) {
    fprintf(stderr, "Failed to update program header\n");
    return -1;
  }

  phdr_buf = NULL;
  if(elf->bits == 32) {
    phdr_list32 = elf32_getphdr(elf->e);
    if(phdr_list32) {
      phdr_buf = &phdr_list32[inject->pidx];
      phdr_size = sizeof(Elf32_Phdr);
    }
  } else {
    phdr_list64 = elf64_getphdr(elf->e);
    if(phdr_list64) {
      phdr_buf = &phdr_list64[inject->pidx];
      phdr_size = sizeof(Elf64_Phdr);
    }
  }
  if(!phdr_buf) {
    fprintf(stderr, "Failed to get program header\n");
    return -1;
  }

  off = lseek(elf->fd, elf->ehdr.e_phoff + inject->pidx*elf->ehdr.e_phentsize, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }

  n = write(elf->fd, phdr_buf, phdr_size);
  if(n != phdr_size) {
    fprintf(stderr, "Failed to write program header\n");
    return -1;
  }

  return 0;
}


int inject_code_section(int fd, inject_data_t *inject) {
    elf_data_t elf;
    int ret;
    size_t n; 

    elf.fd  = fd;
    elf.e   = NULL;


    if(elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "[x] Initialization of libelf failed.\n");
        return -1;
    }

    // Initialization of the ELF descriptor
    elf.e = elf_begin(elf.fd, ELF_C_READ, NULL);
    if (!elf.e) {
        fprintf(stderr, "[x] ELF file opening failed.\n");
        return -1; 
    }

    // Checking if the file is an executable file
    if(elf_kind(elf.e) != ELF_K_ELF) {
        fprintf(stderr, "[x] ELF file supplied isn't executable.\n");
        return -1; 
    }


    // TODO: Maybe adding architecture check too? 
    // Is it necessary? 
    ret = gelf_getclass(elf.e);

    if (ret==ELFCLASSNONE){
        fprintf(stderr, "[x] ELF file unknown");
        return -1;
    }
    else if(ret==ELFCLASS32) {
        printf("[+] ELF format 32-bit.\n");
        elf.bits = 32;
    }
    else {
        printf("[+] ELF format 64-bit.\n");
        elf.bits = 64;
    }   

    // Guetting the executable header
    if (!gelf_getehdr(elf.e, &elf.ehdr)) {
        fprintf(stderr, "[x] Can't get executable header.\n");
        return -1;
    }
    printf("[+] Getting executable header successfully.\n");

    // Finding the rewritable segment -- i.e. PT_NOTE
    if(find_pt_note_segment(&elf, inject)<0){
        return -1;
    }

    // Adding the code we want to inject into the binary
    if (write_inject(&elf, inject) < 0) {
        return -1;
    }

    // Code Address alignment 
    n = (inject->off % 4096) - (inject->secaddr % 4096);
    inject->secaddr += n;

    // Rewriting code section for the injected code
    
}

