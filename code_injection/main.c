#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#include "elf_injectors.h"



// static void exit_gracefully(char *text_format){
//     exit(EXIT_FAILURE);
// }


/**
 * main function
*/
int main(int argc, char *argv[]){
    // Initialization
    FILE *inject_file;
    int elf_fd, ret; 
    size_t len_injectf, secaddr;
    long entry;
    char *elf_fname, *inject_fname, *secname, *code;
    inject_data_t inject_data;

    if (argc != 6) {
        printf("Usage: %s <elf> <inject> <name> <addr> <entry>\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    elf_fname       = argv[1];
    inject_fname    = argv[2];
    secname         = argv[3];
    secaddr         = strtoul(argv[4], NULL, 0);
    entry           = strtol(argv[5], NULL, 0);

    // Opening the binary file to inject
    inject_file = fopen(inject_fname, 'r');
    if (!inject_file) {
        fprintf(stderr, "Failed to open %s. \n", inject_fname);
        exit(EXIT_FAILURE);
    } else {
        fprintf(stdout, "File %s opened successfully.", inject_fname);
    }

    fseek(inject_file, 0, SEEK_END); // Positionning at 0 byte to the end of the file 
    len_injectf = ftell(inject_file); // to get the length of the file

    fseek(inject_file, 0, SEEK_SET); // Begining of the file
    code = malloc(len_injectf);
    if (!code) {
        fprintf(stderr, "Failed to allocation code buffer. \n");
        fclose(inject_file);
        exit(EXIT_FAILURE);
    } else {
        fprintf(stdout, "Code buffer allocated.");
    }

    // Reading the file into the code buffer
    if (fread(code, 1, len_injectf, inject_file) != len_injectf) {
        fprintf(stderr, "Failed to read inject file.\n");
        exit(EXIT_FAILURE);
    }else{
        fprintf(stdout, "Reading inject file complete.");
    }

    fclose(inject_file);

    // Initialisation of inject_data
    inject_data.code    = code;
    inject_data.len     = len_injectf;
    inject_data.entry   = entry; 
    inject_data.secname = secname;
    inject_data.secaddr = secaddr;

    elf_fd = open(elf_fname, O_RDWR);
    if (elf_fd < 0) {
        fprintf(stderr, "Failed to open %s.", elf_fname);
    }

    ret = 0;
    ret = inject_code_section(elf_fd, &inject_data);
    
    free(code);
    close(elf_fd);

    return ret;
}
