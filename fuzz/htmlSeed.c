/*
 * htmlSeed.c: Generate the HTML seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>

#define SEED_BUF_SIZE 16384

int
main(int argc, char **argv) {
    int opts = 0;
    FILE *file;
    char buf[SEED_BUF_SIZE];
    size_t size;

    if (argc != 2) {
        fprintf(stderr, "Usage: htmlSeed [FILE]\n");
        return(1);
    }

    fwrite(&opts, sizeof(opts), 1, stdout);

    /* Copy file */
    file = fopen(argv[1], "rb");
    do {
        size = fread(buf, 1, SEED_BUF_SIZE, file);
        if (size > 0)
            fwrite(buf, 1, size, stdout);
    } while (size == SEED_BUF_SIZE);
    fclose(file);

    return(0);
}

