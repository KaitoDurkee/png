#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

// Stolen from: http://www.libpng.org/pub/png/spec/1.2/PNG-CRCAppendix.html

/* Table of CRCs of all 8-bit messages. */
unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
int crc_table_computed = 0;

/* Make the table for a fast CRC. */
void make_crc_table(void)
{
    unsigned long c;
    int n, k;

    for (n = 0; n < 256; ++n) {
        c = (unsigned long) n;
        for (k = 0; k < 8; ++k) {
            if (c & 1) {
                c = 0xedb88320L ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

/* Update a running CRC with the bytes buf[0..len-1]--the CRC
    should be initialized to all 1's, and the transmitted value
    is the 1's complement of the final running CRC (see the
    crc() routine below)). */

unsigned long update_crc(unsigned long crc, unsigned char *buf,
                        int len)
{
    unsigned long c = crc;
    int n;

    if (!crc_table_computed)
    make_crc_table();
    for (n = 0; n < len; ++n) {
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long crc(unsigned char *buf, int len)
{
    return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

#define PNG_SIG_CAP 8
#define IHDR 0x52444849
#define IDAT 0x54414449
#define IEND 0x444E4549
#define CHUNK_BUF_CAP (32 * 1024)
#define INJECTION_DATA_BUF_CAP (64 * 1024)
#define INJECTION_MAGIC "iiNj"

uint8_t png_sig[PNG_SIG_CAP] = {137, 80, 78, 71, 13, 10, 26, 10};
uint8_t chunk_buf[CHUNK_BUF_CAP];
uint8_t injection_data_buf[INJECTION_DATA_BUF_CAP];

#define read_bytes_or_panic(file, buf, buf_cap) read_bytes_or_panic_(file, buf, buf_cap, __FILE__, __LINE__)
void read_bytes_or_panic_(FILE *file, void *buf, size_t buf_cap, const char *source_file, int source_line)
{
    size_t n = fread(buf, buf_cap, 1, file);
    if (n != 1) {
        if (ferror(file)) {
            fprintf(stderr, "%s(%d): ERROR: could not read %zu bytes from file: %s\n",
                    source_file, source_line,
                    buf_cap, strerror(errno));
            exit(1);
        } else if (feof(file)) {
            fprintf(stderr, "%s(%d): ERROR: could not read %zu bytes from file: reached the end of file\n",
                    source_file, source_line,
                    buf_cap);
            exit(1);
        } else {
            assert(0 && "unreachable");
        }
    }
}

#define write_bytes_or_panic(file, buf, buf_cap) write_bytes_or_panic_(file, buf, buf_cap, __FILE__, __LINE__)
void write_bytes_or_panic_(FILE *file, void *buf, size_t buf_cap, const char *source_file, int source_line)
{
    size_t n = fwrite(buf, buf_cap, 1, file);
    if (n != 1) {
        if (ferror(file)) {
            fprintf(stderr, "%s(%d): ERROR: could not write %zu bytes to file: %s\n",
                    source_file, source_line,
                    buf_cap, strerror(errno));
            exit(1);
        } else {
            assert(0 && "unreachable");
        }
    }
}

void print_bytes(uint8_t *buf, size_t buf_cap)
{
    for (size_t i = 0; i < buf_cap; ++i) {
        printf("%u ", buf[i]);
    }
    printf("\n");
}

void reverse_bytes(void *buf0, size_t buf_cap)
{
    uint8_t *buf = buf0;
    /* If buffer capacity is odd, the middle element does not need
    to be moved/swapped */
    for (size_t i = 0; i < buf_cap/2; ++i) {
        uint8_t t = buf[i];
        buf[i] = buf[buf_cap - i - 1];
        buf[buf_cap - i - 1] = t;
    }
}

void usage(FILE *file, char *program)
{
    fprintf(file, "%s: Usage: %s <input.png> <output.png>\n",
            __FILE__,
            program);
}

int main(int argc ,char **argv)
{
    (void) argc;
    assert(*argv != NULL);
    char *program = *argv++;

    if (*argv == NULL) {
        usage(stderr, program);
        fprintf(stderr, "%s: ERROR: no input file is provided\n", __FILE__);
        return EXIT_FAILURE;
    }
    
    char *input_filepath = *argv++;

    
    if (*argv == NULL) {
        usage(stderr, program);
        fprintf(stderr, "%s: ERROR: no output file is provided\n", __FILE__);
        return EXIT_FAILURE;
    }

    char *output_filepath = *argv++;

    if (*argv == NULL) {
        usage(stderr, program);
        fprintf(stderr, "%s: ERROR: no injection data file is provided\n", __FILE__);
        return EXIT_FAILURE;
    }

    char *injection_data_filepath = *argv++;

    FILE *input_file = fopen(input_filepath, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "%s: ERROR: could not open file %s: %s\n", __FILE__,
                input_filepath, strerror(errno));
        return EXIT_FAILURE;
    }

    FILE *output_file = fopen(output_filepath, "wb");
    if (output_file == NULL) {
        fprintf(stderr, "%s: ERROR: could not open file %s: %s\n", __FILE__,
                output_filepath, strerror(errno));
        return EXIT_FAILURE;
    }

    FILE *injection_data_file = fopen(injection_data_filepath, "rb");
    if (output_file == NULL) {
        fprintf(stderr, "%s: ERROR: could not open file %s: %s\n", __FILE__,
                injection_data_filepath, strerror(errno));
        return EXIT_FAILURE;
    }

    uint8_t sig[PNG_SIG_CAP];
    read_bytes_or_panic(input_file, sig, PNG_SIG_CAP);
    write_bytes_or_panic(output_file, sig, PNG_SIG_CAP);
    printf("Signature: ");
    print_bytes(sig, PNG_SIG_CAP);
    if (memcmp(sig, png_sig, PNG_SIG_CAP) != 0) {
        fprintf(stderr, "%s: ERROR: %s does not appear to be a valid PNG image\n",
                __FILE__, input_filepath);
        return EXIT_FAILURE;
    }
    printf("------------------------------\n");

    bool quit = false;
    while(!quit) {
        uint32_t chunk_sz;
        read_bytes_or_panic(input_file, &chunk_sz, sizeof(chunk_sz));
        write_bytes_or_panic(output_file, &chunk_sz, sizeof(chunk_sz));
        // Must reverse bytes for programmatic usage, because PNG uses big-endian byte ordering
        reverse_bytes(&chunk_sz, sizeof(chunk_sz));

        uint8_t chunk_type[4];
        read_bytes_or_panic(input_file, chunk_type, sizeof(chunk_type));
        write_bytes_or_panic(output_file, chunk_type, sizeof(chunk_type));

        if (*(uint32_t*) chunk_type == IEND) {
            quit = true;
        }

        size_t n = chunk_sz;
        while (n > 0) {
            size_t m = n;
            if (m > CHUNK_BUF_CAP) {
                m = CHUNK_BUF_CAP;
            }
            read_bytes_or_panic(input_file, chunk_buf, m);
            write_bytes_or_panic(output_file, chunk_buf, m);
            n -= m;
        }

        uint32_t chunk_crc;
        read_bytes_or_panic(input_file, &chunk_crc, sizeof(chunk_crc));
        write_bytes_or_panic(output_file, &chunk_crc, sizeof(chunk_crc));

        if (*(uint32_t*) chunk_type == IHDR) {
            /* Inject data after PNG header*/
            #if 1
            char injected_data[] = "YEP";
            uint32_t injected_sz = sizeof(injected_data);
            reverse_bytes(&injected_sz, sizeof(injected_sz));
            write_bytes_or_panic(output_file, &injected_sz, sizeof(injected_sz));
            reverse_bytes(&injected_sz, sizeof(injected_sz));

            char* injected_type = INJECTION_MAGIC;
            write_bytes_or_panic(output_file, injected_type, 4);

            write_bytes_or_panic(output_file, injected_data, injected_sz);
        
            uint32_t injected_crc = crc(injected_data, sizeof(injected_data));
            write_bytes_or_panic(output_file, &injected_crc, sizeof(injected_crc));
            // TODO: fix CRC calculation and writing method to match PNG spec (includes chunk type)
            // TODO: refactor crc calculation method into funtion that results in a crc ready for writing to file

            // TODO: implement injecting arbitrary text data that is read from a file
            // The start of this is below
            #else
            size_t t = fseek(injection_data_file, 0L, SEEK_END);
            if (t != 0) {
                fprintf(stderr, "%s(%d): ERROR: failed to seek in file: %s\n",
                        __FILE__, __LINE__, strerror(errno));
                return EXIT_FAILURE;
            }
            uint32_t injection_sz = ftell(injection_data_file);
            rewind(injection_data_file);

            size_t n = injection_sz;
            while (n > 0) {
                size_t injection_chunk_sz = n;
                if (injection_chunk_sz > INJECTION_DATA_BUF_CAP) {
                    injection_chunk_sz = INJECTION_DATA_BUF_CAP;
                }
            
                write_bytes_or_panic(output_file, &injection_chunk_sz, sizeof(injection_chunk_sz));
                
                char * injected_type[4] = INJECTION_MAGIC;
                // reverse_bytes(&injected_type, 4);
                write_bytes_or_panic(output_file, &injected_type, 4);
                // reverse_bytes(&injected_type, 4);

                read_bytes_or_panic(injection_data_file, injection_data_buf, injection_chunk_sz);
                // reverse_bytes(&injection_data_buf, injection_chunk_sz);
                write_bytes_or_panic(output_file, injection_data_buf, injection_chunk_sz);
                // reverse_bytes(&injection_data_buf, injection_chunk_sz);
                
                unsigned long injection_crc = crc(injection_data_buf, injection_chunk_sz);
                // reverse_bytes(&injection_crc, sizeof(injection_crc));
                write_bytes_or_panic(output_file, &injection_crc, sizeof(injection_crc));
                // reverse_bytes(&injection_crc, sizeof(injection_crc));

                printf("Chunk size: %u\n", injection_chunk_sz);
                printf("Chunk type: %.*s (0x%08X)\n",
                    (int) sizeof(injected_type), injected_type,
                    *(uint32_t*) injected_type);
                printf("Chunk CRC: 0x%08X\n", injection_crc);
                printf("------------------------------\n");

                n -= injection_chunk_sz;
            }
            fclose(injection_data_file);
            #endif
        }

        printf("Chunk size: %u\n", chunk_sz);
        printf("Chunk type: %.*s (0x%08X)\n",
               (int) sizeof(chunk_type), chunk_type,
              *(uint32_t*) chunk_type);
        printf("Chunk CRC: 0x%08X\n", chunk_crc);
        printf("------------------------------\n");
    }

    fclose(input_file);
    fclose(output_file);

    /*
    printf("UINT8_MAX: %d\n", UINT8_MAX);
    printf("UINT16_MAX: %d\n", UINT16_MAX);
    printf("UINT32_MAX: %I64d\n", UINT32_MAX);
    printf("UINT64_MAX: %I64d\n", UINT64_MAX);
    */

    return EXIT_SUCCESS;
}