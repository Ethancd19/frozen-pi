#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#define OUTPUT_DIR "/boot/"
#define RANGE_FILE "/boot/key_range.txt"
#define DUMP_BLOCK_SIZE 4096

int main() {
    FILE *range = fopen(RANGE_FILE, "r");
    if (!range) {
        perror("Failed to open key_range.txt");
        return 1;
    }

    uint64_t phys_start = 0, phys_end = 0;
    if (fscanf(range, "%lx %lx", &phys_start, &phys_end) != 2) {
        fprintf(stderr, "Failed to parse key_range.txt\n");
        fclose(range);
        return 1;
    }
    fclose(range);

    uint64_t dump_size = phys_end - phys_start;
    if (dump_size == 0 || dump_size > (512 * 1024 * 1024)) {
        fprintf(stderr, "Invalid or too large dump size: %lu bytes\n", dump_size);
        return 1;
    }

    int mem = open("/dev/mem", O_RDONLY);
    if (mem < 0) {
        perror("Failed to open /dev/mem");
        return 1;
    }

    if (lseek(mem, phys_start, SEEK_SET) == (off_t)-1) {
        perror("lseek failed");
        close(mem);
        return 1;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char filename[256];
    strftime(filename, sizeof(filename), OUTPUT_DIR "dump_%Y%m%d_%H%M%S.bin", t);

    FILE *out = fopen(filename, "wb");
    if (!out) {
        perror("Failed to open output file");
        close(mem);
        return 1;
    }

    printf("[+] Dumping %lu bytes from physical 0x%lx to %s\n", dump_size, phys_start, filename);

    char buffer[DUMP_BLOCK_SIZE];
    uint64_t remaining = dump_size;
    while (remaining > 0) {
        size_t to_read = remaining > DUMP_BLOCK_SIZE ? DUMP_BLOCK_SIZE : remaining;
        if (read(mem, buffer, to_read) != to_read) {
            perror("Read failed");
            break;
        }
        fwrite(buffer, 1, to_read, out);
        remaining -= to_read;
    }

    fclose(out);
    close(mem);
    printf("[+] Dump complete.\n");
    return 0;
}
