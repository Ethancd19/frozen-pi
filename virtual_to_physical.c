#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#define PAGEMAP_ENTRY 8
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1ULL << 55) - 1)

uint64_t get_physical_address(pid_t pid, uint64_t vaddr) {
    char pagemap_path[64];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);

    int fd = open(pagemap_path, O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        return -1;
    }

    off_t offset = (vaddr / PAGE_SIZE) * PAGEMAP_ENTRY;
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return -1;
    }

    uint64_t entry;
    if (read(fd, &entry, PAGEMAP_ENTRY) != PAGEMAP_ENTRY) {
        perror("read pagemap");
        close(fd);
        return -1;
    }

    close(fd);

    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        return -1;
    }

    uint64_t pfn = entry & PFN_MASK;
    return (pfn << PAGE_SHIFT) | (vaddr & (PAGE_SIZE - 1));
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <virtual_address>\n", argv[0]);
        return EXIT_FAILURE;
    }

    pid_t pid = atoi(argv[1]);
    uint64_t vaddr_start = strtoull(argv[2], NULL, 16);

    const size_t range_size = 16 * 1024 *1024; // 16MB
    uint64_t vaddr_end = vaddr_start + range_size;

    uint64_t paddr_start = get_physical_address(pid, vaddr_start);
    if (paddr_start == 0) {
        fprintf(stderr, "[!] Failed to translate start address\n");
        return 1;
    }
    
    uint64_t paddr_end = paddr_start + range_size;

    if (paddr_start == 0 || paddr_end == 0) {
        fprintf(stderr, "[!] Failed to get physical address\n");
        return EXIT_FAILURE;
    }

    printf("[+] Virtual Range : 0x%" PRIx64 " - 0x%" PRIx64 "\n", vaddr_start, vaddr_end);
    printf("[+] Physical Range: 0x%" PRIx64 " - 0x%" PRIx64 "\n", paddr_start, paddr_end);

    FILE *f = fopen("/boot/key_range.txt", "w");
    if (!f) {
        perror("fopen /boot/key_range.txt");
        return EXIT_FAILURE;
    }

    fprintf(f, "0x%" PRIx64 " 0x%" PRIx64 "\n", paddr_start, paddr_end);
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    return 0;
}