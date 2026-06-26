#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLOB_SIZE (16 * 1024 * 1024) // 16 MB

int main() {
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char *key_blob = malloc(BLOB_SIZE);
    if (!key_blob) {
        perror("malloc failed");
        return 1;
    }

    // Fill buffer with repeated AES key
    for (size_t i = 0; i < BLOB_SIZE; i += sizeof(key)) {
        memcpy(key_blob + i, key, sizeof(key));
    }

    // Touch all pages to commit to RAM
    for (size_t i = 0; i < BLOB_SIZE; i += 4096) {
        key_blob[i] = key_blob[i];
    }

    // Print PID and range of the buffer to utilize virtual_to_physical
    printf("[+] Injected AES key to heap\n");
    printf("[+] PID: %d\n", getpid());
    printf("[+] key_blob address: %p - %p\n", (void*)key_blob, (void*)(key_blob + BLOB_SIZE));

    sleep(120);

    free(key_blob);
    return 0;
}