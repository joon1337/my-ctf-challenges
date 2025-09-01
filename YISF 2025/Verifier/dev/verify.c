#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <openssl/sha.h>

int check_sha256(const char *input, const char *target_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);

    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hash_hex + i * 2, "%02x", hash[i]);
    hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
    return strcmp(hash_hex, target_hex) == 0;
}

void check_serial(const char *serial) {
    char part1[5], part2[5], part3[5], part4[5];
    if (strlen(serial) != 19) {
        syscall(SYS_exit, 0);
    }

    if (sscanf(serial, "%4s-%4s-%4s-%4s", part1, part2, part3, part4) != 4) {
        syscall(SYS_exit, 0);
    }

    int flag = 1;
    if (!check_sha256(part1, "3355b58b97617985ad032226043d3008c5dc915288326e0074654ba344f5b471")) {
        flag = 0;
    }
    if (!check_sha256(part2, "d2c2198d191d3c2f14bba11fe2bb4396bd1dfb7d3df32b70e472d15a72eed13f")) {
        flag = 0;
    }
    if (!check_sha256(part3, "74515ecf40255d006ecaca61026235e0694b9916be6fbdd62c4581d58664b5b4")) {
        flag = 0;
    }
    if (!check_sha256(part4, "a77b3237cb73acfb0e31f93694398f8e7dc158edb14552cbede81d9bf3839e86")) {
        flag = 0;
    }
    if (!flag) {
        syscall(SYS_exit, 0);
    }
}

void check_name(const char *name, const char *serial) {
    char part1[5], part2[5], part3[5], part4[5];
    char name_temp[8] = {0};
    uint32_t sum = 0;

    if (strlen(name) != 8 || strlen(serial) != 19) {
        syscall(SYS_exit, 0);
    }

    if (sscanf(serial, "%4s-%4s-%4s-%4s", part1, part2, part3, part4) != 4) {
        syscall(SYS_exit, 0);
    }

    memcpy(&sum, part1, 4);
    sum += *(uint32_t *)part2;
    sum += *(uint32_t *)part3;
    sum += *(uint32_t *)part4;

    for (int i = 0; i < 8; i++) {
        name_temp[i] = (uint8_t)name[i] ^ ((uint8_t *)&sum)[i % 4];
    }

    if (memcmp(name_temp, "\xac\xf5\x1c>\xe7\xf4\x1bm", 8)) {
        syscall(SYS_exit, 0);
    }
}

void print_flag(const char *name, const char *serial) {
    uint32_t _serial[4] = {0};
    char part1[5], part2[5], part3[5], part4[5];

    if (sscanf(serial, "%4s-%4s-%4s-%4s", part1, part2, part3, part4) != 4) {
        syscall(SYS_exit, 0);
    }

    memcpy(&_serial[0], part1, 4);
    memcpy(&_serial[1], part2, 4);
    memcpy(&_serial[2], part3, 4);
    memcpy(&_serial[3], part4, 4);

    uint32_t _name[2] = {0};
    memcpy(_name, name, 8);

    _serial[0] ^= _name[0];
    _serial[1] ^= _name[1];
    _serial[2] ^= _name[0];
    _serial[3] ^= _name[1];

    uint8_t xor_key[128] = {
        124, 101, 101, 50, 61, 50, 97, 52, 116, 50, 97, 54, 52, 51, 56, 49,
        115, 52, 102, 102, 58, 56, 101, 50, 122, 102, 100, 48, 98, 99, 49, 100,
        41, 100, 49, 50, 56, 53, 99, 97, 47, 102, 55, 51, 50, 51, 54, 54,
        47, 102, 98, 63, 61, 53, 96, 101, 122, 52, 97, 100, 55, 51, 103, 48,
        127, 97, 48, 49, 58, 99, 107, 53, 126, 53, 55, 49, 53, 96, 53, 63,
        40, 97, 99, 98, 61, 57, 102, 101, 47, 57, 48, 99, 51, 55, 103, 51,
        121, 98, 63, 53, 110, 101, 50, 48, 116, 100, 99, 52, 98, 56, 50, 62,
        121, 56, 63, 53, 59, 51, 101, 101, 121, 102, 99, 51, 54, 101, 96, 62
    };

    printf("YISF{");
    for (int i = 0; i < 128; i++) {
        printf("%c", xor_key[i] ^ ((uint8_t *)_serial)[i % 16]);
    }
    printf("}\n");
}

void core(char *name, char *serial) {
    check_name(name, serial);
    check_serial(serial);
    print_flag(name, serial);
}

__attribute__((constructor))
void init() {
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char buf[4096];
        fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (strstr(buf, "TracerPid:\t0") == NULL) {
            syscall(SYS_exit, 0);
        }
    }

    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
        syscall(SYS_exit, 0);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("usage: %s <name> <serial>\n", argv[0]);
        syscall(SYS_exit, 0);
    }
    core(argv[1], argv[2]);
    return 0;
}
