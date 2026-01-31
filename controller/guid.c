#include "guid.h"
#include <windows.h>
#include <stdio.h>

// 단순: boot_id는 collector 시작 시 한 번만
static uint64_t g_boot_id = 0;

void guid_init_boot_id(void)
{
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    g_boot_id = (uint64_t)qpc.QuadPart ^ GetTickCount64();
}

// 매우 단순한 hash (나중에 xxhash64 교체 가능)
static uint64_t simple_hash64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return x;
}

void make_process_guid(
    uint32_t pid,
    uint64_t start_ts,
    const wchar_t* image,
    char out_guid[64]
){
    uint64_t h = g_boot_id;
    h ^= pid;
    h ^= start_ts;

    if (image) {
        const wchar_t* p = image;
        while (*p) {
            h ^= (uint64_t)(*p++);
            h = simple_hash64(h);
        }
    }

    h = simple_hash64(h);
    sprintf(out_guid, "p-%016llx", (unsigned long long)h);
}
