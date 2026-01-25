#pragma once
#include <stdint.h>

void guid_init_boot_id(void);
void make_process_guid(
    uint32_t pid,
    uint64_t start_ts,
    const wchar_t* image,
    char out_guid[64]
);
