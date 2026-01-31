#pragma once
#include <windows.h>

int jsonl_open(const wchar_t* path);
void jsonl_close(void);

void jsonl_write_proc_start(
    const char* ts,
    uint32_t pid,
    uint32_t ppid,
    const wchar_t* image,
    const wchar_t* cmdline,
    const char* process_guid,
    const wchar_t* host
);

void jsonl_write_proc_end(
    const char* ts,
    uint32_t pid,
    const char* process_guid
);

void jsonl_write_net_connect(
    const char* ts,
    uint32_t pid,
    const char* process_guid,
    const char* src_ip,
    uint16_t src_port,
    const char* dst_ip,
    uint16_t dst_port
);
