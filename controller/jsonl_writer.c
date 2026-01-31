#include "jsonl_writer.h"
#include <stdio.h>

static FILE* g_fp = NULL;

int jsonl_open(const wchar_t* path)
{
    g_fp = _wfopen(path, L"ab");
    return g_fp != NULL;
}

void jsonl_close(void)
{
    if (g_fp) fclose(g_fp);
    g_fp = NULL;
}

void jsonl_write_proc_start(
    const char* ts,
    uint32_t pid,
    uint32_t ppid,
    const wchar_t* image,
    const wchar_t* cmdline,
    const char* process_guid,
    const wchar_t* host
){
    fprintf(g_fp,
        "{\"ts\":\"%s\",\"event_type\":\"proc_start\","
        "\"pid\":%u,\"ppid\":%u,"
        "\"image\":\"%S\",\"cmdline\":\"%S\","
        "\"host\":\"%S\",\"process_guid\":\"%s\"}\n",
        ts, pid, ppid, image, cmdline, host, process_guid
    );
    fflush(g_fp);
}
