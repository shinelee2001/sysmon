#pragma once

// output
#define DEFAULT_OUTPUT_PATH L"telemetry-raw.jsonl"

// kernel flags
#define KERNEL_FLAGS (EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP)

// buffer
#define JSON_BUFFER_SIZE 4096

// process guid
#define PROCESS_GUID_PREFIX "p-"
#define PROCESS_GUID_HEX_LEN 16   // 64bit
