#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int etw_consume(const wchar_t* session_name);
void etw_consumer_request_stop(void);
