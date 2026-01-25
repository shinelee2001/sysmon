#pragma once
#include <windows.h>

int etw_start_kernel_session(const wchar_t* name);
void etw_stop_kernel_session(const wchar_t* name);
