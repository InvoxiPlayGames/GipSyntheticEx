#pragma once
#include <Windows.h>

#define SYNTHETICHOOKS_SUCCESS 0
#define SYNTHETICHOOKS_FAILED  -1

int SyntheticHooks_SetArrival(BYTE* arrival_buffer, int arrival_size);
int SyntheticHooks_SetMetadata(BYTE* metadata_blob, int metadata_size);
int DoSyntheticHooks(HMODULE synthetic_dll);
