#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

#include "GipSyntheticHooks.h"

// Original xboxgipsynthetic.dll function type definitions
typedef long (*SyntheticController_Connect_t)(void* controller);
typedef long (*SyntheticController_Disconnect_t)(void* controller);
typedef long (*SyntheticController_CreateController_t)(unsigned long type_maybe, void** out_controller);
typedef long (*SyntheticController_RemoveController_t)(void* controller);
typedef long (*SyntheticController_SendReport_t)(void* controller, unsigned long report_type, void* report_buf, unsigned int report_size);

// We dynamically import these, I don't know how I'd do it otherwise...
SyntheticController_Connect_t SyntheticController_Connect;
SyntheticController_Disconnect_t SyntheticController_Disconnect;
SyntheticController_CreateController_t SyntheticController_CreateController;
SyntheticController_RemoveController_t SyntheticController_RemoveController;
SyntheticController_SendReport_t SyntheticController_SendReport;

// Keep track of whether we've started or not
bool GipSynthEx_Started = false;
// ...and whether we've been able to hook functions or not
bool GipSynthEx_StartedWithHooks = false;

// The GipSynthEx library has not been started.
#define GIPSYNTHEX_ERROR_NOT_STARTED 0x8B000001

// The GipSynthEx library has already been started.
#define GIPSYNTHEX_ERROR_ALREADY_STARTED 0x8B000002

// ConnectEx can not be called if the library could not initialise properly.
#define GIPSYNTHEX_ERROR_NO_CONNECTEX 0x8B000003

// The GipSynthEx library failed to start because it can't load the DLL.
#define GIPSYNTHEX_ERROR_CANT_FIND_DLL 0x8B000004

// The GipSynthEx lbirary failed to start because it can't import the functions.
#define GIPSYNTHEX_ERROR_CANT_FIND_FUNCTIONS 0x8B000005

// Failed to set the arrival data because it was invalid.
#define GIPSYNTHEX_ERROR_INVALID_ARRIVAL 0x8B000006

// Failed to set the metadata because it was invalid.
#define GIPSYNTHEX_ERROR_INVALID_METADATA 0x8B000007

// The library was successfully started.
#define GIPSYNTHEX_STARTED_SUCCESSFULLY 0

// The library was started, but couldn't 
#define GIPSYNTHEX_STARTED_WITHOUT_CONNECTEX 1

extern "C" {
	__declspec(dllexport) int GipSynthEx_Startup() {
		// Attempt to load the XboxGipSynthetic library.
		HMODULE synthetic_module = LoadLibraryA("xboxgipsynthetic.dll");
		if (synthetic_module == NULL)
			return GIPSYNTHEX_ERROR_CANT_FIND_DLL;

		// Resolve all the external functions from it
		SyntheticController_Connect =
			(SyntheticController_Connect_t)GetProcAddress(synthetic_module, "SyntheticController_Connect");
		SyntheticController_Disconnect =
			(SyntheticController_Disconnect_t)GetProcAddress(synthetic_module, "SyntheticController_Disconnect");
		SyntheticController_CreateController =
			(SyntheticController_CreateController_t)GetProcAddress(synthetic_module, "SyntheticController_CreateController");
		SyntheticController_RemoveController =
			(SyntheticController_RemoveController_t)GetProcAddress(synthetic_module, "SyntheticController_RemoveController");
		SyntheticController_SendReport =
			(SyntheticController_SendReport_t)GetProcAddress(synthetic_module, "SyntheticController_SendReport");
		// and make sure none of them are NULL.
		if (SyntheticController_Connect == NULL ||
			SyntheticController_Disconnect == NULL ||
			SyntheticController_CreateController == NULL ||
			SyntheticController_RemoveController == NULL ||
			SyntheticController_SendReport == NULL)
			return GIPSYNTHEX_ERROR_CANT_FIND_FUNCTIONS;

		// by this point, we've prepared enough to use other functions
		GipSynthEx_Started = true;

		// try to apply our hooks
		if (DoSyntheticHooks(synthetic_module) == SYNTHETICHOOKS_SUCCESS)
			GipSynthEx_StartedWithHooks = true;

		if (!GipSynthEx_StartedWithHooks)
			return GIPSYNTHEX_STARTED_WITHOUT_CONNECTEX;
		return GIPSYNTHEX_STARTED_SUCCESSFULLY;
	}

	__declspec(dllexport) int GipSynthEx_CreateController(int type, ULONGLONG* controller_handle) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;

		void* handle = NULL;
		long rval = SyntheticController_CreateController(type, &handle);
		if (rval == 0)
			*controller_handle = (ULONGLONG)handle;

		return rval;
	}

	__declspec(dllexport) int GipSynthEx_Connect(ULONGLONG controller_handle) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;

		// make sure we don't have a custom arrival or metadata block set
		SyntheticHooks_SetArrival(NULL, 0);
		SyntheticHooks_SetMetadata(NULL, 0);

		return SyntheticController_Connect((void*)controller_handle);
	}

	__declspec(dllexport) int GipSynthEx_ConnectEx(ULONGLONG controller_handle, BYTE *arrival, int arrival_size, BYTE *metadata, int metadata_size) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;
		if (!GipSynthEx_StartedWithHooks)
			return GIPSYNTHEX_ERROR_NO_CONNECTEX;

		// set the custom metadata and arrival blocks in our hooks
		if (SyntheticHooks_SetArrival(arrival, arrival_size) != SYNTHETICHOOKS_SUCCESS)
			return GIPSYNTHEX_ERROR_INVALID_ARRIVAL;
		if (SyntheticHooks_SetMetadata(metadata, metadata_size) != SYNTHETICHOOKS_SUCCESS)
			return GIPSYNTHEX_ERROR_INVALID_METADATA;

		long rval = SyntheticController_Connect((void*)controller_handle);

		// clean up the custom arrival and metadata we set
		SyntheticHooks_SetArrival(NULL, 0);
		SyntheticHooks_SetMetadata(NULL, 0);

		return rval;
	}

	__declspec(dllexport) int GipSynthEx_SendReport(ULONGLONG controller_handle, ULONG report_type, BYTE *report_buf, unsigned int report_size) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;

		return SyntheticController_SendReport((void*)controller_handle, report_type, report_buf, report_size);
	}

	__declspec(dllexport) int GipSynthEx_Disconnect(ULONGLONG controller_handle) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;

		return SyntheticController_Disconnect((void*)controller_handle);
	}

	__declspec(dllexport) int GipSynthEx_RemoveController(ULONGLONG controller_handle) {
		if (!GipSynthEx_Started)
			return GIPSYNTHEX_ERROR_NOT_STARTED;

		return SyntheticController_RemoveController((void*)controller_handle);
	}
}