#include <Windows.h>
#include <Psapi.h>
#include <MinHook.h>

#include "GipSyntheticHooks.h"

bool has_arrival = false;
int arrival_size = 0;
UINT8 arrival_buf[0x1C];

bool has_metadata = false;
int metadata_size = 0;
UINT8 metadata_buf[0x400];

// SyntheticWrite::CreateMetadataMsg
long (*SyntheticWriteCreateMetadataMsg)(void* thisSyntheticWrite, UINT8 device_type, void* metadata_block, int metadata_size);
long SyntheticWriteCreateMetadataMsgHook(void* thisSyntheticWrite, UINT8 device_type, void* metadata_block, int metadata_size_) {
	long rval = 0;
	if (!has_metadata)
		rval = SyntheticWriteCreateMetadataMsg(thisSyntheticWrite, device_type, metadata_block, metadata_size_);
	else
		rval = SyntheticWriteCreateMetadataMsg(thisSyntheticWrite, device_type, metadata_buf, metadata_size);
	return rval;
}

// GipMsg_Hello::MakeHello
long (*GipMsg_HelloMakeHello)(void* thisGipMsg_Hello, UINT64 some_id, unsigned short unused, unsigned short pid, unsigned short revision, unsigned short idk);
long GipMsg_HelloMakeHelloHook(void* thisGipMsg_Hello, UINT64 some_id, unsigned short unused, unsigned short pid, unsigned short revision, unsigned short idk) {
	long rval = GipMsg_HelloMakeHello(thisGipMsg_Hello, some_id, unused, pid, revision, idk);
	if (has_arrival) {
		// copy our arrival into the buffer, the first 8 bytes are an id that can't be changed
		memcpy((UINT8*)thisGipMsg_Hello + 8, arrival_buf + 8, arrival_size - 8);
	}
	return rval;
}

int SyntheticHooks_SetArrival(BYTE* arrival_buffer, int arrival_size_) {
	if (arrival_buffer == NULL || arrival_size_ == 0) {
		has_arrival = false;
		arrival_size = 0;
		memset(arrival_buf, 0, sizeof(arrival_buf));
		return S_OK;
	}

	// make sure the arrival message matches the required size
	if (arrival_size_ != sizeof(arrival_buf))
		return SYNTHETICHOOKS_FAILED;

	memcpy(arrival_buf, arrival_buffer, sizeof(arrival_buf));
	arrival_size = arrival_size_;
	has_arrival = true;
	return SYNTHETICHOOKS_SUCCESS;
}

int SyntheticHooks_SetMetadata(BYTE* metadata_blob, int metadata_size_) {
	if (metadata_blob == NULL || metadata_size_ == 0) {
		has_metadata = false;
		metadata_size = 0;
		memset(metadata_buf, 0, sizeof(metadata_buf));
		return S_OK;
	}

	// make sure the metadata message isn't too big
	if (metadata_size_ > sizeof(metadata_buf))
		return SYNTHETICHOOKS_FAILED;

	memcpy(metadata_buf, metadata_blob, metadata_size_);
	metadata_size = metadata_size_;
	has_metadata = true;
	return SYNTHETICHOOKS_SUCCESS;
}

// 
UINT8 create_metadata_sigs[] = { 0x41, 0x81, 0xF9, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0xBB, 0x57, 0x00, 0x07, 0x80 };
UINT8 create_metadata_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
UINT8 create_metadata_start[] = { 0x40, 0x53, 0x55, 0x56 };
int create_metadata_offset = 0x26;

UINT8 make_hello_sigs[] = { 0xb8, 0x57, 0x00, 0x07, 0x80, 0x00, 0x00, 0xb8, 0x5e, 0x04, 0x00, 0x00 };
UINT8 make_hello_mask[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff };
UINT8 make_hello_start[] = { 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x42, 0xff };
int make_hello_offset = 0x33;

void* GetBaseAddress(HMODULE module, int* image_size) {
	MODULEINFO info;
	if (module != NULL) {
		if (GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(MODULEINFO))) {
			if (image_size != NULL) *image_size = info.SizeOfImage;
			return info.lpBaseOfDll;
		}
	}
	return NULL;
}

void* FindSignature(void* start_addr, int scan_size, UINT8* sig_buf, UINT8* mask_buf, int sig_mask_size, UINT8* start, int start_size, int start_offset) {
	UINT8* base = (UINT8*)start_addr;
	UINT8* current_target = NULL;
	int ct_i = 0;
	// search for our signature with our mask
	for (int i = 0; i < scan_size - sig_mask_size; i++) {
		if ((base[i] & mask_buf[ct_i]) == sig_buf[ct_i]) {
			if (ct_i == 0) current_target = &base[i];
			ct_i++;
			if (ct_i == sig_mask_size) goto finished;
		}
		else {
			ct_i = 0;
			current_target = NULL;
		}
	}
finished:
	// we haven't actually found the bytes we were looking for
	if (ct_i != sig_mask_size)
		current_target = NULL;
	// if we have a target candidate, go backwards to find the function start
	if (current_target != NULL) {
		UINT8* go_backwards = current_target;
		int found_backwards = 0;
		for (int i = 0; i < start_offset; i++) {
			go_backwards -= 1;
			if (memcmp(go_backwards, start, start_size) == 0) {
				current_target = go_backwards;
				found_backwards = 1;
				break;
			}
		}
		if (!found_backwards)
			current_target = NULL;
	}
	return (void*)current_target;
}

int DoSyntheticHooks(HMODULE synthetic_dll) {
	int synthetic_dll_size = 0;
	void * synthetic_dll_base_addr = GetBaseAddress(synthetic_dll, &synthetic_dll_size);
	if (synthetic_dll_base_addr == NULL)
		return SYNTHETICHOOKS_FAILED;

	void* make_hello_addr = FindSignature(synthetic_dll_base_addr, synthetic_dll_size, make_hello_sigs, make_hello_mask, sizeof(make_hello_sigs),
		make_hello_start, sizeof(make_hello_start), make_hello_offset);
	void* create_metadata_addr = FindSignature(synthetic_dll_base_addr, synthetic_dll_size, create_metadata_sigs, create_metadata_mask,
		sizeof(create_metadata_sigs), create_metadata_start, sizeof(create_metadata_start), create_metadata_offset);

	if (make_hello_addr == NULL || create_metadata_addr == NULL)
		return SYNTHETICHOOKS_FAILED;

	MH_Initialize();
	MH_CreateHook(create_metadata_addr, &SyntheticWriteCreateMetadataMsgHook, (void**)&SyntheticWriteCreateMetadataMsg);
	MH_CreateHook(make_hello_addr, &GipMsg_HelloMakeHelloHook, (void**)&GipMsg_HelloMakeHello);
	MH_EnableHook(MH_ALL_HOOKS);

	return SYNTHETICHOOKS_SUCCESS;
}
