#include "main.h"
static HANDLE DsOpenHandle(PWCHAR Path)
{
	UNICODE_STRING NtPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE File;
	NTSTATUS Status;
	
	RtlDosPathNameToNtPathName_U(Path, &NtPath, NULL, NULL);
	
	InitializeObjectAttributes(&ObjectAttributes,
							   &NtPath,
							   OBJ_CASE_INSENSITIVE,
							   NULL,
							   NULL);
							   
	Status = NtCreateFile(&File,
						  DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
						  &ObjectAttributes,
						  &IoStatusBlock,
						  NULL,
						  FILE_ATTRIBUTE_NORMAL,
						  0,
						  FILE_OPEN,
						  FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
						  NULL,
						  0);
	
	RtlFreeHeap(RtlProcessHeap(), 0, NtPath.Buffer);
	
	if (NT_SUCCESS(Status)) {
		RtlSetLastWin32Error(ERROR_SUCCESS);
	} else {
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
		File = INVALID_HANDLE_VALUE;
	}
	return File;
}

static PVOID DsRenameHandle(HANDLE Handle)
{
	LPCWSTR Stream = DS_STREAM_RENAME;
	SIZE_T BufSize = sizeof(FILE_RENAME_INFO) + sizeof(DS_STREAM_RENAME) - sizeof(WCHAR);
	PFILE_RENAME_INFO Rename = (PFILE_RENAME_INFO)RtlAllocateHeap(RtlProcessHeap(), 0, BufSize); // FILE_RENAME_INFO contains space for 1 WCHAR without NULL-byte
	if (Rename == NULL) {
		DS_DEBUG_LOG(L"Could not allocate memory");
		return NULL;
	}
	RtlZeroMemory(Rename, BufSize);

	// set our FileNameLength and FileName to DS_STREAM_RENAME
	Rename->FileNameLength = (DWORD)(sizeof(DS_STREAM_RENAME) - sizeof(WCHAR));
	RtlCopyMemory(Rename->FileName, Stream, sizeof(DS_STREAM_RENAME));

	BOOL RenameOk;
	NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
	
	Status = NtSetInformationFile(Handle, &IoStatusBlock, Rename, BufSize, FileRenameInformation);
	
	if (!NT_SUCCESS(Status)) {
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
		RenameOk = FALSE;
	} else {
		RenameOk = TRUE;
	}
	
	if(!RenameOk)
	{
		RtlFreeHeap(RtlProcessHeap(), 0, Rename);
		return NULL;
	}
	return Rename;
}

static BOOL DsDepositeHandle(HANDLE Handle)
{
	// Ref: https://cybersecuritynews.com/windows-11-24h2-disrupts-self-delete/
	FILE_DISPOSITION_INFO_EX DeleteEx;
	RtlZeroMemory(&DeleteEx, sizeof(DeleteEx));

	DeleteEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
	NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;

	Status = NtSetInformationFile(Handle, &IoStatusBlock, &DeleteEx, sizeof(DeleteEx), FileDispositionInformationEx);
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
	return NT_SUCCESS(Status);
}

int wmain(int argc, wchar_t **argv)
{
	WCHAR Path[MAX_PATH + 1];
	RtlZeroMemory(Path, sizeof(Path));
	
	UNICODE_STRING Name;
	NTSTATUS Status;
	DWORD Len = 0;
    PPEB Peb = (PPEB)NtCurrentPeb();
	
	if (Peb != NULL && Peb->ProcessParameters != NULL) {
		UNICODE_STRING *ImageName = &Peb->ProcessParameters->ImagePathName;
		if (ImageName->Length > 0 && ImageName->Buffer != NULL) {
			Name.Buffer = Path;
			Name.MaximumLength = sizeof(Path);
			RtlCopyMemory(Path, ImageName->Buffer, min(ImageName->Length + sizeof(WCHAR), Name.MaximumLength));
			if (ImageName->Length + sizeof(WCHAR) < Name.MaximumLength) {
				Path[ImageName->Length / sizeof(WCHAR)] = L'\0';
				Status = STATUS_SUCCESS;
			} else {
				Path[ImageName->MaximumLength / sizeof(WCHAR)] = L'\0';
				Status = STATUS_BUFFER_TOO_SMALL;
            }
			Name.Length = ImageName->Length;
		}
	}

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL) {
		Len = Name.Length * sizeof(WCHAR);
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
	}

    if (Len == 0) {
        DS_DEBUG_LOG(L"Failed to get the current module path via PEB");
        return NtCurrentTeb()->LastErrorValue;
    }

	HANDLE Current = DsOpenHandle(Path);
	if (Current == INVALID_HANDLE_VALUE) {
		DS_DEBUG_LOG(L"Failed to acquire handle to current running process");
		return NtCurrentTeb()->LastErrorValue;
	}

	// rename the associated HANDLE's file name
	DS_DEBUG_LOG(L"Attempting to rename file name");
	PVOID Rename = DsRenameHandle(Current);
	if (Rename == NULL) {
		DS_DEBUG_LOG(L"Failed to rename to stream");
		return NtCurrentTeb()->LastErrorValue;
	}

	DS_DEBUG_LOG(L"Successfully renamed file primary :$DATA ADS to specified stream, closing initial handle");
	NtClose(Current);
	RtlFreeHeap(RtlProcessHeap(), 0, Rename); // free memory allocated in ds_rename_handle


	// open another handle, trigger deletion on close
	Current = DsOpenHandle(Path);
	if (Current == INVALID_HANDLE_VALUE) {
		DS_DEBUG_LOG(L"Failed to reopen current module");
		return NtCurrentTeb()->LastErrorValue;
	}

	if (!DsDepositeHandle(Current)) {
		DS_DEBUG_LOG(L"Failed to set delete deposition");
		return NtCurrentTeb()->LastErrorValue;
	}

	// trigger the deletion deposition on hCurrent
	DS_DEBUG_LOG(L"Closing handle to trigger deletion deposition");
	NtClose(Current);
 
	// verify we've been deleted
	if (!RtlDosPathNameToNtPathName_U(Path, &Name, NULL, NULL)) {
		DS_DEBUG_LOG(L"Failed to delete copy, file still exists");
		return NtCurrentTeb()->LastErrorValue;
	}

	DS_DEBUG_LOG(L"Successfully deleted self from disk");
	return ERROR_SUCCESS;
}
