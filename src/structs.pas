unit structs;

interface

uses
  Windows, SysUtils;

const
  PS_INHERIT_HANDLES = 4;
  GDI_HANDLE_BUFFER_SIZE = 34;

const
  IMAGE_NT_SIGNATURE = $00004550;

type NTSTATUS = LongInt;

type
  KPRIORITY = LongInt;

type
  _UNICODE_STRING = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  UNICODE_STRING = _UNICODE_STRING;
  PUNICODE_STRING = ^UNICODE_STRING;

type
  _CURDIR = record
    DosPath: UNICODE_STRING;
    Handle: THandle;
  end;

  CURDIR = _CURDIR;
  PCURDIR = ^CURDIR;

type
  _RTL_DRIVE_LETTER_CURDIR = record
    Flags: Word;
    Length: Word;
    TimeStamp: Cardinal;
    DosPath: UNICODE_STRING;
  end;

  RTL_DRIVE_LETTER_CURDIR = _RTL_DRIVE_LETTER_CURDIR;
  PRTL_DRIVE_LETTER_CURDIR = ^RTL_DRIVE_LETTER_CURDIR;

type
  _RTL_USER_PROCESS_PARAMETERS = record
    MaximumLength: Cardinal;
    Length: Cardinal;
    Flags: Cardinal;
    DebugFlags: Cardinal;
    ConsoleHandle: THandle;
    ConsoleFlags: Cardinal;
    StandardInput: THandle;
    StandardOutput: THandle;
    StandardError: THandle;
    CurrentDirectory: CURDIR;
    DllPath: UNICODE_STRING;
    ImagePathName: UNICODE_STRING;
    CommandLine: UNICODE_STRING;
    Environment: Pointer;
    StartingX: Cardinal;
    StartingY: Cardinal;
    CountX: Cardinal;
    CountY: Cardinal;
    CountCharsX: Cardinal;
    CountCharsY: Cardinal;
    FillAttribute: Cardinal;
    WindowFlags: Cardinal;
    ShowWindowFlags: Cardinal;
    WindowTitle: UNICODE_STRING;
    DesktopInfo: UNICODE_STRING;
    ShellInfo: UNICODE_STRING;
    RuntimeData: UNICODE_STRING;
    CurrentDirectories: array [0 .. 31] of RTL_DRIVE_LETTER_CURDIR;
    EnvironmentSize: NativeUInt;
  end;

  RTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS;
  PRTL_USER_PROCESS_PARAMETERS = ^RTL_USER_PROCESS_PARAMETERS;
  PPRTL_USER_PROCESS_PARAMETERS = ^PRTL_USER_PROCESS_PARAMETERS;

type
  _PEB_LDR_DATA = record
    Length: ULONG;
    Initialized: ULONG;
    SsHandle: Pointer;
    InLoadOrderModuleList: LIST_ENTRY;
    InMemoryOrderModuleList: LIST_ENTRY;
    InInitializationOrderModuleList: LIST_ENTRY;
  end;

  PEB_LDR_DATA = _PEB_LDR_DATA;
  PPEB_LDR_DATA = ^PEB_LDR_DATA;

  // To check
type
  PPEB_FREE_BLOCK = ^_PEB_FREE_BLOCK;

  _PEB_FREE_BLOCK = record
    Next: PPEB_FREE_BLOCK;
    Size: Cardinal;
  end;

  PEB_FREE_BLOCK = _PEB_FREE_BLOCK;

type
  _PEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    Spare: BOOLEAN;
    Mutant: THandle;
    ImageBase: Pointer;
    LoaderData: PPEB_LDR_DATA;
    ProcessParameters: PRTL_USER_PROCESS_PARAMETERS;
    // Changed from PVOID for type safety
    SubSystemData: Pointer;
    ProcessHeap: Pointer;
    FastPebLock: Pointer;
    FastPebLockRoutine: Pointer;
    FastPebUnlockRoutine: Pointer;
    EnvironmentUpdateCount: ULONG;
    KernelCallbackTable: ^Pointer;
    EventLogSection: Pointer;
    EventLog: Pointer;
    FreeList: Pointer;
    TlsExpansionCounter: ULONG;
    TlsBitmap: Pointer;
    TlsBitmapBits: array [0 .. 1] of ULONG;
    ReadOnlySharedMemoryBase: Pointer;
    ReadOnlySharedMemoryHeap: Pointer;
    ReadOnlyStaticServerData: ^Pointer;
    AnsiCodePageData: Pointer;
    OemCodePageData: Pointer;
    UnicodeCaseTableData: Pointer;
    NumberOfProcessors: ULONG;
    NtGlobalFlag: ULONG;
    Spare2: array [0 .. 3] of BYTE;
    CriticalSectionTimeout: LARGE_INTEGER;
    HeapSegmentReserve: ULONG;
    HeapSegmentCommit: ULONG;
    HeapDeCommitTotalFreeThreshold: ULONG;
    HeapDeCommitFreeBlockThreshold: ULONG;
    NumberOfHeaps: ULONG;
    MaximumNumberOfHeaps: ULONG;
    ProcessHeaps: ^PPVOID;
    GdiSharedHandleTable: Pointer;
    ProcessStarterHelper: Pointer;
    GdiDCAttributeList: Pointer;
    LoaderLock: Pointer;
    OSMajorVersion: ULONG;
    OSMinorVersion: ULONG;
    OSBuildNumber: ULONG;
    OSPlatformId: ULONG;
    ImageSubSystem: ULONG;
    ImageSubSystemMajorVersion: ULONG;
    ImageSubSystemMinorVersion: ULONG;
    GdiHandleBuffer: array [0 .. 33] of ULONG;
    PostProcessInitRoutine: ULONG;
    TlsExpansionBitmap: ULONG;
    TlsExpansionBitmapBits: array [0 .. 127] of BYTE;
    SessionId: ULONG;
  end;

  PEB = _PEB;
  PPEB = ^PEB;

type
  _FILE_INFORMATION_CLASS = (FileDirectoryInformation = 1,
    FileFullDirectoryInformation, // 2
    FileBothDirectoryInformation, // 3
    FileBasicInformation, // 4
    FileStandardInformation, // 5
    FileInternalInformation, // 6
    FileEaInformation, // 7
    FileAccessInformation, // 8
    FileNameInformation, // 9
    FileRenameInformation, // 10
    FileLinkInformation, // 11
    FileNamesInformation, // 12
    FileDispositionInformation, // 13
    FilePositionInformation, // 14
    FileFullEaInformation, // 15
    FileModeInformation, // 16
    FileAlignmentInformation, // 17
    FileAllInformation, // 18
    FileAllocationInformation, // 19
    FileEndOfFileInformation, // 20
    FileAlternateNameInformation, // 21
    FileStreamInformation, // 22
    FilePipeInformation, // 23
    FilePipeLocalInformation, // 24
    FilePipeRemoteInformation, // 25
    FileMailslotQueryInformation, // 26
    FileMailslotSetInformation, // 27
    FileCompressionInformation, // 28
    FileObjectIdInformation, // 29
    FileCompletionInformation, // 30
    FileMoveClusterInformation, // 31
    FileQuotaInformation, // 32
    FileReparsePointInformation, // 33
    FileNetworkOpenInformation, // 34
    FileAttributeTagInformation, // 35
    FileTrackingInformation, // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation, // 40
    FileIoCompletionNotificationInformation, // 41
    FileIoStatusBlockRangeInformation, // 42
    FileIoPriorityHintInformation, // 43
    FileSfioReserveInformation, // 44
    FileSfioVolumeInformation, // 45
    FileHardLinkInformation, // 46
    FileProcessIdsUsingFileInformation, // 47
    FileNormalizedNameInformation, // 48
    FileNetworkPhysicalNameInformation, // 49
    FileIdGlobalTxDirectoryInformation, // 50
    FileIsRemoteDeviceInformation, // 51
    FileUnusedInformation, // 52
    FileNumaNodeInformation, // 53
    FileStandardLinkInformation, // 54
    FileRemoteProtocolInformation, // 55

    FileRenameInformationBypassAccessCheck, // 56
    FileLinkInformationBypassAccessCheck, // 57

    FileVolumeNameInformation, // 58
    FileIdInformation, // 59
    FileIdExtdDirectoryInformation, // 60
    FileReplaceCompletionInformation, // 61
    FileHardLinkFullIdInformation, // 62
    FileIdExtdBothDirectoryInformation, // 63
    FileDispositionInformationEx, // 64
    FileRenameInformationEx, // 65
    FileRenameInformationExBypassAccessCheck, // 66
    FileDesiredStorageClassInformation, // 67
    FileStatInformation, // 68
    FileMemoryPartitionInformation, // 69
    FileStatLxInformation, // 70
    FileCaseSensitiveInformation, // 71
    FileLinkInformationEx, // 72
    FileLinkInformationExBypassAccessCheck, // 73
    FileStorageReserveIdInformation, // 74
    FileCaseSensitiveInformationForceAccessCheck, // 75

    FileMaximumInformation);

  FILE_INFORMATION_CLASS = _FILE_INFORMATION_CLASS;
  PFILE_INFORMATION_CLASS = ^FILE_INFORMATION_CLASS;

type
  _PROCESSINFOCLASS = (ProcessBasicInformation = 0, ProcessQuotaLimits = 1,
    ProcessIoCounters = 2, ProcessVmCounters = 3, ProcessTimes = 4,
    ProcessBasePriority = 5, ProcessRaisePriority = 6, ProcessDebugPort = 7,
    ProcessExceptionPort = 8, ProcessAccessToken = 9,
    ProcessLdtInformation = 10, ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12, ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14, ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16, ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18, ProcessWx86Information = 19,
    ProcessHandleCount = 20, ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22, ProcessDeviceMap = 23,
    ProcessSessionInformation = 24, ProcessForegroundInformation = 25,
    ProcessWow64Information = 26, ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28, ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30, ProcessDebugFlags = 31,
    ProcessHandleTracing = 32, ProcessIoPriority = 33, ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35, ProcessCookie = 36,
    ProcessImageInformation = 37, ProcessCycleTime = 38,
    ProcessPagePriority = 39, ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41, ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43, ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45, ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47, ProcessTokenVirtualizationEnabled = 48,
    ProcessOwnerInformation = 49, ProcessWindowInformation = 50,
    ProcessHandleInformation = 51, ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53, ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55, ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57, ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59, ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61, ProcessMemoryExhaustion = 62,
    ProcessFaultInformation = 63, ProcessTelemetryIdInformation = 64,
    ProcessCommitReleaseInformation = 65, ProcessReserved1Information = 66,
    ProcessReserved2Information = 67, ProcessSubsystemProcess = 68,
    ProcessInPrivate = 70, ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
    ProcessSubsystemInformation = 75,
    ProcessWin32kSyscallFilterInformation = 79, ProcessEnergyTrackingState = 82,
    MaxProcessInfoClass);

  PROCESSINFOCLASS = _PROCESSINFOCLASS;

type
  PIO_STATUS_BLOCK = ^IO_STATUS_BLOCK;
  IO_STATUS_BLOCK = record
    case Integer of
      0: (Status: NTSTATUS);
      1: (Pointer: Pointer);
  end;

type
  _FILE_DISPOSITION_INFORMATION = record
    DeleteFile: BOOLEAN; // BOOLEAN in C++ maps to Boolean in Delphi
  end;

  FILE_DISPOSITION_INFORMATION = _FILE_DISPOSITION_INFORMATION;
  PFILE_DISPOSITION_INFORMATION = ^FILE_DISPOSITION_INFORMATION;

type
  LARGE_INTEGER = record
    LowPart: Cardinal; // Lower 32 bits
    HighPart: LongInt; // Higher 32 bits
  end;

  PLARGE_INTEGER = ^LARGE_INTEGER;

type
  _OBJECT_ATTRIBUTES = record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: ULONG;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;

  OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;

type
  _PROCESS_BASIC_INFORMATION = record
    ExitStatus: NTSTATUS;
    PebBaseAddress: PPEB;
    AffinityMask: NativeUInt;
    BasePriority: LongInt;
    UniqueProcessId: NativeUInt;
    InheritedFromUniqueProcessId: NativeUInt;
  end;

  PROCESS_BASIC_INFORMATION = _PROCESS_BASIC_INFORMATION;
  PPROCESS_BASIC_INFORMATION = ^PROCESS_BASIC_INFORMATION;

type
  __CLIENT_ID = record
    UniqueProcess: THandle;
    UniqueThread: THandle;
  end;

  CLIENT_ID = __CLIENT_ID;
  PCLIENT_ID = ^CLIENT_ID;


 type
  IMAGE_DOS_HEADER = record
    e_magic: WORD;                     // Magic number
    e_cblp: WORD;                      // Bytes on last page of file
    e_cp: WORD;                        // Pages in file
    e_crlc: WORD;                      // Relocations
    e_cparhdr: WORD;                   // Size of header in paragraphs
    e_minalloc: WORD;                  // Minimum extra paragraphs needed
    e_maxalloc: WORD;                  // Maximum extra paragraphs needed
    e_ss: WORD;                        // Initial (relative) SS value
    e_sp: WORD;                        // Initial SP value
    e_csum: WORD;                      // Checksum
    e_ip: WORD;                        // Initial IP value
    e_cs: WORD;                        // Initial (relative) CS value
    e_lfarlc: WORD;                    // File address of relocation table
    e_ovno: WORD;                      // Overlay number
    e_res: array[0..3] of WORD;        // Reserved words
    e_oemid: WORD;                     // OEM identifier (for e_oeminfo)
    e_oeminfo: WORD;                   // OEM information; e_oemid specific
    e_res2: array[0..9] of WORD;       // Reserved words
    e_lfanew: LONG;                    // File address of new exe header
  end;
  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;

  IMAGE_DATA_DIRECTORY = record
    VirtualAddress: DWORD;
    Size: DWORD;
  end;
  PIMAGE_DATA_DIRECTORY = ^IMAGE_DATA_DIRECTORY;

  IMAGE_OPTIONAL_HEADER = record
    Magic: WORD;
    MajorLinkerVersion: BYTE;
    MinorLinkerVersion: BYTE;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    {$IFDEF WIN64}
    ImageBase: ULONGLONG;
    {$ELSE}
    BaseOfData: DWORD;
    ImageBase: DWORD;
    {$ENDIF}
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: WORD;
    MinorOperatingSystemVersion: WORD;
    MajorImageVersion: WORD;
    MinorImageVersion: WORD;
    MajorSubsystemVersion: WORD;
    MinorSubsystemVersion: WORD;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: WORD;
    DllCharacteristics: WORD;
    {$IFDEF WIN64}
    SizeOfStackReserve: ULONGLONG;
    SizeOfStackCommit: ULONGLONG;
    SizeOfHeapReserve: ULONGLONG;
    SizeOfHeapCommit: ULONGLONG;
    {$ELSE}
    SizeOfStackReserve: DWORD;
    SizeOfStackCommit: DWORD;
    SizeOfHeapReserve: DWORD;
    SizeOfHeapCommit: DWORD;
    {$ENDIF}
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array[0..15] of IMAGE_DATA_DIRECTORY;
  end;
  PIMAGE_OPTIONAL_HEADER = ^IMAGE_OPTIONAL_HEADER;

  IMAGE_FILE_HEADER = record
    Machine: WORD;
    NumberOfSections: WORD;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: WORD;
    Characteristics: WORD;
  end;
  PIMAGE_FILE_HEADER = ^IMAGE_FILE_HEADER;

  IMAGE_NT_HEADERS = record
    Signature: DWORD;
    FileHeader: IMAGE_FILE_HEADER;
    OptionalHeader: IMAGE_OPTIONAL_HEADER;
  end;
  PIMAGE_NT_HEADERS = ^IMAGE_NT_HEADERS;


  // Macro replacement for NT_SUCCESS
function NT_SUCCESS(Status: NTSTATUS): BOOLEAN; inline;

// Check NT_STATUS function
function CheckNtStatus(Status: NTSTATUS; const FuncName: string): BOOLEAN;

implementation

function NT_SUCCESS(Status: NTSTATUS): BOOLEAN;
begin
  Result := Status >= 0;
end;

function CheckNtStatus(Status: NTSTATUS; const FuncName: string): BOOLEAN;
begin
  if NT_SUCCESS(Status) then
  begin
    Result := True;
  end
  else
  begin
    Writeln(Format('[!] %s Failed (0x%x)', [FuncName, Cardinal(Status)]));
    Result := False;
  end;
end;

end.
