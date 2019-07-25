program dosidcli;

{$APPTYPE CONSOLE}

uses
  windows, Classes, SysUtils;

const
  AGROW_ALLOC = 256;
  ADEFAULT_SIZE = 1024;

type
  tfile = record
    sf:string; //filename
    parent:string; //parent file if is inside a packed file
    hit:boolean;
    size:cardinal;
    container:string; //container type if inside a packed file
  end;

  IMAGE_DOS_HEADER = packed record
    e_magic   : Word;                         // Magic number ("MZ")
    e_cblp    : Word;                         // Bytes on last page of file
    e_cp      : Word;                         // Pages in file
    e_crlc    : Word;                         // Relocations
    e_cparhdr : Word;                         // Size of header in paragraphs
    e_minalloc: Word;                         // Minimum extra paragraphs needed
    e_maxalloc: Word;                         // Maximum extra paragraphs needed
    e_ss      : Word;                         // Initial (relative) SS value
    e_sp      : Word;                         // Initial SP value
    e_csum    : Word;                         // Checksum
    e_ip      : Word;                         // Initial IP value
    e_cs      : Word;                         // Initial (relative) CS value
    e_lfarlc  : Word;                         // Address of relocation table
    e_ovno    : Word;                         // Overlay number
    e_res     : packed array [0..3] of Word;  // Reserved words
    e_oemid   : Word;                         // OEM identifier (for e_oeminfo)
    e_oeminfo : Word;                         // OEM info; e_oemid specific
    e_res2    : packed array [0..9] of Word;  // Reserved words
    e_lfanew  : Longint;                      // File address of new exe header
  end;

  TExeFileKind = (
    fkUnknown,  // unknown file kind: not an executable
    fkError,    // error file kind: used for files that don't exist
    fkDOS,      // DOS executable
    fkExe32,    // 32 bit executable
    fkExe16,    // 16 bit executable
    fkDLL32,    // 32 bit DLL
    fkDLL16,    // 16 bit DLL
    fkVXD       // virtual device driver
  );

var
  b:array[0..4095] of byte; //i/o buffer
  exepath: String;              // path to the exe file
  exekind: TExeFileKind;        // kind of exe

/////////////////////////////////////////////////////////////////////////////////
function ExeType(const FileName: string): TExeFileKind;
  {Examines given file and returns a code that indicates the type of executable
  file it is (or if it isn't an executable)}
const
  cDOSRelocOffset = $18;  // offset of "pointer" to DOS relocation table
  cWinHeaderOffset = $3C; // offset of "pointer" to windows header in file
  cNEAppTypeOffset = $0D; // offset in NE windows header app type field
  cDOSMagic = $5A4D;      // magic number identifying a DOS executable
  cNEMagic = $454E;       // magic number identifying a NE executable (Win 16)
  cPEMagic = $4550;       // magic nunber identifying a PE executable (Win 32)
  cLEMagic = $454C;       // magic number identifying a Virtual Device Driver
  cNEDLLFlag = $80;       // flag in NE app type field indicating a DLL
var
  FS: TFileStream;              // stream to executable file
  WinMagic: Word;               // word that contains PE or NE magic numbers
  HdrOffset: LongInt;           // offset of windows header in exec file
  DOSHeader: IMAGE_DOS_HEADER;  // DOS header
  AppFlagsNE: Byte;             // byte defining DLLs in NE format
  DOSFileSize: Integer;         // size of DOS file
begin
  try
    // Open stream onto file: raises exception if can't be read
    FS := TFileStream.Create(FileName, fmOpenRead + fmShareDenyNone);
    try
      // Assume unkown file
      Result := fkUnknown;
      // Any exec file is at least size of DOS header long
      if FS.Size < SizeOf(DOSHeader) then
        Exit;
      FS.ReadBuffer(DOSHeader, SizeOf(DOSHeader));
      // DOS files begin with "MZ"
      if DOSHeader.e_magic <> cDOSMagic then
        Exit;
      // DOS files have length >= size indicated at offset $02 and $04
      // (offset $02 indicates length of file mod 512 and offset $04 indicates
      // no. of 512 pages in file)
      if (DOSHeader.e_cblp = 0) then
        DOSFileSize := DOSHeader.e_cp * 512
      else
        DOSFileSize := (DOSHeader.e_cp - 1) * 512 + DOSHeader.e_cblp;
      if FS.Size <  DOSFileSize then
        Exit;
      // DOS file relocation offset must be within DOS file size.
      if DOSHeader.e_lfarlc > DOSFileSize then
        Exit;
      // We know we have an executable file: assume its a DOS program
      Result := fkDOS;
      // Try to find offset of Windows program header
      if FS.Size <= cWinHeaderOffset + SizeOf(LongInt) then
        // file too small for windows header "pointer": it's a DOS file
        Exit;
      // read it
      FS.Position := cWinHeaderOffset;
      FS.ReadBuffer(HdrOffset, SizeOf(LongInt));
      // Now try to read first word of Windows program header
      if FS.Size <= HdrOffset + SizeOf(Word) then
        // file too small to contain header: it's a DOS file
        Exit;
      FS.Position := HdrOffset;
      // This word should be NE, PE or LE per file type: check which
      FS.ReadBuffer(WinMagic, SizeOf(Word));
      case WinMagic of
        cPEMagic:
        begin
          // 32 bit Windows application: now check whether app or DLL
          Result := fkExe32;
        end;
        cNEMagic:
        begin
          // We have 16 bit Windows executable: check whether app or DLL
          if FS.Size <= HdrOffset + cNEAppTypeOffset + SizeOf(AppFlagsNE) then
            // app flags field would be beyond EOF: assume DOS
            Exit;
          // read app flags byte
          FS.Position := HdrOffset + cNEAppTypeOffset;
          FS.ReadBuffer(AppFlagsNE, SizeOf(AppFlagsNE));
          if (AppFlagsNE and cNEDLLFlag) = cNEDLLFlag then
            // app flags indicate DLL
            Result := fkDLL16
          else
            // app flags indicate program
            Result := fkExe16;
        end;
        cLEMagic:
          // We have a Virtual Device Driver
          Result := fkVXD;
        else
          // DOS application
          {Do nothing - DOS result already set};
      end;
    finally
      FS.Free;
    end;
  except
    // Exception raised in function => error result
    Result := fkError;
  end;
end;

begin
  if paramcount<1 then
  begin
    writeln('dosidcli v1.0');
    writeln('---------------------');
    writeln('');
    writeln('Usage: dosidcli "x:\full\path\to\file.exe"');
    exit;
  end;
  exepath:=paramstr(1);
  if fileexists(exepath)=false then
  begin
    writeln('file not found.');
    exit;
  end;

  exekind := ExeType(exepath);

  if exekind = fkDOS then
  begin
    writeln('DOS!');
    exit;
  end
  else begin
    writeln('SOMETHINGELSE!');
    exit;
  end;

  writeln('Done.');
end.
