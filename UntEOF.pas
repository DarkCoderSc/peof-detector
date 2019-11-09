(*******************************************************************************

	Author:
		->  Jean-Pierre LESUEUR (@DarkCoderSc)
        https://github.com/DarkCoderSc
        https://gist.github.com/DarkCoderSc

        https://www.phrozen.io/

	Description:
		-> Unit for EOF manipulation on Portable Executable Files (x86/x64).
		-> Detection and Removal of EOF Data (Often used by Malware to store configuration / files etc..).

	Category:
		-> Malware Research & Detection

  License:
		-> MIT

	Functions:
		-> WritePEOF()     : Write extra data at the end of a PE File.
		-> ReadPEOF()      : Read extra data stored at the end of a PE File.
		-> FileIsValidPE() : Check whether or not a file is a valid Portable Executable File.
		-> ClearPEOF()     : Remove / Sanitize / Disinfect a PE File from any extra data stored at it end.
		-> GetPEOFSize()   : Get the size of the extra data stored at the end of a PE File.
		-> GetFileSize()   : Get the expected file size of a PE File following PE Header description.
		-> ContainPEOF()   : Return True if some extra data is detected at the end of a PE File.

*******************************************************************************)

unit UntEOF;

interface

uses WinAPI.Windows, System.SysUtils, Classes;

type
  TBasicPEInfo = record
    Valid : Boolean;     // True = Valid PE; False = Invalid PE
    Arch64 : Boolean;    // True = 64bit Image; False = 32bit Image
    ImageSize : Int64;
  end;

function WritePEOF(APEFile : String; ABuffer : PVOID; ABufferSize : Integer) : Boolean;
function ReadPEOF(APEFile : String; ABuffer : PVOID; ABufferSize : Integer; ABufferPos : Integer = 0) : Boolean;
function FileIsValidPE(AFileName : String) : Boolean;
function ClearPEOF(APEFile : String) : Boolean;
function GetPEOFSize(APEFile : String) : Int64;
function GetFileSize(AFileName : String) : Int64;
function ContainPEOF(APEFile : String) : Boolean;

implementation

{-------------------------------------------------------------------------------
  Get File Size (Nothing more to say)
-------------------------------------------------------------------------------}
function GetFileSize(AFileName : String) : Int64;
var AFileInfo : TWin32FileAttributeData;
begin
  result := 0;

  if NOT FileExists(AFileName) then
    Exit();

  if NOT GetFileAttributesEx(
                              PWideChar(AFileName),
                              GetFileExInfoStandard,
                              @AFileInfo)
  then
    Exit();

  ///
  result := (Int64(AFileInfo.nFileSizeLow) or Int64(AFileInfo.nFileSizeHigh shl 32));
end;

{-------------------------------------------------------------------------------
  Is target file a 64bit PE file
-------------------------------------------------------------------------------}
function GetBasicPEInfo(APEFile : String; var ABasicPEInfo : TBasicPEInfo) : Boolean;
var hFile : THandle;
    AImageDosHeader : TImageDosHeader;
    dwBytesRead : DWORD;
    AImageFileHeader : TImageFileHeader;
    AImageNtHeaderSignature : DWORD;
    AOptionalHeader32 : TImageOptionalHeader32;
    AOptionalHeader64 : TimageOptionalHeader64;
    I : Integer;
    AImageSectionHeader : TimageSectionHeader;
begin
  result := False;

  ABasicPEInfo.Valid     := False;
  ABasicPEInfo.Arch64    := False;
  ABasicPEInfo.ImageSize := 0;

  // Open Target File (Must Exists)
  hFile := CreateFile(
                        PChar(APEFile),
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        nil,
                        OPEN_EXISTING,
                        0,
                        0
  );
  if hFile = INVALID_HANDLE_VALUE then
    Exit;

  try
    SetFilePointer(hFile, 0, nil, FILE_BEGIN);

    // Read the Image Dos Header
    if NOT ReadFile(
                      hFile,
                      AImageDosHeader,
                      SizeOf(TImageDosHeader),
                      dwBytesRead,
                      nil
    ) then
      Exit();

    // To be considered as a valid PE file, e_magic must be $5A4D (MZ)
    if (AImageDosHeader.e_magic <> IMAGE_DOS_SIGNATURE) then
      Exit();

    // Move the cursor to Image NT Signature
    SetFilePointer(hFile, AImageDosHeader._lfanew, nil, FILE_BEGIN);

    // Read the Image NT Signature
    if NOT ReadFile(
                      hFile,
                      AImageNtHeaderSignature,
                      SizeOf(DWORD),
                      dwBytesRead,
                      nil
    ) then
      Exit();

    // To be considered as a valid PE file, Image NT Signature must be $00004550 (PE00)
    if (AImageNtHeaderSignature <> IMAGE_NT_SIGNATURE) then
      Exit();


    ABasicPEInfo.Valid := True;

    // Read the Image File Header
    if NOT ReadFile(
                      hFile,
                      AImageFileHeader,
                      sizeOf(TImageFileHeader),
                      dwBytesRead,
                      0
    ) then
      Exit();

    // TImageDosHeader.Machine contains the architecture of the file
    ABasicPEInfo.Arch64 := (AImageFileHeader.Machine = IMAGE_FILE_MACHINE_AMD64);

    if ABasicPEInfo.Arch64 then begin
      // For 64bit Image
      if NOT ReadFile(
                        hFile,
                        AOptionalHeader64,
                        sizeOf(TImageOptionalHeader64),
                        dwBytesRead,
                        0
      ) then
        Exit();

      Inc(ABasicPEInfo.ImageSize, AOptionalHeader64.SizeOfHeaders);

      Inc(ABasicPEInfo.ImageSize, AOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
    end else begin
      // For 32bit Image
      if NOT ReadFile(
                        hFile,
                        AOptionalHeader32,
                        sizeOf(TImageOptionalHeader32),
                        dwBytesRead,
                        0
      ) then
        Exit();

      Inc(ABasicPEInfo.ImageSize, AOptionalHeader32.SizeOfHeaders);

      Inc(ABasicPEInfo.ImageSize, AOptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
    end;

    // Iterate through each section to get the size of each for ImageSize calculation
    for I := 0 to AImageFileHeader.NumberOfSections -1 do begin
      if NOT ReadFile(
                        hFile,
                        AImageSectionHeader,
                        SizeOf(TImageSectionHeader),
                        dwBytesRead, 0
      ) then
        Exit(); // Fatal

      Inc(ABasicPEInfo.ImageSize, AImageSectionHeader.SizeOfRawData);
    end;

    // All steps successfully passed
    result := True;
  finally
    CloseHandle(hFile);
  end;
end;

{-------------------------------------------------------------------------------
  Is target file a valid Portable Executable
-------------------------------------------------------------------------------}
function FileIsValidPE(AFileName : String) : Boolean;
var ABasicPEInfo : TBasicPEInfo;
begin
  result := False;
  ///

  GetBasicPEInfo(AFileName, ABasicPEInfo);

  result := ABasicPEInfo.Valid;
end;

{-------------------------------------------------------------------------------
   Write Data to the End of a PE File.
-------------------------------------------------------------------------------}
function WritePEOF(APEFile : String; ABuffer : PVOID; ABufferSize : Integer) : Boolean;
var hFile : THandle;
    ABytesWritten : Cardinal;
begin
  result := false;

  if NOT FileIsValidPE(APEFile) then
    Exit();

  hFile := CreateFile(
                      PWideChar(APEFile),
                      GENERIC_WRITE,
                      0,
                      nil,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      0
  );

  if hFile = INVALID_HANDLE_VALUE then
    Exit;

  try
    SetFilePointer(hFile, 0, nil, FILE_END);

    if NOT WriteFile(
                      hFile,
                      ABuffer^,
                      ABufferSize,
                      ABytesWritten,
                      0
    ) then
      Exit();

    result := true;
  finally
    CloseHandle(hFile);
  end;
end;

{-------------------------------------------------------------------------------
   Read Data from the End of a PE File.
-------------------------------------------------------------------------------}
function ReadPEOF(APEFile : String; ABuffer : PVOID; ABufferSize : Integer; ABufferPos : Integer = 0) : Boolean;
var hFile : THandle;
    ABytesRead : Cardinal;
begin
  result := false;

  if NOT FileIsValidPE(APEFile) then
    Exit();

  hFile := CreateFile(
                        PWideChar(APEFile),
                        GENERIC_READ,
                        0,
                        nil,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        0
  );

  if hFile = INVALID_HANDLE_VALUE then
    Exit();

  try
    SetFilePointer(
                    hFile,
                    (-ABufferSize + ABufferPos),
                    nil,
                    FILE_END
    );

    if NOT ReadFile(
                      hFile,
                      ABuffer^,
                      ABufferSize,
                      ABytesRead,
                      0
    ) then
      Exit();

    result := true;
  finally
    CloseHandle(hFile);
  end;
end;

{-------------------------------------------------------------------------------
  Get Target PE File EOF Size

  return codes:
  -------------

  -1   : Error
  >= 0 : The length of EOF data found
-------------------------------------------------------------------------------}
function GetPEOFSize(APEFile : String) : Int64;
var ABasicPEInfo : TBasicPEInfo;
begin
  result := -1;

  if NOT GetBasicPEInfo(APEFile, ABasicPEInfo) then
    raise Exception.Create('Error: Invalid PE File');

  result := (GetFileSize(APEFile) - ABasicPEInfo.ImageSize);
end;

{-------------------------------------------------------------------------------
  Clear unexpected data at the end of a PE File
-------------------------------------------------------------------------------}
function ClearPEOF(APEFile : String) : Boolean;
var ABasicPEInfo : TBasicPEInfo;
    AFileStream : TMemoryStream;
    AFileSize : Int64;
    AImageSize : Int64;
begin
  result := False;

  if NOT GetBasicPEInfo(APEFile, ABasicPEInfo) then
    raise Exception.Create('Error: Invalid PE File');

  AFileSize := GetFileSize(APEFile);
  AImageSize := ABasicPEInfo.ImageSize;

  // No EOF but no error so far so we return true
  if (AFileSize - AImageSize) = 0 then begin
    Exit(True);
  end;

  {
    One technique to patch the file. Ignore content after the ImageSize
    grabbed from PE info.
  }
  AFileStream := TMemoryStream.Create();
  try
    AFileStream.LoadFromFile(APEFile);

    AFileStream.Position := 0;
    AFileStream.SetSize(AImageSize);

    AFileStream.SaveToFile(APEFile);
  finally
    AFileStream.Free;
  end;

  result := True;
end;

{-------------------------------------------------------------------------------
  Detect if a PE file contain some data at the end of the file
-------------------------------------------------------------------------------}
function ContainPEOF(APEFile : String) : Boolean;
begin
  result := (GetPEOFSize(APEFile) > 0);
end;

end.
