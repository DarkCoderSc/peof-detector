{
  JPL : @DarkCoderSc
}

unit UntUtils;

interface

uses Windows, ShlObj;

function BrowseForFolder(const ADialogTitle : String; const AInitialFolder : String = ''; ACanCreateFolder: Boolean = False) : String;

implementation

{-------------------------------------------------------------------------------
  Show native Windows Dialog to select an existing folder.
-------------------------------------------------------------------------------}

function BrowseForFolderCallBack(hwnd : HWND; uMsg: UINT; lParam, lpData: LPARAM): Integer stdcall;
begin
  if (uMsg = BFFM_INITIALIZED) then begin
    SendMessage(hwnd, BFFM_SETSELECTION, 1, lpData);
  end;

  ///
  result := 0;
end;

function BrowseForFolder(const ADialogTitle : String; const AInitialFolder : String = ''; ACanCreateFolder: Boolean = False) : String;
var ABrowseInfo : TBrowseInfo;
    AFolder  : array[0..MAX_PATH-1] of Char;
    pItem  : PItemIDList;
begin
  ZeroMemory(@ABrowseInfo, SizeOf(TBrowseInfo));
  ///

  ABrowseInfo.pszDisplayName := @AFolder[0];
  ABrowseInfo.lpszTitle := PChar(ADialogTitle);
  ABrowseInfo.ulFlags := BIF_RETURNONLYFSDIRS or BIF_NEWDIALOGSTYLE;


  if NOT ACanCreateFolder then
    ABrowseInfo.ulFlags := ABrowseInfo.ulFlags or BIF_NONEWFOLDERBUTTON;

  ABrowseInfo.hwndOwner := 0;

  if AInitialFolder <> '' then begin
    ABrowseInfo.lpfn   := BrowseForFolderCallBack;
    ABrowseInfo.lParam := NativeUInt(@AInitialFolder[1]);
  end;

  pItem := SHBrowseForFolder(ABrowseInfo);
  if Assigned(pItem) then begin
    if SHGetPathFromIDList(pItem, AFolder) then
      result := AFolder
    else
      result := '';

    GlobalFreePtr(pItem);
  end else
    result := '';
end;


end.
