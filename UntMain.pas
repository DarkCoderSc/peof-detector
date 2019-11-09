(*******************************************************************************

	Author:
		->  Jean-Pierre LESUEUR (@DarkCoderSc)
			  https://github.com/DarkCoderSc
			  https://gist.github.com/DarkCoderSc

			  https://www.phrozen.io/

	Description:
		-> Demonstrate how to use the UntEOF.pas Library for EOF actions.

	Category:
		-> Malware Research & Detection

  License:
		-> MIT

*******************************************************************************)

unit UntMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.Samples.Spin, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.ComCtrls, System.ImageList, Vcl.ImgList;

type
  TFrmMain = class(TForm)
    OD: TOpenDialog;
    page: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    memoread: TMemo;
    Img16: TImageList;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    edtstr: TEdit;
    Label2: TLabel;
    spint: TSpinEdit;
    Label3: TLabel;
    GroupBox2: TGroupBox;
    edtpefile: TEdit;
    btnloadpefile: TButton;
    Panel1: TPanel;
    btnReadData: TButton;
    Panel2: TPanel;
    btnWrite: TButton;
    lstscan: TListView;
    Panel3: TPanel;
    btnScan: TButton;
    btnErad: TButton;
    Memo: TMemo;
    btnRead: TButton;
    procedure btnWriteClick(Sender: TObject);
    procedure btnReadDataClick(Sender: TObject);
    procedure btnloadpefileClick(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure btnScanClick(Sender: TObject);
    procedure btnEradClick(Sender: TObject);
    procedure btnReadClick(Sender: TObject);
  private
    { Private declarations }

    procedure ScanFolder(ADirectory : String);
  public
    { Public declarations }
  end;

var
  FrmMain: TFrmMain;

implementation

uses UntEOF, UntUtils, JSON, math;

{$R *.dfm}

{-------------------------------------------------------------------------------
  Another cool function I share with you (A bit old tho)
-------------------------------------------------------------------------------}
function BufferToHexView(ABuffer : PVOID; ABufferSize : Int64; pLastOffset : PNativeUINT = nil; AStartOffset : NativeUINT = 0) : String;
var ARows     : DWORD;

    i, n      : integer;

    AVal      : Byte;
    sBuilder  : TStringBuilder;
    HexVal    : array[0..16-1] of TVarRec;
    AsciiVal  : array[0..16-1] of TVarRec;
    HexMask   : String; {%x}
    AsciiMask : String; {%s}

begin
  result := '';

  ///
  ARows := ceil(ABufferSize / 16);

  sBuilder := TStringBuilder.Create();
  try
    {
      Row
    }
    for I := 0 to ARows -1 do begin
      {
        Col
      }
      for n := 0 to 16-1 do begin
        AVal := PByte(NativeUInt(ABuffer) + (I * 16) + n)^;

        HexVal[n].VType    := vtInteger;
        HexVal[n].VInteger := AVal;

        AsciiVal[n].VType := vtChar;
        if AVal in [32..255] then begin
          AsciiVal[n].VChar := AnsiChar(AVal);
        end else begin
          AsciiVal[n].VChar := '.';
        end;
      end;

      HexMask   := '';
      AsciiMask := '';
      for n := 0 to 16-1 do begin
        if ((I * 16) + n) > ABufferSize then begin
          HexMask   := HexMask   + #32#32#32;
          AsciiMask := AsciiMask + #32#32;

          continue;
        end;

        HexMask   := HexMask + '%.2x' + #32;
        AsciiMask := AsciiMask + '%s';
      end;
      Delete(HexMask, length(HexMask), 1);

      {
        Draw
      }
      sBuilder.AppendLine(
          Format('%.8x', [AStartOffset + (I * 16)]) + '|' +
          Format(HexMask, HexVal) + '|' +
          Format(AsciiMask, AsciiVal)
      );
    end;
  finally
    result := sBuilder.ToString();

    if Assigned(pLastOffset) then begin
      pLastOffset^ := (ARows * 16);
    end;

    sBuilder.Free;
  end;
end;

procedure TFrmMain.ScanFolder(ADirectory : String);
var ASearchRec : TSearchRec;
    AFullPath : String;
    AItem : TListItem;
    AEOFSize : Int64;
begin
  if NOT DirectoryExists(ADirectory) then
    raise Exception.Create('Target directory doesn''t exists.');

  lstscan.Clear;
  btnErad.Enabled := False;

  ADirectory := IncludeTrailingPathDelimiter(ADirectory);

  if (FindFirst(Format('%s*.*', [ADirectory]), (faAnyFile - faDirectory), ASearchRec) = 0) then begin
    repeat
      AFullPath := Format('%s%s', [ADirectory, ASearchRec.Name]);
      ///

      if NOT FileIsValidPE(AFullPath) then
        continue;

      AItem := lstscan.Items.Add;

      AEOFSize := GetPEOFSize(AFullPath);

      AItem.Caption := ASearchRec.Name;
      AItem.SubItems.Add(Format('%d bytes', [AEOFSize]));
      AItem.SubItems.Add(ADirectory);

      if AEOFSize > 0 then begin
        AItem.ImageIndex := 3;
        btnErad.Enabled := True;
      end else
        AItem.ImageIndex := 4;
    until (FindNext(ASearchRec) <> 0);

    FindClose(ASearchRec);
  end;
end;

procedure TFrmMain.btnEradClick(Sender: TObject);
var i : integer;
    AItem : TlistItem;
    ATargetFolder : String;
begin
  ATargetFolder := '';

  for I := 0 to lstscan.Items.Count -1 do begin
    AItem := lstscan.Items[i];

    ATargetFolder := AItem.SubItems[1];

    if (AItem.ImageIndex <> 3) then
     continue;

    ClearPEOF(IncludeTrailingPathDelimiter(AItem.SubItems[1]) + AItem.Caption);
  end;

  // Re launch a scan on the same folder
  if ATargetFolder <> '' then
    ScanFolder(ATargetFolder);
end;

procedure TFrmMain.btnloadpefileClick(Sender: TObject);
begin
  OD.FileName := '';

  if NOT OD.Execute then
    Exit();

  edtpefile.Text := OD.FileName;
end;

procedure TFrmMain.btnWriteClick(Sender: TObject);
var AJson : TJsonObject;
    AJsonStr : String;
    ARet : Boolean;
    I : Integer;
begin
  if NOT FileExists(edtpefile.Text) then
    raise Exception.Create('Please load a valid PE file.');

  ClearPEOF(edtpefile.Text); // Clear possible existing data

  AJson := TJsonObject.Create();
  try
    AJson.AddPair('data1', TJSONString.Create(edtstr.text));
    AJson.AddPair('data2', TJSONNumber.Create(spint.value));
    AJson.AddPair('data3', TJSONString.Create(memo.Text));

    AJsonStr := AJson.ToJSON;

    ARet := WritePEOF(edtpefile.Text, @AJsonStr[1], (Length(AJsonStr) * SizeOf(WideChar)));
    if NOT ARet then
      raise Exception.Create('Could not write EOF Data to file');
  finally
    AJson.Free;
  end;

  edtstr.Clear;
  memo.Clear;

  ///
  MessageBoxW(self.Handle, 'Success', 'Write PEOF', MB_IconInformation);
end;

function GetJsonStringFromEOF(AFileName : String) : String;
var ASize : Int64;
begin
  result := '';

  if ContainPEOF(AFileName) = False then
      raise Exception.Create('The file doesn''t contain any EOF Data or is not a valid PE File.');

  {
    Read the whole EOF as JSON String
  }
  ASize := GetPEOFSize(AFileName);
  if ASize = 0 then
    raise Exception.Create('Invalid EOF Size');

  SetLength(result, (ASize div SizeOf(WideChar)));

  if NOT ReadPEOF(AFileName, @result[1], ASize) then
    raise Exception.Create('Could not read EOF Data');
end;

procedure TFrmMain.btnReadClick(Sender: TObject);
var AJson : TJsonValue;
    AJsonStr : String;
begin
  try
    AJsonStr := GetJsonStringFromEOF(edtpefile.text);

    AJson := TJsonObject.ParseJSONValue(AJsonStr); // If Invalid Json String, will trigger an exception
    try
      edtstr.Text := AJson.GetValue<string>('data1');
      spint.Value := AJson.GetValue<integer>('data2');
      Memo.Text := AJson.GetValue<string>('data3');
    finally
      AJson.Free;
    end;
  except
    on E : Exception do
      MessageBoxW(self.Handle, PWideChar('Error while retrieving EOF data : ' +  E.Message), 'Error',  MB_IconHand);
  end;
end;

procedure TFrmMain.btnReadDataClick(Sender: TObject);
var AJsonStr : String;
begin
  try
    if NOT OD.Execute() then
      exit();

    AJsonStr := GetJsonStringFromEOF(OD.FileName);

    Memoread.Text := BufferToHexView(@AJsonStr[1], Length(AJsonStr) * SizeOf(WideChar));
  except
    on E : Exception do
      MessageBoxW(self.Handle, PWideChar('Error while retrieving EOF data : ' +  E.Message), 'Error',  MB_IconHand);
  end;
end;

procedure TFrmMain.btnScanClick(Sender: TObject);
var AFolder : String;
begin
  AFolder := BrowseForFolder('Select target folder');

  if AFolder = '' then
    Exit();

  ScanFolder(AFolder);
end;

procedure TFrmMain.FormResize(Sender: TObject);
begin
  btnWrite.Left := (Panel2.Width div 2) - btnWrite.Width - 4;
  btnRead.Left  := (Panel2.Width div 2) + 4;

  btnReadData.Left  := (Panel1.Width div 2) - (btnRead.Width div 2);

  btnScan.Left  := (Panel3.Width div 2) - btnScan.Width - 4;
  btnErad.Left  := (Panel3.Width div 2) + 4;

  btnLoadPeFile.Left := edtpefile.Left + edtpefile.Width + 4;
end;

end.
