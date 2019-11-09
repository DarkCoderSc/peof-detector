program peof_example;

uses
  Vcl.Forms,
  UntMain in 'UntMain.pas' {FrmMain},
  UntUtils in 'UntUtils.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFrmMain, FrmMain);
  Application.Run;
end.
