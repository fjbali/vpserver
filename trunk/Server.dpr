program Server;

{$APPTYPE CONSOLE}

{%File 'HTTP11.pas'}     
{%File 'HTTP11F.inc'}
{%File 'HTTP11T.inc'}
{%File 'HTTP11T2.inc'}
{%File 'md5.pas'}
{%File 'PipeUtils.pas'}
{%File 'SBase.pas'} 
{%File 'SLog.pas'}
{%File 'STypes.pas'} 
{%File 'SUilts.pas'}
{%File 'winsock2.pas'}
{%File 'WSAdapt.inc'}
{%File 'WSUtils.pas'}

uses STypes, SUtils, SBase;

var
 Mode:TMode;
 Config:TConfig;
 Servers:TServers;
 Settings:TSettings;

begin
 ChDir(ServerDir);
 Mode:=LoadMode;
 case Mode of
  mMain:
   begin
    ShowLogo;
    LoadConfig(Config);
    StartServers(Config, Servers);
    StartDialogAndWait(Config, Servers);
    StopServers(Servers);
    MyWait;
   end;
  mServer:
   begin
    FillChar(Settings, sizeof(Settings), 0);
    ReadSettings(Settings);
    ExecuteCommands(Settings);
   end;
 end;
end.
