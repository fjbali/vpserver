//VPSERVER 3.0 - HTTP Server
//Copyright (C) 2009 Ivanov Viktor
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.

program Server;

{$APPTYPE CONSOLE}

{%File 'config.inc'}
{%File 'HTTP11.pas'}     
{%File 'HTTP11F.inc'}
{%File 'dynmime.inc'}
{%File 'HTTP11T.inc'}
{%File 'HTTP11T2.inc'}
{%File 'md5.pas'}
{%File 'PipeUtils.pas'}
{%File 'SBase.pas'} 
{%File 'SLog.pas'}
{%File 'STypes.pas'} 
{%File 'SUtils.pas'}
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
