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

unit SLog;

interface

uses STypes;

procedure ConsoleLog(const Msg:String);
procedure StartDialog;
procedure StopDialog;
procedure SetLogLevel(const Lev:Byte);
function GetInputLine:String;
procedure WriteInputLine(const S:String);
procedure SetLogOutput(var F:TextFile);
procedure SetLogInput(var F:TextFile);
procedure InstallPipeConnect(const Pipe:TPipes;const PipeLog:Boolean=false);
procedure UninstallPipeConnect(var Pipe:TPipes);
{procedure SendSMsg(const Msg:TMsg;const Param;const Size:LongWord;out RealSent:LongWord);
procedure RecvSMsg(const Msg:TMsg;out Param;const BufSize:LongWord;out RealRecv:LongWord);
}

var
 LogDir:String;

const
 LogExt='.log';

implementation

uses {$IFNDEF FPC}Windows, {$ENDIF}SUtils, PipeUtils;

var
 Ride:TRide;
 cons:Integer=0;
 LogOut:^TextFile;
 LogIn:^TextFile;

procedure SetLogOutput(var F:TextFile);
begin
 StartRide(Ride);
 LogOut:=@F;
 StopRide(Ride);
end;

procedure SetLogInput(var F:TextFile);
begin
 StartRide(Ride);
 LogIn:=@F;
 StopRide(Ride);
end;

procedure ConsoleLog(const Msg:String);
var Sh:String;
begin
 StartRide(Ride);
 if InterlockedIncrement(cons)<>1 then
  Sh:=#13+Msg+#13#10+PROMPT
 else
  Sh:=Msg+#13#10;
 write(LogOut^, Sh);
 InterlockedDecrement(cons);
 StopRide(Ride);
end;

procedure StartDialog;
begin
end;

procedure StopDialog;
begin
 ConsoleLog('');
end;

procedure SetLogLevel(const Lev:Byte);
begin
end;

function GetInputLine:String;
begin
 if InterlockedIncrement(cons)=1 then
  write(LogOut^, #13#10+PROMPT);
 readln(LogIn^, Result);
 InterlockedDecrement(cons);
end;

procedure WriteInputLine(const S:String);
begin
 if InterlockedIncrement(cons)=1 then
  write(LogOut^, #13#10+PROMPT);
 StartRide(Ride);
 writeln(LogOut^, S);
 StopRide(Ride);
 InterlockedDecrement(cons);
end;

procedure InstallPipeConnect(const Pipe:TPipes;const PipeLog:Boolean=false);
begin
end;

procedure UninstallPipeConnect(var Pipe:TPipes);
begin
 ClosePipe(Pipe);
end;

{
procedure SendSMsg(const Msg:TMsg;const Param;const Size:LongWord;out RealSent:LongWord);
begin
end;

procedure RecvSMsg(const Msg:TMsg;out Param;const BufSize:LongWord;out RealRecv:LongWord);
begin
end;
}

initialization
 Ride:=RegisterRide;
 LogOut:=@Output;
 LogIn:=@Input;
{$IFDEF MSWINDOWS}
 LogDir:=GetEnvironmentVariable('APPDATA');
 if LogDir<>'' then
  begin
   if LogDir[Length(LogDir)]<>'\' then
    LogDir:=LogDir+'\';
   LogDir:=LogDir+SNAME+'\';
   if not DirectoryExists(LogDir) then
    MkDir(LogDir);
   if not DirectoryExists(LogDir) then
    LogDir:='';
  end;
 if LogDir='' then
{$ENDIF}
 LogDir:=ServerDir
finalization
 UnregisterRide(Ride);
end.
