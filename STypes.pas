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

unit STypes;

interface

uses {$IFDEF FPC}SysUtils, {$ENDIF}{$IFDEF MSWINDOWS}Windows, WinSock2{$ENDIF};

type
 TPStatus=(psPreAlpha, psAlpha, psBeta, psRC, psFinal);
 TMode=(mMain, mServer, mUnk);
{$IFDEF MSWINDOWS}
 TRide=record
  Lock:Integer;
  Event:THandle;
 end;
 PThreadID=^TThreadID;
{$IFNDEF FPC}
 TThreadID=LongWord;
{$ENDIF}
{$ELSE}
 TRide=TRTLCriticalSelection;
{$ENDIF}
{$IFDEF FPC}
 TTID=TThreadID;
{$ELSE}
 TTID=LongWord;
{$ENDIF}
 PStringC=^TStringC;
 TStringC=record
  Next:PStringC;
  S:String;
 end;
 PSockRecord=^TSockRecord;
 TSockRecord=record
  Socket:TSocket;
  Wait:LongWord;
  Sent:LongWord;
  Recv:LongWord;
  Ride:TRide;
 end;
 TSocket={$IFDEF MSWINDOWS}WinSock2{$ENDIF}.TSocket;
{$IFDEF MSWINDOWS}
 TSocketInfo=TWSAProtocol_Info;
 TTime=TSystemTime;
 TPipes=record
  stdinp_r:THandle;
  stdinp_w:THandle;
  stdout_r:THandle;
  stdout_w:THandle;
 end;
{$ENDIF}
 PParams=^TParams;
 TParams=record
  Name:String;
  HomeDir:String;
  IP:String;
  Port:Word;
  LogLevel:Byte;
  Sock:TSocket;
  Info:TSocketInfo;
  LogPipe:TPipes;
  RWait:LongWord;
  KAWait:LongWord;
 end;
 PServerRecord=^TServerRecord;
 TServerRecord=record
  Next:PServerRecord;
  Params:TParams;
 end;
 TConfig=record
  AmServers:Byte;
  ServerRecords:PServerRecord;
  Main:PServerRecord;
  StartupCom:PStringC;
  EndCom:PStringC;
 end;
 TServers=record
  Count:LongWord;
  Arr:Pointer;
 end;
 PServerData=^TServerData;
 TServerData=record
  Params:PParams;
  PipeIn:TextFile;
  PipeOut:TextFile;
  PI:TProcessInformation;
  IsLogging:Boolean;
  IsStart:Boolean;
 end;
 PSettings=^TSettings;
 TSettings=record
  Params:TParams;
  IsLogging:Boolean;
  IsStart:Boolean;
  hThread:TThreadID;
  tid:TTID;
 end;
 PSettingsRecord=^TSettingsRecord;
 TSettingsRecord=record
  Settings:PSettings;
  Socket:TSocket;
 end;
 TCommand=(cmQuit, cmStart, cmStop, cmStartLog, cmStopLog);
 TMsg=Byte;
 TCommandOrd=1..sizeof(TCommand)*sizeof(Byte);
 membuf=^statbuf;
 statbuf=array[1..MaxInt] of Byte;
{$IFDEF FPC}
 TTextRec=SysUtils.TTextRec;
{$ENDIF}

var
 BUILD, SERV, ServerDir:String;

const
 BADMsg='BAD';
 OKMsg='OK';
 MAXLW=$FFFFFFFF;

{$I Config.inc}

implementation

var
 t1, t2, t3, t4, t5:String;

initialization
{$IFDEF FPC}
 t1:='';
 t2:={$I %FPCVERSION%};
{$ELSE}
 Str(RTLVersion:0:1, t1);
 Str(CompilerVersion:0:1, t2);
{$ENDIF}
{$IF DECLARED(GPL)}
 t3:='1';
{$ELSE}
 t3:='0';
{$IFEND}
 Str(VER:0:1, t4);
 Str(BUILDVER, t5);
 BUILD:=t1+t2+t3+t5;
 case SSTATUS of
  psPreAlpha:
   t3:='pre-alpha';
  psAlpha:
   t3:='alpha';
  psBeta:
   t3:='beta';
  psRC:
   t3:='RC'+t5;
  psFinal:
   t3:='Final';
 end;
 SERV:=SNAME+' '+t4+' '+t3+' Build '+BUILD;
{$IFDEF MSWINDOWS}
 ServerDir:=ParamStr(0);
 while ServerDir[Length(ServerDir)]<>'\' do
  SetLength(ServerDir, Length(ServerDir)-1);
{$ELSE}
 ServerDir:='/etc/vpserver';
{$ENDIF}
end.
