unit STypes;

interface

uses {$IFDEF FPC}SysUtils, {$ENDIF}{$IFNDEF MSWINDOWS}BaseUnix, Sockets, Process, Pipes{$ELSE}Windows, WinSock2{$ENDIF};

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
 TThreadID=Integer;
{$ENDIF}
{$ELSE}
 TRide=TRTLCriticalSelection;
{$ENDIF}
{$IFDEF FPC}
 TTID=TThreadID;
{$ELSE}
 TTID=LongWord;
{$ENDIF}
 PSockRecord=^TSockRecord;
 TSockRecord=record
  Socket:TSocket;
  Wait:LongWord;
  Sent:LongWord;
  Recv:LongWord;
  Ride:TRide;
 end;
 TSocket={$IFNDEF MSWINDOWS}Sockets{$ELSE}WinSock2{$ENDIF}.TSocket;
{$IFDEF MSWINDOWS}
 TSocketInfo=TWSAProtocol_Info;
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
  StartupCom:String;
  StartupNum:LongWord;
  EndCom:String;    
  EndNum:LongWord;
 end;
{$IFDEF MSWINDOWS}
 TTime=TSystemTime;
 TPipes=record
  stdinp_r:THandle;
  stdinp_w:THandle;
  stdout_r:THandle;
  stdout_w:THandle;
 end;
{$ELSE}
 TProcessInformation=TProcess;
 TPipes=record                           
  OutP:TOutputPipeStream;
  InP:TInputPipeStream;
 end;
{$ENDIF}
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
  IsStart:Boolean;
 end;
 PSettings=^TSettings;
 TSettings=record
  Params:TParams;
  IsStart:Boolean;
  hThread:TThreadID;
  tid:TTID;
 end;
 PSettingsRecord=^TSettingsRecord;
 TSettingsRecord=record
  Settings:PSettings;
  Socket:TSocket;
 end;
 TCommand=(cmQuit, cmStart, cmStop);
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
 Str(BUILDVER:0:1, t5);
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
