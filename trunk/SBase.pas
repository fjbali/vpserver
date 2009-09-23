unit SBase;

interface

{������������� ����������� ������ �������}
//{$DEFINE DEBUG_MODE1}

uses STypes;

{���������� ����� �������}
function LoadMode:TMode;
{���������� ����}
procedure ShowLogo;
{��������� �����������}
procedure LoadConfig(out Conf:TConfig);
{��������� �������}
procedure StartServers(const Config:TConfig;out Servers:TServers);
{��������� ������}
procedure StartDialogAndWait(var Config:TConfig;var Servers:TServers);
{���������� �������}
procedure StopServers(var Servers:TServers);
{��������� ��������� �������}
procedure ReadSettings(out Settings:TSettings);
{��������� �������}
procedure ExecuteCommands(var Settings:TSettings);

implementation

uses SUtils, SLog, PipeUtils, WSUtils, HTTP11, {$IFDEF MSWINDOWS}Windows{$ENDIF};

{���������� ����� �������}
function LoadMode:TMode;
var
 i:LongWord;
 s:String;
begin
 if ParamCount=1 then
  begin {��������� �����������}
   LoadMode:=mUnk;
   {�������� MD5 ������������� �����}
   i:=Random(255);
   writeln(i);
   readln(s);
   if s<>GetMD5(i, sizeof(i)) then
    Exit;
   {�������� MD5 ������}
   i:=StrToInt(ParamStr(1));
   readln(s);
   if (s<>GetMD5(i, sizeof(i))) or (TMode(i)<>mServer) then
    Exit;
   {�� ���������� ������������}
   LoadMode:=TMode(i);
   writeln(OKMsg);
{$IFDEF MSWINDOWS}
   {�������� ������ ��� �������}
   SetConsoleTitle(PChar('Server Mode: '+ParamStr(1)));
{$ENDIF}
   Exit;
  end
 else
  begin {��� ���������� �������}
{$IFDEF DEBUG_MODE1}
   LoadMode:=mServer; {������� �������}
{$ELSE}
   LoadMode:=mMain; {������ �������� ����}
{$ENDIF}
   Exit;
  end;
 {�������� �� ������ �������������}
 writeln(BADMsg);
end;

{�������� ����}
procedure ShowLogo;

  {������� �������}
  procedure ShowSpace;
  begin
   write(' ':(((80-Length(SERV)-2) div 2)-1));
  end;

  {������� ><}
  procedure ShowSubLogo;
  var n:Integer;
  begin
   ShowSpace;
   for n:=0 to (Length(SERV) div 2) do
    write('>');
   for n:=0 to Length(SERV)-(Length(SERV) div 2) do
    write('<');
   writeln;
  end;

begin   
{$IFDEF MSWINDOWS}
 SetConsoleTitle(PChar(SERV)); {������������� ��������� ����}
{$ENDIF}
{������� ����}
 ShowSubLogo;
 ShowSpace;
 write('>'+SERV+'<'#13#10);
 ShowSubLogo;
{������� ���. �����}
 writeln(#13#10, LogoText);
 Sleep(200);
end;

{----------------------Config procs}

{������������� ������� �������}
function SetStartupCommands(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetStartupCommands:=true;
 if val='' then
  begin
   {��������� ������}
   Wait:=true;
   Exit;
  end;
 {��������� �������}
 Conf.StartupCom:=Conf.StartupCom+val+#10;
 inc(Conf.StartupNum);
end;

{������������� ������� ������}
function SetEndCommands(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetEndCommands:=true;
 if val='' then
  begin
   {��������� ������}
   Wait:=true;
   Exit;
  end;
 {��������� �������}
 Conf.EndCom:=Conf.EndCom+val+#10;
 inc(Conf.EndNum);
end;

{���������� �������� �����}
function SetHomeDir(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetHomeDir:=false;
 if curserv=nil then
  Exit; {�� � ������ �������}
 {��������� %%}
 curserv^.Params.HomeDir:=ExpandEnvString(val);
 SetHomeDir:=true;
end;

{���������� IP �������}
function SetIP(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetIP:=false;
 if curserv=nil then
  Exit; {�� � ������ �������}
 curserv^.Params.IP:=val;
 SetIP:=true;
end;

{���������� ���� �������}
function SetPort(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetPort:=false;
 if curserv=nil then
  Exit; {�� � ������ �������}
 curserv^.Params.Port:=StrToInt(val);
 SetPort:=true;
end;

{���������� ������� ��������������}
function SetLogLevel(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetLogLevel:=false;
 if (curserv=nil) or (Length(val)<>1) or (not (val[1] in ['0'..'2'])) then
  Exit; {������������ ������}
 curserv^.Params.LogLevel:=ord(val[1])-ord('0');
 SetLogLevel:=true;
end;

{���������� ������� ����������}
function SetReadWait(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetReadWait:=false;
 if curserv=nil then
  Exit; {�� � ������ �������}
 curserv^.Params.RWait:=StrToInt(val);
 SetReadWait:=true;
end;

{���������� ������� Keep-Alive ����������}
function SetKATimeout(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetKATimeout:=false;
 if curserv=nil then
  Exit; {�� � ������ �������}
 curserv^.Params.KAWait:=StrToInt(val);
 SetKATimeout:=true;
end;

{���������� ������ �������}
function SetServer(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
var
 ServerName:String;
 tempsrv:PServerRecord;
begin
 SetServer:=false;
 if val[Length(val)]<>']' then
  Exit; {����������� ���������� ������}
 ServerName:=val;
 {�������� ��� �������}
 SetLength(ServerName, Length(ServerName)-1);
 {���� ������}
 tempsrv:=Conf.ServerRecords;
 while tempsrv<>nil do
  begin
   if tempsrv^.Params.Name=ServerName then
    break;
   tempsrv:=tempsrv^.Next;
  end;
 if tempsrv=nil then
  begin {�� �����}
   New(curserv);
   if Conf.ServerRecords=nil then
    Conf.ServerRecords:=curserv {������ ������}
   else
    begin {��������� ������ � ����}
     tempsrv:=Conf.ServerRecords;
     while tempsrv^.Next<>nil do
      tempsrv:=tempsrv^.Next;
     tempsrv^.Next:=curserv;
    end;
   tempsrv:=curserv;
   tempsrv^.Next:=nil;
   if Conf.Main<>nil then
    tempsrv^.Params:=Conf.Main^.Params {��������� ��������� ������� Main}
   else
    with tempsrv^.Params do
     begin {��������� ��������� ���������}
      HomeDir:=ServerDir;
      IP:='0.0.0.0';
      Port:=80;
      LogLevel:=0;
      RWait:=5000;
      KAWait:=5000;
     end;
   tempsrv^.Params.Name:=ServerName;
   inc(Conf.AmServers);
  end
 else
  curserv:=tempsrv; {������������� ������� ������}
 if ServerName='Main' then
  Conf.Main:=tempsrv;
 SetServer:=true;
end;

{-------------------------------End}

{��������� �����������}
procedure LoadConfig(out Conf:TConfig);
var
 curserv:PServerRecord;
 Wait:Boolean;
 ind:Integer;
type
 TConfProc=function(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
const
 PRCS=9;
 {������ �����}
 ParseVals:array[0..PRCS-1] of String=(
  '[Server=', 'HomeDir=', 'IP=', 'LogLevel=', 'Port=', 'ReadWait=',
  'KeepAliveTimeout=', '[StartupCommands]', '[EndCommands]'
 );
 {������ ������������}
 ParseProc:array[0..PRCS-1] of TConfProc=(
  SetServer, SetHomeDir, SetIP, SetLogLevel, SetPort, SetReadWait,
  SetKATimeout, SetStartupCommands, SetEndCommands
 );
  {������� ������}
  function ParseLine(const val:String):Boolean;
  var
   newval:String;
  begin
   ParseLine:=false;
   Wait:=false;
   {������������ ������}
   newval:=val;
   while Pos('[ ', newval)=1 do
    Delete(newval, 2, 1);
   while Pos(' ]', newval)=(Length(newval)-1) do
    Delete(newval, Length(newval)-1, 1);
   if Pos(' =', newval)<>0 then
    Delete(newval, Pos(' =', newval), 1);
   if Pos('= ', newval)<>0 then
    Delete(newval, Pos('= ', newval)+1, 1);
   {���� ����������}
   if Pos('=', newval)<>0 then
    ind:=IndexStr(copy(newval, 1, Pos('=', newval)), ParseVals)
   else
    if (newval[Length(newval)]=']') and (newval[1]='[') then
     ind:=IndexStr(newval, ParseVals)
    else
     Exit;
   if ind<0 then
    Exit;
   {��������� ����������}
   Delete(newval, 1, Length(ParseVals[ind]));
   ParseLine:=ParseProc[ind](Conf, curserv, newval, Wait);
  end;

var
 F:Text;
 s:String;
 r:Boolean;
 Line:LongWord;
begin    
 ConsoleLog('����� ���������...');
 FillChar(Conf, sizeof(Conf), 0);
 {��������� ����}
 Assign(F, 'config.conf');
 FileMode:=0;
{$I-}
 FileMode:=0;
 Reset(F);
{$I+}
 if IOResult<>0 then
  begin
   ConsoleLog('Error: �� ���� ������� ���� �����������');
   MyHalt(2);
   Exit;
  end;
 {���������� ���������}
 curserv:=nil;
 Line:=0;
 r:=true;
 Wait:=false;
 {������ ����}
 while not Eof(F) do
  begin
   inc(Line);
   readln(F, s);
   {������������ ������}
   if Pos(';', s)<>0 then
    s:=copy(s, 1, Pos(';', s)-1);
   DelStr(s, '  ', 1);
   Crop(s);
   if s='' then
    continue;
   if (not Wait) or (copy(s, 1, 1)='[') then
    r:=ParseLine(s)
   else
    r:=ParseProc[ind](Conf, curserv, s, Wait);
   if not r then
    break;
  end;
 {������ �� ��������� �����}
// Close(F);
 if r then
  Exit;
 {�������� �� ������}
 writeln('Error: �� ���� ���������� ���� ������������ (������ '+IntToStr(Line)+')');
 MyHalt(1);
end;

{����� ������ � ����}
function FindServer(const Records:PServerRecord;const Name:String):Integer;
var T:PServerRecord;
    C:Integer;
begin
 FindServer:=-1;
 T:=Records;
 C:=0;
 {����������� ����}
 while T<>nil do
  begin
   inc(C);
   if T^.Params.Name=Name then
    begin {�����}
     FindServer:=C;
     Exit;
    end;
   T:=T^.Next;
  end;
end;

{�������� ������ � ������� �� ������}
function GetServerData(const Servers:TServers;const Num:Integer):PServerData;
begin
 GetServerData:=nil;
 if (Num<0) or (LongWord(Num)>Servers.Count) then
  Exit; {������������ �����}
 GetServerData:=PServerData(Pointer(@membuf(Servers.Arr)^[(Num-1)*sizeof(PServerData)+1])^);
end;

{�������� ��������� ������� � ����}
procedure WriteSettings(var F:TextFile;const Settings:TSettings); forward;

{��������� ��������}
procedure StartServers(const Config:TConfig;out Servers:TServers);
var
 P:PServerRecord;
 L:PServerData;
 o, t:LongWord;
 s:String;
 Pipe:TPipes;
 PI:TProcessInformation;
 OK:Boolean;
 Settings:TSettings;
begin
 ConsoleLog('������ �������...');
 {���������� ������}
 FillChar(Servers, sizeof(Servers), 0);
 P:=Config.ServerRecords;
 Servers.Count:=Config.AmServers;
 GetMem(Servers.Arr, Servers.Count*sizeof(PServerData));
 FillChar(Servers.Arr^, Servers.Count*sizeof(PServerData), 0);
 o:=0;
 {����������� ����}
 while P<>nil do
  begin
   {��������� �������}
   if WinExecWithPipe(ParamStr(0)+' '+IntToStr(ord(mServer)), {$IFDEF MSWINDOWS}SW_HIDE{$ELSE}0{$ENDIF}, Pipe, PI)=0 then
    begin
     New(L);
     FillChar(L^, sizeof(L^), 0);
     if OpenPipe(L^.PipeIn, L^.PipeOut, Pipe)=0 then
      begin {������� ������}
       L^.Params:=@P^.Params;
       L^.PI:=PI;
{$I-}
       {���������� �����������}
       readln(L^.PipeIn, t);
       writeln(L^.PipeOut, GetMD5(t, sizeof(t)));
       t:=ord(mServer);
       writeln(L^.PipeOut, GetMD5(t, sizeof(t)));
       readln(L^.PipeIn, s);
{$I+}
       PServerData(Pointer(@membuf(Servers.Arr)^[o+1])^):=L;
       OK:=(s=OKMsg) and (IOResult=0);
      end
     else
      OK:=false;
     if not OK then
      begin {������� �������}
{$IFDEF MSWINDOWS}
       TerminateProcess(PI.hProcess, INFINITE);
       CloseHandle(PI.hProcess);
       CloseHandle(PI.hThread);
       if PServerData(Pointer(@membuf(Servers.Arr)^[o+1])^)=nil then
        ClosePipe(Pipe)
       else
        begin
         Close(L^.PipeOut);
         Close(L^.PipeIn);
        end;
{$ELSE}
       PI.Terminate;
       PI.Destroy;
{$ENDIF}
       Dispose(L);
      end
     else
      begin
       {������� ���������}
       FillChar(Settings, sizeof(Settings), 0);
       Settings.Params:=P^.Params;
       WriteSettings(L^.PipeOut, Settings);
      end;
    end;
   P:=P^.Next;
   inc(o, sizeof(PServerData));
  end;
end;

{---------------------Command procs}

const
 NoEPar='������� ������� �������';
 UnkSer='����������� ������: ';
 CantS='���������� ��������� ������ ';
 SerIsNot=': ������ �� ������';

{������� HELP}
function HelpFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
begin
 ConsoleLog('������� ��������� � ����� README.TXT');
 HelpFunc:=0;
end;

{������� START}
function StartFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
var
 Num:Integer;
 L:PServerData;
 Res:LongWord;
begin
 StartFunc:=1; 
 if Param='' then
  begin {��� ���������}
   ConsoleLog(NoEPar);
   Exit;
  end;
 {���� ������}
 Num:=FindServer(Config.ServerRecords, Param);
 if Num<0 then
  begin {�� �����}
   ConsoleLog(UnkSer+Param);
   Exit;
  end;
 {�������� ������}
 L:=GetServerData(Servers, Num);
 if L=nil then
  begin {������ ���}
   ConsoleLog(CantS+Param+SerIsNot);
   Exit;
  end;
 {��������� ���������}
 if L^.IsStart then
  begin
   ConsoleLog('������ '+Param+' ��� �������');
   Exit;
  end;
 with L^.Params^ do {��������� ����}
  Res:=ListenPort(IP, Port, Sock);
 if Res<>0 then
  begin {�� �������}
   ConsoleLog(CantS+Param+': ����� �� ����� ���� ������');
   StartFunc:=Res;
   Exit;
  end;
 with L^.Params^ do {�������� ����� ��� �������}
  Res:=DuplicateSocket(Sock, L^.PI.dwProcessId, Info);
 if Res<>0 then
  begin {�� ����������}
   StopConnection(L^.Params^.Sock);
   ConsoleLog(CantS+Param+': ������ ��� �������� ������ �������');
   StartFunc:=Res;
   Exit;
  end;
{$I-}
 {��������� ������}
 writeln(L^.PipeOut, TCommandOrd(cmStart));
 for Res:=1 to sizeof(L^.Params^.Info) do
  writeln(L^.PipeOut, membuf(@L^.Params^.Info)^[Res]);
 readln(L^.PipeIn, Res);
{$I+}
 {�������� �� ������}
 if Res=0 then
  Res:=IOResult
 else
  IOResult;
 L^.IsStart:=Res=0;
 if L^.IsStart then {�� ��}
  ConsoleLog('������ '+Param+' �������')
 else
  begin {���� ������}
   StopConnection(L^.Params^.Sock);
   ConsoleLog(CantS+Param+': ������ �������');
  end;
 StartFunc:=Res;
end;

{������� STOP}
function StopFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
var
 Num:Integer;
 L:PServerData;
 Res:LongWord;
begin
{�������� �� ��, ��� � � START}
 StopFunc:=1;
 if Param='' then
  begin
   ConsoleLog(NoEPar);
   Exit;
  end;
 Num:=FindServer(Config.ServerRecords, Param);
 if Num<0 then
  begin
   ConsoleLog(UnkSer+Param);
   Exit;
  end;
 L:=GetServerData(Servers, Num);
 if L=nil then
  begin
   ConsoleLog('���������� ���������� ������ '+Param+SerIsNot);
   Exit;
  end;   
 if not L^.IsStart then
  begin
   ConsoleLog('������ '+Param+' �� �������');
   Exit;
  end;
 {��������� ����}
 StopConnection(L^.Params^.Sock);
{$I-}
 {������������� ������}
 writeln(L^.PipeOut, TCommandOrd(cmStop));
 readln(L^.PipeIn, Res);
{$I+}
 {�������� �� ������}
 if Res=0 then
  Res:=IOResult
 else
  IOResult;
 if Res<>0 then
  begin {�������� �� ������}
   ConsoleLog('��������� ������ �� ������� ������� '+Param);
   ConsoleLog('������ '+Param+' �������� �����������. ������������� ��� �������������');
  end;
 L^.IsStart:=false;
 ConsoleLog('������ '+Param+' ����������');
 StopFunc:=Res;
end;

{-------------------------------End}

{��������� ������}
procedure StartDialogAndWait(var Config:TConfig;var Servers:TServers);
type
 ComFunc=function(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
const
 ACOM=3;
 {������ ������}
 coms:array[0..ACOM-1] of String=(
  'HELP', 'START', 'STOP'
 );
 {������ ������������}
 comp:array[0..ACOM-1] of ComFunc=(
  HelpFunc, StartFunc, StopFunc
 );
var
 Com, Param:String;
 I:Integer;
 R:LongWord;
 P1:PLongWord;
 P2:PString;
begin
 ConsoleLog('������ ��������� ������...');
 {���������� � �������}
 StartDialog;
 P1:=@Config.StartupNum;
 P2:=@Config.StartupCom;
 while true do
  begin
   if P1^>0 then
    begin {��������� ������� �� ������}
     Param:=copy(P2^, 1, Pos(#10, P2^)-1);
     Delete(P2^, 1, Length(Param)+1);
     WriteInputLine(Param);
     dec(P1^);
    end
   else
    if P1=@Config.EndNum then
     break {�������}
    else
     Param:=GetInputLine; {������ �������}
   if Param='' then
    continue; {��� �������}
   {������������ ������}
   if Pos(' ', Param)<>0 then
    Com:=copy(Param, 1, Pos(' ', Param)-1)
   else
    Com:=Param;
   Delete(Param, 1, Length(Com));
   Crop(Param);
   Com:=UpString(Com);
   if Com='QUIT' then
    begin {����������� ������}
     P1:=@Config.EndNum;
     P2:=@Config.EndCom;
     continue;
    end;
   {���� �������}
   I:=IndexStr(Com, coms);
   if I<0 then {�� �����}
    ConsoleLog('Error: ����������� �������')
   else
    begin
     {���������}
     R:=comp[I](Param, Config, Servers);
     if R<>0 then
      ConsoleLog(Com+': ������ '+IntToStr(R));
    end;
  end;
 {�������� SLog, ��� �� ��������� ������}
 StopDialog;
end;

{������� �������}
procedure StopServers(var Servers:TServers);
var
 I:LongWord;
 L:PServerData;
begin
 ConsoleLog('������ �������...');
 {����������� ����}
 for I:=1 to Servers.Count do
  begin
   L:=GetServerData(Servers, I);
   if L=nil then
    continue;
{$I-}
   {���������� ������� ������}
   writeln(L^.PipeOut, TCommandOrd(cmQuit));
   Close(L^.PipeOut);
   Close(L^.PipeIn);
{$I+}
   IOResult;
{$IFDEF MSWINDOWS}
   {�������� ���������}
   if WaitForSingleObject(L^.PI.hProcess, TermTimeout)=WAIT_TIMEOUT then
    TerminateProcess(L^.PI.hProcess, INFINITE); {�������������}
   CloseHandle(L^.PI.hProcess);
   CloseHandle(L^.PI.hThread);
{$ELSE}
   L^.PI.WaitToTerminate;
   L^.PI.Destroy;
{$ENDIF}
   Dispose(L);
  end;
 FreeMem(Servers.Arr);
end;

{�������� ���������}
procedure WriteSettings(var F:TextFile;const Settings:TSettings);
begin
{$I-}
 with Settings.Params do
  begin
   writeln(F, Name);
   writeln(F, HomeDir);
   writeln(F, IP);
   writeln(F, Port);
   writeln(F, LogLevel);
   writeln(F, RWait);
   writeln(F, KAWait);
  end;
{$I+}
 IOResult;
end;

{--------- Mode Server Start ----------}

var
 ClientThreads:Integer=0; {������� �������}

{��������� ���������}
procedure ReadSettings(out Settings:TSettings); 
begin
 FillChar(Settings, sizeof(Settings), 0);
 with Settings.Params do
  begin
   readln(Name);
{$IFDEF MSWINDOWS}
   SetConsoleTitle(PChar('Server: '+Name));
{$ENDIF}
   readln(HomeDir);
   readln(IP);
   readln(Port);
   readln(LogLevel);
   readln(RWait);
   readln(KAWait);
  end;
end;

{����� ��������� �������}
function ProccessThread(P:Pointer):Integer;
var
 Settings:PSettingsRecord absolute P;
begin
 ProccessThread:=0;
 try
  {������ ���������}
  ProccessRequest(Settings^.Socket, @Settings^.Settings^.Params);  
 except
  MessageBeep(MB_ICONHAND);
 end;
 {������� ����� � �����}
 StopConnection(Settings^.Socket);
 Dispose(Settings);
 InterlockedDecrement(ClientThreads);
end;

{����� ����� ��� ������ ������}
function FindNewTID(var Tids:Pointer):PThreadID;
var s, p, t:LongWord;
    N:Pointer;
    i:Boolean;
begin
 if Tids=nil then
  begin {������ �����}
   GetMem(Tids, sizeof(TThreadID)+1);
   membuf(Tids)^[1]:=1;
   Result:=PThreadID(@membuf(Tids)^[2]);
  end
 else
  if membuf(Tids)^[1]=255 then
   begin {������������}
    repeat {���� ������ ����}
     p:=1;
     s:=1;
     GetMem(N, 255*sizeof(TThreadID)+1);
     while p<>(255*sizeof(TThreadID)+1) do
      begin
       Result:=PThreadID(@membuf(Tids)^[p+1]);
{$IFDEF MSWINDOWS}
       i:=WaitForSingleObject(Result^, 0)=WAIT_TIMEOUT;
{$ELSE}
       i:=WaitForThreadTerminate(Result^, 0)<>0;
{$ENDIF}
       if i then
        begin {����� �� ��������}
         PThreadID(@membuf(Tids)^[s+1])^:=Result^;
         inc(s, sizeof(TThreadID));
{$IFDEF MSWINDOWS}
        end
       else
        begin {�������� ������ ���������� ������}
         GetExitCodeThread(Result^, t);
         SetLastError(t);
         CloseHandle(Result^);
        end;
{$ENDIF}
       inc(p, sizeof(TThreadID));
      end;
     {������������� ������}
     FreeMem(Tids);
     GetMem(Tids, s);
     move(N^, Tids^, s);
     membuf(Tids)^[1]:=(s-1) div sizeof(TThreadID);
     FreeMem(N);
     if s=p then {��� ����������}
      Sleep(TermTimeout);
    until s<>p;
    {���� ����� �����}
    Result:=FindNewTID(Tids);
   end
  else
   begin {��������� ������}
    s:=membuf(Tids)^[1]*sizeof(TThreadID)+1;
    {������ ����� ������}
    GetMem(N, s+sizeof(TThreadID));
    move(Tids^, N^, s);
    {������� ������}
    FreeMem(Tids);
    inc(membuf(N)^[1]);
    Tids:=N;
    Result:=PThreadID(@membuf(Tids)^[s+1]);
   end;
end;

{������� ��� ������}
procedure CloseAllTIDS(Tids:Pointer);
var p:LongWord;
begin
 if Tids=nil then
  Exit;
 p:=1;
 {����������� ���� ������}
 while p<>(membuf(Tids)^[1]*sizeof(TThreadID)+1) do
  begin
{$IFDEF MSWINDOWS}
   {��� ����������}
   if WaitForSingleObject(PThreadID(@membuf(Tids)^[p+1])^, TermTimeout)=WAIT_TIMEOUT then
    begin {�����������}
     TerminateThread(PThreadID(@membuf(Tids)^[p+1])^, INFINITE);
     InterlockedDecrement(ClientThreads);
     SetLastError(WAIT_TIMEOUT);
    end;
   CloseHandle(PThreadID(@membuf(Tids)^[p+1])^);
{$ENDIF}
   inc(p, sizeof(TThreadID));
  end;
end;

{��������� �����}
function ServerThread(P:Pointer):Integer;
var
 Settings:PSettings absolute P;
 SettingsRecord:PSettingsRecord;
 Socket:TSocket;
 From:String;
 tids:Pointer;
 tid:TTID;
 hThread:PThreadID;
 le:LongWord;
begin
 SetLastError(0);
 try
  tids:=nil;
  while true do
   begin
    le:=GetLastError;
    {��� ����������}
    Result:=AcceptConnection(Settings^.Params.Sock, From, Socket);
    if Result<>0 then
     begin {������ - �����������}
      {���������� ���������� ����������}
      IgnoreIntr(le);
      {������� ������}
      CloseAllTIDS(tids);
      break;
     end
    else
     begin {�������� ����������}
      New(SettingsRecord);
      SettingsRecord^.Settings:=Settings;
      SettingsRecord^.Socket:=Socket;
      hThread:=FindNewTid(tids);
      hThread^:=BeginThread(nil, 0, ProccessThread, SettingsRecord, 0, tid);
      InterlockedIncrement(ClientThreads);
     end;
   end;
 finally
  {������� ������}
  if tids<>nil then
   FreeMem(tids);
 end;    
 ServerThread:=GetLastError;
end;

{--------------Server command procs}

{������� ��������}
procedure cmStartProc(var Settings:TSettings);
var
 R:LongWord;
begin
 if Settings.IsStart then
  begin {��� �������}
   writeln(1);
   Exit;
  end;
 with Settings.Params do
  begin {��������� ���������}
{$IFDEF DEBUG_MODE1}
   R:=ListenPort(IP, Port, Sock);
{$ELSE}
   for R:=1 to sizeof(Info) do
    readln(membuf(@Info)^[R]);
   R:=CreateDuplicatedSocket(Sock, Info);
{$ENDIF}
   if R=0 then
    begin
     {��������� ��������� �����}
     Settings.hThread:=BeginThread(nil, 0, ServerThread, @Settings, 0, Settings.tid);
     if Settings.hThread=0 then
      R:=GetLastError;
    end;
  end;
 Settings.IsStart:=R=0;
 {�������� � ����������}
 writeln(R);
end;

{������� ��������� �������}
procedure cmStopProc(var Settings:TSettings);
var R:LongWord;
begin
 if not Settings.IsStart then
  begin {�� �������}
   writeln(1);
   Exit;
  end;
 {��������� ����}
 StopConnection(Settings.Params.Sock);
{$IFDEF MSWINDOWS}
 {��������� �����}
 WaitForSingleObject(Settings.hThread, INFINITE);
 GetExitCodeThread(Settings.hThread, R);
 CloseHandle(Settings.hThread);
{$ENDIF}
 Settings.IsStart:=false;
 {�������� � ����������}
 writeln(R);
end;
  
{-------------------------------End}


{��������� �������}
procedure ExecuteCommands(var Settings:TSettings);
type
 TServCommProc=procedure(var Settings:TSettings);
const
 {������ ������������ �������}
 cmhndrs:array[TCommand] of TServCommProc=(
  nil, cmStartProc, cmStopProc
 );
var
 Com:TCommand;
begin
 while true do
  begin
   {��������� �������}
   readln(TCommandOrd(Com));
   if Com=cmQuit then
    break;
   {���������}
   cmhndrs[Com](Settings);
  end;
end;

{--------- Mode Server End ----------}

{$IFDEF MSWINDOWS}
{������ �� �����}
function MyHandlerRoutine(dwCtrlType:LongWord):Boolean; stdcall;
begin
 ConsoleLog('Error: ��������� ������� ��������� ������ � ������� ������� QUIT');
 MyHandlerRoutine:=true;
end;

var
 DefaultTitle:String;
 Len:LongWord;
{$ELSE}
var
{$ENDIF}
 LastExceptProc:Pointer;
 LastErrorProc:Pointer;
 LastExitProc:Pointer;

{����������� ������}

procedure ExceptHandler(ExceptObject:TObject;ExceptAddr:Pointer{$IFDEF FPC};FrameCount:LongInt;Frame:PPointer{$ENDIF});
begin
{$I-}
 PauseAllThreads;
 writeln('��������� �������������� ����������');
 writeln('�����: ', LongWord(ExceptAddr));
{$IFDEF FPC}
 writeln('Frame count: ', FrameCount);
 if Frame<>nil then
  writeln('Frame: ', LongWord(Frame^));
{$ELSE}
 if Assigned(ExceptObject) then
  ExceptObject.Destroy;
{$ENDIF}
{$I+}     
 IOResult;
end;

procedure SErrorProc(ErrorCode:{$IFDEF FPC}LongInt{$ELSE}Byte{$ENDIF};Addr:Pointer{$IFDEF FPC};Frame:Pointer{$ENDIF});
begin
{$I-}
 PauseAllThreads;
 writeln('��������� ������ � ��������� ���������� ���������');
 writeln('�����: ', LongWord(Addr));
 writeln('��� ������: ', ErrorCode);
{$IFDEF FPC}
 writeln('Frame: ', LongWord(Frame));
{$ENDIF}
 ExitCode:=0;
 ErrorAddr:=nil;
{$I+}
 IOResult;
end;

procedure SExitProc;
begin
 ExitProc:=LastExitProc;
 if ErrorAddr<>nil then
  SErrorProc(ExitCode, ErrorAddr{$IFDEF FPC}, nil{$ENDIF});
end;

initialization
{$IFDEF MSWINDOWS}
 {������ �� �����}
 SetConsoleCtrlHandler(@MyHandlerRoutine, true);
 {�������� �������� ���� �� ���������}
 Len:=GetConsoleTitle(nil, 0);
 SetLength(DefaultTitle, Len);
 if Len<>0 then
  GetConsoleTitle(PChar(DefaultTitle), Len);
 {������������� ����� �������� ������}
 SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOOPENFILEERRORBOX or SEM_NOALIGNMENTFAULTEXCEPT);
{$ENDIF}
 {������������� ����������� ������}
 LastExceptProc:={$IFDEF FPC}@{$ENDIF}ExceptProc;
 LastErrorProc:=@ErrorProc;
 LastExitProc:=ExitProc;
 ExceptProc:=@ExceptHandler;
 ErrorProc:=SErrorProc;
 ExitProc:=@SExitProc;
 {��������� ���� ���������� ���������}
 SUtils.SetEnvironmentVariable('VPSERVERdir', ServerDir);
 {��������� ��� ���� STDIO}
 Rewrite(Output);
 Reset(Input);
 AutoFlush(Output);
 AutoFlush(Input);
finalization
{$IFDEF MSWINDOWS}
 {���������� ���������}
 SetConsoleTitle(PChar(DefaultTitle));
{$ENDIF}
 {���������� ����������� ������}
 if {$IFDEF FPC}@{$ENDIF}ExceptProc=@ExceptHandler then
  ExceptProc:=LastExceptProc;
 if @ErrorProc=@SErrorProc then
  ErrorProc:=LastErrorProc;
 if ExitProc=@SExitProc then
  ExitProc:=LastExitProc;
end.
