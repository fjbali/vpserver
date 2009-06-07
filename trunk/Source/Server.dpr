program Server;

{$APPTYPE CONSOLE}
{$H+} {��������� ������� ������!}

{=======���������� �����=======}

type
 PWSABUF=^WSABUF;     //��������� ��� ������
 WSABUF=record
  len:Longint;
  buf:Pointer;
 end;
 PWSAEVENT=^WSAEVENT; //"������" ��� ��������
 WSAEVENT=LongWord;
 PWSAOVERLAPPED=^WSAOVERLAPPED; //��������� ��� ��������
 WSAOVERLAPPED=record
  Internal:LongWord;
  InternalHigh:LongWord;
  Offset:LongWord;
  OffsetHigh:LongWord;
  hEvent:WSAEVENT;
 end;
 PSOCKET=^TSOCKET;    //���������� ������
 TSOCKET=Integer;
 PWSADATA=^WSADATA;   //������ � WS2_32.DLL
 WSADATA=record
  wVersion:Word;
  wHighVersion:Word;
  szDescription:array[0..256] of Char;
  szSystemStatus:array[0..128] of Char;
  iMaxSockets:Word;
  iMaxUpdDg:Word;
  lpVendorInfo:PChar;
 end;
 Pin_addr=^in_addr;   //����� ����������
 in_addr=record
  case Byte of
   0:(S_un_b:record
       s_b1, s_b2, s_b3, s_b4:Byte;
      end);
   1:(S_un_w:record
       s_w1, s_w2:Word;
      end);
   2:(S_addr:Longint);
 end;
 sockaddr_in=record   //����� ��������� ������ ������
  sin_family:Smallint;
  sin_port:Word;
  sin_addr:in_addr;
  sin_zero:array[1..8] of Char;
 end;
 Psockaddr=^sockaddr; //����� ������
 sockaddr=record
  sa_family:Word;
  sa_data:array[0..13] of Char;
 end;
 PSystemTime=^TSystemTime; //�����
 TSystemTime=record
  wYear:Word;
  wMonth:Word;
  wDayOfWeek:Word;
  wDay:Word;
  wHour:Word;
  wMinute:Word;
  wSecond:Word;
  wMilliseconds:Word;
 end;
 TFileTime=record     //����� �����
  dwLowDateTime:LongWord;
  dwHighDateTime:LongWord;
 end;
 TWin32FindData=record //������ � �����
  dwFileAttributes:LongWord;
  ftCreationTime:TFileTime;
  ftLastAccessTime:TFileTime;
  ftLastWriteTime:TFileTime;
  nFileSizeHigh:LongWord;
  nFileSizeLow:LongWord;
  dwReserved0:LongWord;
  dwReserved1:LongWord;
  cFileName:array[0..259] of Char;
  cAlternateFileName:array[0..13] of Char;
 end;
 LogLev=(llAll, llNotice, llError); //������ ����

{=======������� �������=======}

 TMGetInfo=function:PChar; stdcall;
 TMInitProc=function(var h:LongWord):Boolean; stdcall;
 TMRelProc=procedure(h:LongWord); stdcall;
 TMMethProc=function(h:LongWord;Meth:PChar):Boolean; stdcall;
 TMHeadProc=function(h:LongWord;HName:PChar;HVal:PChar):Boolean; stdcall;
 TMLoadPostProc=procedure(h:LongWord;var Buf;Size:LongWord); stdcall;
 TMLoadGetProc=procedure(h:LongWord;GETLine:PChar); stdcall;
 TMLoadMeth=procedure(h:LongWord;Meth:PChar); stdcall;
 TMQueryProc=function(h:LongWord;PartOP, OptOP, KAlive, PostOP:Boolean;ppath:PChar):Boolean; stdcall;
 TMUpdateParamsProc=function(h:LongWord;var PartOP, OptOP, KAlive, SCLen:Boolean;resph:PChar):LongWord; stdcall;
 TMGetHLine=function(h:LongWord;n:LongWord;main:Boolean):PChar; stdcall;
 TMSetPosProc=function(h:LongWord;var ofs:Longint):Boolean; stdcall;
 TMReadProc=procedure(h:LongWord;var Buf;BufSize:LongWord;var RealRead:Longint); stdcall;
 TMConfProc=function(s:PChar):Boolean; stdcall;
 TMGetSMeth=procedure(h:LongWord;n:LongWord;Str:PChar);

{=======�������� ���������=======}

const
 AF_INET=2;                //�� �� ����
 SOCK_STREAM=1;            //�� �� �������
 IPPROTO_TCP=6;            //�� �� TCP
 SOCKET_ERROR=-1;          //��� ������
 WSA_IO_PENDING=997;       //����� ���������� IO
 INFINITE=$FFFFFFFF;       //����� �� ������ ������
 WSA_INFINITE=INFINITE;    //-|-
 SYS=-1;                   //������� �������
 MAX_L=151;                //����������� �������
 VER='2.74alpha';          //������
 SERV='VPSERVER '+VER;     //��� �������

{=======API-�������=======}

//�������������
function WSAStartup(wVersionRequested:Integer;lpWSAData:PWSADATA):Integer; stdcall; external 'WS2_32.DLL';
//�������������� ����������� ��� ������
function socket(af, stype, protocol:Integer):TSOCKET; stdcall; external 'WS2_32.DLL';
//�������������� �����
function htons(hostshort:Word):Word; stdcall; external 'WS2_32.DLL';
//������ �� IP
function inet_ntoa(addr:in_addr):PChar; stdcall; external 'WS2_32.DLL';
//��������� ������
function WSAGetLastError:Integer; stdcall; external 'WS2_32.DLL';
//IP �� ������
function inet_addr(cp:PChar):Longint; stdcall; external 'WS2_32.DLL';
//��������� � ������ �����
function bind(s:TSocket;name:Psockaddr;namelen:Integer):Integer; stdcall; external 'WS2_32.DLL';
//�������
function listen(s:TSocket;backlog:Integer):Integer; stdcall; external 'WS2_32.DLL';
//����� ��������
function accept(s:TSocket;addr:Psockaddr;addrlen:PInteger):TSocket; stdcall; external 'WS2_32.DLL';
//������� "������"
function WSACreateEvent:WSAEVENT; stdcall; external 'WS2_32.DLL';
//�������� �����
function WSARecv(s:TSocket;lpBuffers:PWSABUF;dwBufferCount:LongWord;
                 lpNumberOfBytesRecvd:PLongWord;lpFlags:
                 PLongWord;lpOverlapped:PWSAOVERLAPPED;lpCompletionRoutine:Pointer):Integer; stdcall; external 'WS2_32.DLL';
//��������� �����
function WSASend(s:TSocket;lpBuffers:PWSABUF;dwBufferCount:LongWord;
                 lpNumberOfBytesSent:PLongWord;lpFlags:LongWord;
                 lpOverlapped:PWSAOVERLAPPED;lpCompletionRoutine:Pointer):Integer; stdcall; external 'WS2_32.DLL';
//����� ��� "������"
function WSAWaitForMultipleEvents(cEvents:LongWord;const lphEvents:PWSAEVENT;fWaitAll:Boolean;dwTimeout:LongWord;fAlertable:Boolean):LongWord; stdcall; external 'WS2_32.DLL';
//�������� "������"
function WSAResetEvent(hEvent:WSAEVENT):Boolean; stdcall; external 'WS2_32.DLL';
//�������� ���������
function WSAGetOverlappedResult(s:TSOCKET;lpOverlapped:PWSAOVERLAPPED;lpcbTransfer:PLongWord;fWait:Boolean;lpdwFlags:PLongWord):Boolean; stdcall; external 'WS2_32.DLL';
//������� �����
function closesocket(s:TSocket):Integer; stdcall; external 'WS2_32.DLL';
//������� "������"
function WSACloseEvent(hEvent:WSAEVENT):Boolean; stdcall; external 'WS2_32.DLL';
//���������, ��������
function InterlockedIncrement(var Addend:Integer):Integer; stdcall; external 'kernel32.dll';
//���������, ��������
function InterlockedDecrement(var Addend:Integer):Integer; stdcall; external 'kernel32.dll';
//��������� ������
function GetLastError:LongWord; stdcall; external 'kernel32.dll';
//����������� ������
function FormatMessage(dwFlags:LongWord;lpSource:Pointer;dwMessageId:LongWord;dwLanguageId:LongWord;
                       lpBuffer:PChar;nSize:LongWord;Arguments:Pointer):LongWord; stdcall; external 'kernel32.dll' name 'FormatMessageA';
//�����
procedure Sleep(dwMilliseconds:LongWord); stdcall; external 'kernel32.dll';
//����������� �����
function ResumeThread(hThread:LongWord):LongWord; stdcall; external 'kernel32.dll';
//������������ �����
function SuspendThread(hThread:LongWord):LongWord; stdcall; external 'kernel32.dll';
//��������� �����
function TerminateThread(hThread:LongWord;dwExitCode:LongWord):Boolean; stdcall; external 'kernel32.dll';
//�������� ���������� �� ���������
function GetEnvironmentVariableA(lpName:PChar;lpBuffer:PChar;nSize:LongWord):LongWord; stdcall; external 'kernel32.dll';
//�������� ������� �����
function GetFileAttributesA(lpFileName:PChar):LongWord; stdcall; external 'kernel32.dll';
//������� ����������
function CloseHandle(hObject:LongWord):Boolean; stdcall; external 'kernel32.dll';
//�������� ������������� �������� ������
function GetCurrentThreadId:LongWord; stdcall; external 'kernel32.dll';
//�������� ��������� ����� (GMT)
procedure GetSystemTime(var lpSystemTime:TSystemTime); stdcall; external 'kernel32.dll';
//����� ����
function FindFirstFileA(lpFileName:PChar;var lpFindFileData:TWin32FindData):LongWord; stdcall; external 'kernel32.dll' name 'FindFirstFileA';
//������� �����
function FindClose(hFindFile:LongWord):Boolean; stdcall; external 'kernel32.dll';
//�������� ��������� ����� �� ������� �����
function FileTimeToSystemTime(const lpFileTime:TFileTime;var lpSystemTime:TSystemTime):Boolean; stdcall; external 'kernel32.dll' name 'FileTimeToSystemTime';
//������� "������"
function CreateEvent(lpEventAttributes:Pointer;bManualReset, bInitialState:Boolean;lpName:PChar):LongWord; stdcall; external 'kernel32.dll' name 'CreateEventA';
//���������� "������"
function SetEvent(hEvent:LongWord):Boolean; stdcall; external 'kernel32.dll';
//�������� "������"
function ResetEvent(hEvent:LongWord):Boolean; stdcall; external 'kernel32.dll';
//����� "������"
function WaitForSingleObject(hHandle:LongWord;dwMilliseconds:LongWord):LongWord; stdcall; external 'kernel32.dll';
//��������� ����������
function LoadLibrary(lpLibFileName:PChar):LongWord; stdcall; external 'kernel32.dll' name 'LoadLibraryA';
//����� ���������
function GetProcAddress(hModule:LongWord;lpProcName:PChar):Pointer; stdcall; external 'kernel32.dll' name 'GetProcAddress';
//����� ������
function SetErrorMode(uMode:LongWord):LongWord; stdcall; external 'kernel32.dll';

{=======��������������� �������=======}

//�������� �������� ������
function SysErrorMessage(ErrorCode:Integer):String;
var Buffer:array[0..255] of Char;
    Len:Integer;
begin
 Len:=FormatMessage($3200, nil, ErrorCode, 0, Buffer, sizeOf(Buffer), nil);
 while (Len>0) and (Buffer[Len-1] in [#0..#32, '.']) do
  dec(Len);
 SetString(Result, Buffer, Len);
end;
//���������� Int � Str
procedure CvtInt; Assembler;
asm
 or cl, cl
 jnz @CvtLoop
@C1:
 or eax, eax
 jns @C2
 neg eax
 call @C2
 mov al, '-'
 inc ecx
 dec esi
 mov [esi], al
 ret
@C2:
 mov ecx, 10
@CvtLoop:
 push edx
 push esi
@D1:
 xor edx, edx
 div ecx
 dec esi
 add dl, '0'
 cmp dl, '0'+10
 jb @D2
 add dl, ('A'-'0')-10
@D2:
 mov [esi], dl
 or eax, eax
 jne @D1
 pop ecx
 pop edx
 sub ecx, esi
 sub edx, ecx
 jbe @D5
 add ecx, edx
 mov al, '0'
 sub esi, edx
 jmp @z
@zloop:
 mov [esi+edx], al
@z:
 dec edx
 jnz @zloop
 mov [esi], al
@D5:
end;
//��������� Int � Str
function IntToStr(Value:Integer):String; Assembler;
asm
 push esi
 mov esi, esp
 sub esp, 16
 xor ecx, ecx
 push edx
 xor edx, edx
 call CvtInt
 mov edx, esi
 pop eax
 call System.@LStrFromPCharLen
 add esp, 16
 pop esi
end;
//��������� Str � Int
function StrToInt(const S:string):Integer;
var E:Integer;
begin
 Val(S, Result, E);
 if E<>0 then
  Result:=-MaxInt;
end;
//�������� ���������� �� ���������
function GetEnvironmentVariable(const Name:String):String;
var Len:Integer;
begin
 Result:='';
 Len:=GetEnvironmentVariableA(PChar(Name), nil, 0);
 if Len>0 then
  begin
   SetLength(Result, Len-1);
   GetEnvironmentVariableA(PChar(Name), PChar(Result), Len);
  end;
end;
//���������� ������������� �����
function DirectoryExists(const Directory:String):Boolean;
var Code:Integer;
begin
 Code:=GetFileAttributesA(PChar(Directory));
 Result:=(Code<>-1) and (($10 and Code)<>0);
end;
//�������� ��������� ��������� �����
function FileLastWriteDate(const FileName:String):TSystemTime;
var Handle:LongWord;
    FindData:TWin32FindData;
begin
 Handle:=FindFirstFileA(PChar(FileName), FindData);
 if Handle<>INFINITE then
  begin
   FindClose(Handle);
   if ((FindData.dwFileAttributes and $10)=0) and FileTimeToSystemTime(FindData.ftLastWriteTime, Result) then
    Exit;
  end;
 FillChar(Result, sizeof(TSystemTime), 0);
end;
//������� ������ �� ������
procedure DelStr(var s:String;substr:String;del:Integer);
begin
 while Pos(substr, s)<>0 do
  Delete(s, Pos(substr, s), del);
end;
//������������� � ������� �������
function UpString(s:String):String;
var i:Integer;
begin
 Result:=s;
 for i:=1 to Length(s) do
  Result[i]:=UpCase(Result[i]);
end;

{=======������� ������======}

var MGetInfo:TMGetInfo=nil;
    MInitProc:TMInitProc=nil;
    MRelProc:TMRelProc=nil;
    MMethProc:TMMethProc=nil;
    MHeadProc:TMHeadProc=nil;
    MLoadPostProc:TMLoadPostProc=nil;
    MLoadGetProc:TMLoadGetProc=nil;
    MLoadMeth:TMLoadMeth=nil;
    MQueryProc:TMQueryProc=nil;
    MUpdateParamsProc:TMUpdateParamsProc=nil;
    MGetHLine:TMGetHLine=nil;
    MSetPosProc:TMSetPosProc=nil;
    MReadProc:TMReadProc=nil;
    MConfProc:TMConfProc=nil;
    MGetSMeth:TMGetSMeth=nil;
    PlugInst:Boolean=false;

{=======�������� ����������=======}

var ListenSocket:TSOCKET;                  //��������� �����
    ThreadCount:Integer;                   //���������� �������
    ThreadBusy:array[1..MAX_L] of Boolean; //���� ���������
    ThreadBe:array[1..MAX_L] of Boolean;   //���� �������������
    ThreadHnd:array[1..MAX_L] of LongWord; //����������� �������
    ThreadID:array[1..MAX_L] of LongWord;  //�������������� �������
    ThreadSock:array[1..MAX_L] of TSocket; //������ �������
    ThreadFl:array[1..MAX_L] of File;      //����� �������
    ThreadLog:array[1..MAX_L] of Text;     //���� �������
//    CreateThreadLock:Integer;              //���������� ��������� CreateThreadListener
    LogMsgLock:Integer;                    //���������� ��������� LogMsg
    LogMsgLockE:LongWord;                  //�������� ��� ��������� LogMsg
    LogMsgLockT:LongWord;                  //����� ��������� LogMsg
    TerminateAllThreadsLock:Integer;       //���������� ��������� TerminateAllThreads
    TerminateAllThreadsLockE:LongWord;     //�������� ��� ��������� TerminateAllThreads
    KTimeOut, BTimeOut:LongWord;           //�������� ����������
    SMode:Boolean=false;                   //���������� �����
    mx:Integer;                            //���������� �������
    CheckThreadsLock:Integer;              //���������� ��������� CheckThreads
    CheckThreadsLockT:LongWord;            //����� ��������� CheckThreads

{=======����� �������=======}

procedure Panic_; forward;                              //������
procedure CreateThreadListener(f:Integer); forward;     //������� ����������
procedure LogMsg(lev:LogLev;from:Integer;msg:String); forward; //�������� � ���
procedure MyQuit(ReturnCode:Integer); forward;          //�������������� ����������
procedure MyHalt(ReturnCode:Integer); forward;          //��������� ����������
function FormatSysTime(t:TSystemTime):String; forward;  //������������� �����/����
function GetFormatedTime:String; forward;               //�������� ��������������� �����/����

{=======������ �������=======}

function PanicP(a:Pointer):Integer;
begin
 Result:=0;
 Panic_;
end;

procedure Panic;
var ID:LongWord;
begin
 BeginThread(nil, 0, @PanicP, nil, 0, ID);
 LogMsg(llError, SYS, 'Panic thread '+IntToStr(ID));
end;

//��������� �� ����������
procedure CheckThreads(s:Integer);
var i:Integer;
    f:Boolean;
begin
 if InterlockedIncrement(CheckThreadsLock)<>1 then
  begin
   InterlockedDecrement(CheckThreadsLock);
   LogMsg(llAll, s, 'CheckThreads is already started by other thread');
   Exit;
  end;
 CheckThreadsLockT:=GetCurrentThreadId;
 f:=false;
 while ThreadCount<mx do
  begin
   if not f then
    begin
     f:=true;
     LogMsg(llAll, s, 'Starting threads...');
    end;
   CreateThreadListener(s);
  end;
 f:=false;
 for i:=1 to MAX_L do          //�������� �� ���� �������
  if ThreadBe[i] and (not ThreadBusy[i]) then
   begin
    f:=true;
    break;
   end;
 if not f then
  begin
   //��������� ������� �� ����������
   LogMsg(llAll, s, 'No threads are free! Create new!');
   CreateThreadListener(s);      //������� ����� �����
  end;
 CheckThreadsLockT:=0;
 InterlockedDecrement(CheckThreadsLock);
end;

const
 fhsbc='File has been closed'; //��������� � �������������� �������� �����
 rtout='Read timeout';         //�������� ����� ��������

//��������� ������
function ThreadProc(Index:PInteger):Integer;
var EventTotal:Longint;
    EventArray:array[0..63] of WSAEVENT;
    i:Integer;
    UKAlive, FErr:Boolean;
//������� ��������/��������� ������
function SendRecvBuf(var buf;len:Longint;r:Boolean):Longint;
var DataBuf:WSABUF;
    SentRecvBytes, Flags, BytesTransferred:Longint;
    AcceptOverlapped:WSAOVERLAPPED;
    EIndex:LongWord;
    Res:Integer;
    w:LongWord;
begin
 //������������� (��������� ���������� � ������ ���������� ��������)
 EventTotal:=0;
 EventArray[EventTotal]:=WSACreateEvent;
 FillChar(AcceptOverlapped, sizeof(WSAOVERLAPPED), 0);
 AcceptOverlapped.hEvent:=EventArray[EventTotal];
 DataBuf.len:=len;
 DataBuf.buf:=@buf;
 Flags:=0;
 EIndex:=EventTotal;
 inc(EventTotal);   
 BytesTransferred:=0;
 if r then   //���� r=true, �� �������� ������
  Res:=WSARecv(ThreadSock[i], @DataBuf, 1, @SentRecvBytes, @Flags, @AcceptOverlapped, nil)
 else        //���� r=false, �� ��������� ������
  Res:=WSASend(ThreadSock[i], @DataBuf, 1, @SentRecvBytes, Flags, @AcceptOverlapped, nil);
 if Res=SOCKET_ERROR then  //������
  if WSAGetLastError<>WSA_IO_PENDING then //�������� �� ������������ ����/�����
//   begin
//    LogMsg(llError, i, 'Error '+IntToStr(WSAGetLastError)+' occured at WSASend()/WSARecv(): '+SysErrorMessage(WSAGetLastError));
    FErr:=true//;
//    Exit;    //���������� 0
//   end
  else
   begin     //����/����� �� �������. ���������� ���������
    if UKAlive then
     w:=KTimeOut
    else
     w:=BTimeOut; //��� 5 ������ - ���� ������ ����������
    EIndex:=WSAWaitForMultipleEvents(EventTotal, @EventArray, false, w, false);
    if EIndex<>$102 then
     begin
      WSAResetEvent(EventArray[EIndex]);
      WSAGetOverlappedResult(ThreadSock[i], @AcceptOverlapped, @BytesTransferred, false, @flags);
     end
    else
     begin
      SetLastError(0);
      FErr:=true;
     end;
   end
 else
  BytesTransferred:=SentRecvBytes;
 if BytesTransferred<>0 then
  WSACloseEvent(EventArray[EIndex]);
 Result:=BytesTransferred; //���������� ����������� ����������/�������� ����
 if WSAGetLastError=WSA_IO_PENDING then
  SetLastError(0); //���������� IO_PENDING
end;
//��������� �����
function SendBuf(var buf;len:Longint):Longint;
begin
 Result:=SendRecvBuf(buf, len, false);
end;
//������� �����
function RecvBuf(var buf;len:Longint):Longint;
begin
 Result:=SendRecvBuf(buf, len, true);
end;
//�������������� ��� ��� Accept-Ranges
type
 PContRang=^TContRang;
 TContRang=record
  StartR:Longint;  //������
  EndR:Longint;    //�����
  Next:PContRang;  //���������
 end;
var wholen:Integer;
    who:sockaddr_in;
    buf:array[1..4096] of Byte;
    buf2:array[1..4096] of Char absolute buf;
    sz, o, arecv, asent, stofs, enofs, PostCL:Longint;
    r, HttpV, resph, ppath, val:String;
    HeadOP, PartOP, Err, OptOP, KAlive, PostOP, NPlugInst, PAcc:Boolean;
    contr, curr, lr:PContRang;
    hmod:LongWord;
    rbuf:array[Byte] of Char;
//������������� ������
procedure ReformStr(var s:String);
function Hex(c:Char):LongWord;
begin
 if ord(c)<ord('A') then
  Hex:=ord(c)-ord('0')+((ord(c)-ord('0')) div 10)*1000
 else
  Hex:=ord(c)-ord('A')+10+((ord(c)-ord('A')) div 6)*1000;
end;
function UnicodeToChar(u:LongWord):Char;
begin
 UnicodeToChar:=WideCharLenToString(PWideChar(@u), 1)[1];
end;
var ps, ns, ls, cc, l:LongWord;
    t:Longint;
begin
 while Pos('%', s)<>0 do
  begin
   ps:=Pos('%', s);
   ns:=1;
   cc:=ns;
   ls:=0;
   while ns<>0 do
    begin
     t:=ps+(cc-1)*3;
     if ((Length(s)-t)<2) or (s[t]<>'%') then
      l:=255
     else
      l:=Hex(s[t+2])+Hex(s[t+1])*16;
     if l>254 then
      begin
       cc:=2;
       l:=0;
      end;
     t:=0;
     while odd(l shr (7-t)) do
      inc(t);
     if t>0 then
      inc(ns, t-1)
     else
      if cc<>1 then
       begin
        ls:=0;
        break;
       end;
     dec(ns);
     inc(cc);
     ls:=(ls shl (7-t)) or (l and (not (((1 shl t)-1) shl (8-t))));
    end;
   if ls=0 then
    Delete(s, ps, 1)
   else
    begin
     Delete(s, ps+1, (cc-1)*3-1);
     s[ps]:=UnicodeToChar(ls);
     if (s[ps]='?') and (ls<>ord('?')) then
      s[ps]:=#1;
     if s[ps]='%' then
      s[ps]:=#1
     else
      if ord(s[ps])<32 then
       s[ps]:='_';
    end;
  end;
 while Pos(#1, s)<>0 do
  s[Pos(#1, s)]:='%';
end;
//�������� ��������� ������
procedure FormNextStr;
var f:Boolean;
    ls:Word;
procedure InternalProc(k:Boolean);
var p:Longint;
begin
 if o=sz then  //���������� �����?
  begin        //�������� �����
   sz:=RecvBuf(buf, 4096);
   inc(arecv, sz);
   o:=0;       //�������� ��������
  end;
 for p:=o+1 to sz do //������������� �����
  if buf[p]=0 then   //���� ��������� #0 - ����� ������ (����, �� ���� ������ ���� Fatal error � ������)
   begin
    f:=true;
    break;
   end
  else
   begin
    if not (buf[p] in [10, 13]) then  //��������� ������
     begin
      r:=r+chr(buf[p]);
      inc(ls);
     end;
    //�������� �� ����� ������ (#13, #10, #13#10)
    if ((buf[p]=10) and ((p=0) or (buf[p-1]<>13)) and ((p=sz) or (buf[p+1]<>13))) or
       ((buf[p]=13) and ((p=0) or (buf[p-1]<>10)) and ((p=sz) or (buf[p+1]<>10))) or
       ((buf[p]=10) and (p>0) and (buf[p-1]=13)) then
     begin
      f:=true;
      break;
     end;
   end;
 o:=p;  //��������� ��������
 if (not f) and (ls<255) and k then  //������ ���� �����, �� �� ����� ����� ������?
  InternalProc(false);  //���������
end;
begin
 ls:=0;  //����� ������ = 0
 r:='';  //�������� ������
 f:=false; //��� �����
 InternalProc(true);
end;
//������� ����
procedure DeleteList;
begin
 while contr<>nil do
  begin
   curr:=contr^.Next;
   Dispose(contr);
   contr:=curr;
  end;
end;
procedure StrToBuf(s:String);
var l:String;
begin
 l:=s;
 if Length(l)>255 then
  SetLength(l, 255);
 Move(PChar(l)^, rbuf, Length(l)+1);
end;
procedure BufToStr(var s:String);
var k:LongWord;
begin
 k:=0;
 while (rbuf[k]<>#0) and (k<255) do
  inc(k);
 SetString(s, PChar(@rbuf), k);
end;
//��������� �����
procedure ProcessFile;
var Mime:TextFile;
    Resp, cont, rcont, alc, puc:String;
    j, rcl, mr, mc, t, ac, tofs:Longint;
    ms, mp, SCLen:Boolean;
    md:LongWord;
const Req='Request to: ';
      clst='Content-Length: ';
      acrc='Accept-Ranges: ';
      crb='Content-Range: bytes ';
      cnt='Content-Type: ';
      al='Allow: ';
      pu='Public: ';
      bndr='VPSERVERBNDR';
      nl=#13#10;
procedure AddMHead(main:Boolean);
var x:LongWord;
begin
 for x:=1 to md do
  Resp:=Resp+MGetHLine(hmod, x, main)+nl;
end;
begin
 if Err then
  begin
   DeleteList;
   PartOP:=false;
  end;
 //���� �����, �� ��������� ���� �� ���������� �����
 if ppath[Length(ppath)]='\' then
  ppath:=ppath+'index.html';
 PAcc:=false;
 mp:=false;
 md:=0;
 if NPlugInst and (not Err) then
  PAcc:=MQueryProc(hmod, PartOP, OptOP, KAlive, PostOP, PChar(ppath));
 if (ppath[1]<>#13) and (not PAcc) then //��������� �� ����-������
  begin
   Assign(ThreadFl[i], ppath);
   //��������� ��������� ����
{$I-}
   Reset(ThreadFl[i], 1);
{$I+}
   if IOResult<>0 then //�� ����������
    begin
     if DirectoryExists(ppath) then
      ppath:=ppath+'\' //���������� ����� � ��� �� ������
     else
      begin            //��������� 404 File Not Found
       OptOP:=false;
       if Err then
        ppath:=#13     //�� ����� error404.html. ����� ����-������
       else
        begin
         LogMsg(llAll, i, Req+ppath); //��������, ��� ��� ������ �� �����-�� ����
         ppath:=val+'\error404.html'; //� ���� ���� error404.html
        end;
       Err:=true;      //���� ������
      end;
     ProcessFile;      //����������� �����
     Exit;
    end;
  end;
 SCLen:=true;
 if PAcc then
  begin
   StrToBuf(resph);
   md:=MUpdateParamsProc(hmod, PartOP, OptOP, KAlive, SCLen, PChar(@rbuf));
   BufToStr(resph);
  end;
 ac:=0;
 tofs:=-1;
 if PAcc then
  PartOP:=MSetPosProc(hmod, tofs)
 else
  tofs:=FileSize(ThreadFl[i])-1;
 if PartOP and (not Err) and (ppath[1]<>#13) then  //���������� ������
  begin
   if enofs=-1 then
    enofs:=tofs;
   //������������ ������?
   if (stofs<0) or (enofs>tofs) then
    PartOP:=false;  //��������� ������������ Range
   curr:=contr;
   while curr<>nil do
    begin
     //���������� ������
     if (curr^.EndR+2) in [1, 0] then
      begin
       if curr^.EndR=-2 then
        curr^.StartR:=tofs-curr^.StartR+1;
       curr^.EndR:=tofs;
      end;
     if (curr^.StartR>curr^.EndR) or (curr^.StartR<0) then
      PartOP:=false;                       //������������ ������
     curr:=curr^.Next;
     mp:=mp or (curr<>nil);
     inc(ac);
    end;
  end;
 if ((not PartOP) or (ppath[1]=#13)) and (contr<>nil) then       //������
  begin
   if ppath[1]<>#13 then
    begin
     LogMsg(llAll, i, Req+ppath);
     Close(ThreadFl[i]);
    end;
   resph:='416 Requested Range Not Satisfiable';
   Err:=true;
   ppath:=val+'\error416.html';
   ProcessFile;
   Exit;
  end;
 //�������� ������� ���������
 if resph='' then  //��� ��� ����������?
  if Err then      //� ���� ������?
   resph:='404 Not Found' //�� - ���� �� ������
  else
   if ppath[1]=#13 then   //������ �� ����, � ���������� ����?
    resph:='204 No Content' //���������� ����-������ - ������ �� ����������
   else
    begin
     if PartOP then //������������ Content-Range?
      resph:='206 Partial Content' //��
     else
      resph:='200 OK'; //������ ����
     LogMsg(llAll, i, Req+ppath); //��� ������ �� �����-�� ����
    end;
 //��������� �����
 Resp:=HttpV+' '+resph; //HTTP/1.X XXX XXXXXXX
 LogMsg(llNotice, i, 'Response: '+Resp); //�� �������� ��� ���
 Resp:=Resp+nl+'Date: '+GetFormatedTime+nl+'Server: '+SERV+nl; //���������� � ������� (ID � ����)
 rcont:='';
 //������� � ���, ��� ������������ ������?
 alc:='GET, POST, HEAD, OPTIONS';
 puc:=alc+', PUT, PATCH, DELETE, TRACE, CONNECT, LINK, UNLINK';
 if PAcc then
  begin
   StrToBuf(alc);
   MGetSMeth(hmod, 1, PChar(@rbuf));
   BufToStr(alc);
   StrToBuf(puc);
   MGetSMeth(hmod, 2, PChar(@rbuf));
   BufToStr(puc);
  end;
 if OptOP then
  Resp:=Resp+al+alc+nl+pu+puc+nl;
 if (ppath[1]<>#13) or PAcc then
  begin
   //���������� ����
   r:='';
   rcl:=tofs+1; //������ �����������
   if not Err then
    if not PAcc then
     begin //�������� ������ � ����� � ���� ����������� ������������� Range
      Resp:=Resp+'Last-Modified: '+FormatSysTime(FileLastWriteDate(ppath))+nl;
      Resp:=Resp+acrc+'bytes'+nl;
     end
    else
   else //������������ Range ������
    Resp:=Resp+acrc+'none'+nl;
   if PartOP then //���� ���������� Range
    if not mp then
     begin
      rcl:=contr^.EndR-contr^.StartR+1;
      Resp:=Resp+crb+IntToStr(contr^.StartR)+'-'+IntToStr(contr^.EndR)+'/'+IntToStr(tofs+1)+nl;
     end
    else
   else
    if rcl>0 then
     begin //�� ���������� Range
      new(contr); //������ �������� Range
      contr^.StartR:=0;
      contr^.EndR:=rcl-1;
      contr^.Next:=nil;
      inc(ac);
     end;
   if OptOP then
    rcl:=0;
   if not PAcc then
    begin
     //�������� ���������� (�� �� ��������� �����)
     for j:=Length(ppath) downto 1 do
      if ppath[j] in ['.', '\'] then
       break
      else
       r:=ppath[j]+r;
     if ppath[j]='.' then //���� ��������� �� �����
      begin
       Assign(Mime, 'mime.types');  //��������� ���� � mime
{$I-}
       Reset(Mime);
{$I+}
       if IOResult=0 then
        begin
         while not Eof(Mime) do
          begin  //���� ���� ����������
           readln(Mime, val);
           if copy(val, 1, Pos(' ', val)-1)<>r then
            continue;
           rcont:=copy(val, Pos(' ', val)+1, Length(val)-Pos(' ', val));
           break;
          end;
         Close(Mime);
        end;
      end;
    end;
   if not (mp or SCLen) then
    begin
     Resp:=Resp+clst+IntToStr(rcl)+nl;
     if rcont<>'' then //����� - ����������
      Resp:=Resp+cnt+rcont+nl;
    end;
  end
 else
  if Err then
   Resp:=Resp+clst+'0'+nl; //���� ���� ����-������, �� ����� = 0
 if mp then
  begin
   Resp:=Resp+cnt+'multipart/byteranges; boundary='+bndr+nl;
   curr:=nil;
   repeat
    new(lr);
    lr^.StartR:=-1;
    lr^.EndR:=-2;
    inc(ac);
    if curr=nil then
     begin
      lr^.Next:=contr;
      curr:=contr;
      contr:=lr;
     end
    else
     begin
      lr^.Next:=curr^.Next;
      curr^.Next:=lr;
      curr:=lr^.Next;
     end;
   until curr^.Next=nil;
  end
 else
  if PAcc then
   AddMHead(true);
 if KAlive then
  cont:='Keep-Alive'
 else
  cont:='close';
 Resp:=Resp+'Connection: '+cont+nl+nl;
 //���������� �����
 LogMsg(llAll, i, 'Sending response...');
 o:=0;
 if HeadOP or (OptOP and (not Err)) then //�� ���������� ���� ��� HEAD � OPTIONS
  ac:=0;
 New(curr);          //������ ������ ��� �������� ���������
 curr^.Next:=contr;
 curr^.StartR:=-1;
 curr^.EndR:=-1;
 contr:=curr;
 inc(ac);
 Err:=false;
 while ac>0 do
  begin //���������� �� ������
   ms:=(curr^.StartR=-1) and (curr^.EndR<0);
   if (curr^.EndR=-2) then
    begin
     Resp:='--'+bndr+nl+crb+IntToStr(curr^.Next^.StartR)+'-'+IntToStr(curr^.Next^.EndR)+'/'+IntToStr(tofs+1)+nl;
     if rcont<>'' then
      Resp:=Resp+cnt+rcont+nl;
     if PAcc then
      AddMHead(false);
     Resp:=Resp+nl;
    end;
   dec(ac);
   if ms then   //���������
    begin
     mr:=1;
     mc:=Length(Resp);
    end
   else         //����
    begin
     if PAcc then
      Err:=MSetPosProc(hmod, curr^.StartR)
     else
      Seek(ThreadFl[i], curr^.StartR); //������� �� ������
     mr:=curr^.StartR;
     mc:=curr^.EndR;
    end;
   while (mc>=mr) and (not Err) do
    begin
     j:=4096-o; //���������� ������������ ������
     sz:=mc-mr+1; //���������� ������ ������
     if sz<j then //���� ��� ����� ������, �� �� ����� ������
      j:=sz;
     if j>0 then
      if ms then       //�������� ��������� � �����
//       for t:=mr to j+mr do
//        buf[o+t]:=ord(Resp[t])
       move(Resp[mr], buf[o+mr], j)
      else
       begin           //������ ���� � �����
        if PAcc then
         MReadProc(hmod, buf[o+1], j, t)
        else
         BlockRead(ThreadFl[i], buf[o+1], j, t);
        if t<j then
         begin
          Err:=true;
          break;
         end;
       end;
     inc(mr, j);
     if ((j+o)<4096) and (ac>0) then
      begin //�� ��������� �����. ���� �����������
       inc(o, j);
       continue;
      end;
     if SendBuf(buf, j+o)<>(j+o) then
      begin //�������� ����������
       Err:=true;
       break;
      end;
     inc(asent, j);
     inc(asent, o);
     o:=0;
    end;
   if Err then
    break; //� ��� ���� ���� ��������� ����
   curr:=curr^.Next;
  end;
 DeleteList;
 if ppath[1]<>#13 then
  Close(ThreadFl[i]); //��������� ����
 LogMsg(llNotice, i, 'OK. Result flag: '+IntToStr(ord(Err)*10+ord(FErr))); //�������� ������ �����/������
end;
//������ ������
procedure BReq;
begin
 HttpV:='HTTP/1.1';
 resph:='400 Bad Request';
 ppath:=#13'error400.html';
end;
//��������� ������ GET
procedure GetOP;
var hn:String;
    IsHost:Boolean;
//��������� ������
procedure SetHost(val:String);
begin
 if IsHost then
  Exit; //��� ���� ���������� ���� ������. BUG VPSERVER 1.0
 ppath:=val+ppath;
 IsHost:=true;
 LogMsg(llNotice, i, 'Host: '+val);
end;
label h, f; //�������� ������������ ����� (����� �� ������������ ���� ���)
var p:Pointer;
    ps, tr:Longint;
begin
 if NPlugInst and (copy(ppath, 1, 1)<>#13) then
  begin        
   StrToBuf(ppath);
   MLoadGetProc(hmod, PChar(@rbuf));
   BufToStr(ppath);
  end;
 if Pos('?', ppath)<>0 then
  ppath:=copy(ppath, 1, Pos('?', ppath)-1); //��� GET-��������� �� �����
 if Pos('#', ppath)<>0 then
  ppath:=copy(ppath, 1, Pos('#', ppath)-1); //��� � �������� �� ����� ����, �� ���������� ��� ������
 ReformStr(ppath); //BUG ALL VPSERVER - ��������� %xy
 IsHost:=false;
 if Pos('://', ppath)<>0 then //��������� ����������� URL
  begin
   LogMsg(llNotice, i, 'Warning! Absolute URL!');
   Delete(ppath, 1, Pos('://', ppath)+3);
   val:=copy(ppath, 1, Pos('/', ppath)-1);
   Delete(ppath, 1, Pos('/', ppath));
   goto h; //���������� ����
  end;
 while true do
  begin
   FormNextStr; //�������� ��������� ������
   if r='' then
    break;      //EOF
   hn:=copy(r, 1, Pos(':', r)-1); //��������
   val:=copy(r, Pos(':', r)+2, Length(r)-Pos(':', r)-1); //��������
   ReformStr(val); //BUG ALL VPSERVER - ��������� %xy
   PAcc:=false;
   if NPlugInst then
    begin     
     StrToBuf(val);
     PAcc:=MHeadProc(hmod, PChar(hn), PChar(@rbuf));
     BufToStr(val);
    end;
   if hn='Host' then
    begin  //�������� ����
h:   if ppath[1]=#13 then
      continue; //���� ������
     if Pos(':', val)<>0 then
      val:=copy(val, 1, Pos(':', val)-1); //������ ����. ��� �� �� �����
     DelStr(val, '\', 1);
     DelStr(val, '/', 1);
     //��� IP?
     if inet_addr(PChar(val))<>-1 then
      val:='localhost'; //��������� �� default-����
     SetHost(val); //���������� ����
     continue;
    end;
   if hn='User-Agent' then
    begin //�������� ��� ������
     LogMsg(llAll, i, 'User agent: '+val);
     continue;
    end;
   if hn='Referer' then
    begin //�������� ������ �������
     LogMsg(llAll, i, 'Referer: '+val);
     continue;
    end;
   if hn='From' then
    begin //�������� e-mail
     LogMsg(llAll, i, 'From: '+val);
     continue;
    end;
   if hn='Range' then
    begin //���������� Range
     if copy(val, 1, 6)<>'bytes=' then
      continue; //����� bytes �� ������ �� ������������
     //������� ������
     Delete(val, 1, 6);
     DelStr(val, ' ', 1);
     DeleteList;
     //������� �������
     new(curr);
     curr^.StartR:=-1;
     contr:=curr;
     lr:=nil;
     while val<>'' do
      begin
       //�������� ���������
       if Pos(',', val)<>0 then
        hn:=copy(val, 1, Pos(',', val)-1)
       else
        hn:=val;
       //������� � �� ��������
       Delete(val, 1, Length(hn));
       if Length(val)<>0 then
        Delete(val, 1, 1); //������� �������
       tr:=Pos('-', hn);
       if tr=0 then
        break;
       if Pos('/', hn)<>0 then
        break;
       if tr=1 then
        begin
         curr^.EndR:=-2;
         Delete(hn, 1, 1);
         curr^.StartR:=abs(StrToInt(hn));
        end
       else
        begin
         curr^.StartR:=abs(StrToInt(copy(hn, 1, tr-1)));
         if tr=Length(hn) then
          curr^.EndR:=-1
         else
          curr^.EndR:=abs(StrToInt(copy(hn, tr+1, Length(hn)-tr)));
        end;
       lr:=curr;
       new(curr);
       lr^.Next:=curr;  //��������� �������
      end;
     //������� ������ �������
     Dispose(curr);
     if lr<>nil then
      lr^.Next:=nil
     else
      contr:=nil;
     //���������, � ������ ������� ������ � �����
     lr:=nil;
     curr:=contr;
     stofs:=-1;
     enofs:=-1;
     while curr<>nil do
      if curr^.StartR=-1 then  //������ �������
       if lr=nil then //� ������?
        begin
         contr:=curr^.Next;
         Dispose(curr);
         curr:=contr;
        end
       else
        begin //���?
         lr^.Next:=curr^.Next;
         Dispose(curr);
         curr:=lr^.Next;
        end
      else
       begin
        if (curr^.StartR<stofs) or (stofs=-1) then
         stofs:=curr^.StartR; //��������� ������
        if curr^.EndR>enofs then
         enofs:=curr^.EndR; //��������� �����
        lr:=curr;
        curr:=lr^.Next; //��������� �������
       end;
     if stofs<>-1 then //���� ������?
      PartOP:=true; //�������� Range
     continue;
    end;
   if hn='Connection' then
    begin  //������������� ����� �����������
     if Pos('Keep-Alive', val)=1 then //���� Keep-Alive
      KAlive:=true
     else
      if Pos('close', val)=1 then //���� close
       KAlive:=false;
     if (val<>'close') and (val<>'Keep-Alive') then //���������� ���
      LogMsg(llAll, i, 'FIXME: "Connection: '+val+'" Not supported connection mode');
     continue;
    end;
   if hn='Content-Length' then
    begin //��� ������ POST
     if PostOP or OptOP or PAcc then  //����� POST/OPTIONS?
      begin  //�� - ������������� �����
       PostCL:=StrToInt(val);
       continue;
      end;
     //������
     LogMsg(llNotice, i, 'Warning! Unexpected header! 400 Bad Request for safe end');
     ppath:=#13#10;
    end;
   if Pos('Accept', hn)=1 then
    continue; //���������� ��� Accept-XXXX
   //����������� ���������
   if not PAcc then
    LogMsg(llAll, i, 'FIXME: "'+hn+': '+val+'" Header has been ignored');
  end;
 if FErr then //������ IO
  begin
f: if GetLastError=0 then //�� ���� ������ - �������� ����� ��������
    LogMsg(llError, i, rtout);
   Exit;
  end;
 if ppath='' then //����� ������ �� ������ 1
  ppath:='.';
 IsHost:=IsHost or (ppath[1]=#13);
 if (not IsHost) and (HttpV<>'HTTP/1.1') then //�������� Host ���������� ������ ��� HTTP1.1
  SetHost('localhost');
 //������ ���� �� ���������� ����, ���������� ��������� ��� POST, ���������� ��������� ��� POST
 if (not IsHost) or (PostOP and (PostCL=-1)) or (ppath=#13#10) then
  BReq;
 //�������� ��������?
 if ppath[1]<>#13 then
  begin //��
   while Pos('/', ppath)<>0 do     //�������� / �� \
    ppath[Pos('/', ppath)]:='\';
   DelStr(ppath, '\\', 1);         //�������� \\ �� \
   if ppath[1]<>'\' then           //�� �����
    ppath:='\'+ppath;
   DelStr(ppath, '*', 1);          //������� RegEx
   DelStr(ppath, '?', 1);
   while ppath[Length(ppath)]='.' do  //�������� '.' Thanks to Genix
    Delete(ppath, Length(ppath), 1);
   DelStr(ppath, '\..\', 3);       //�� �����
  end
 else
  begin //���� ����-�����
   PostOP:=false;                  //�� ������������ POST
   Err:=not Err;                   //������������ ����������
   Delete(ppath, 1, 1); //������� ����-������
   if ppath[1]<>#13 then
    ppath:='\'+ppath; //��������� \
  end;
 if PostCL<>-1 then
  begin //����� POST/OPTIONS
   if o<sz then         //������ ����
    dec(PostCL, sz-o);
   o:=sz;
   while PostCL>0 do
    begin
     ps:=4096;
     if ps>PostCL then
      ps:=PostCL;
     GetMem(p, ps);
     RecvBuf(p^, ps);
     if NPlugInst then
      MLoadPostProc(hmod, p^, ps);
     FreeMem(p);
     dec(PostCL, ps);
    end;
   o:=o+PostCL;
  end;
 //���� ������ ������� ��� 400 Bad Request, �� ������ ���������� ��������
 if (Err and ((copy(resph, 1, 1)='5') or (copy(resph, 1, 3)='400'))) or FErr then
  begin
   LogMsg(llAll, i, 'Set connection mode to "close"');
   KAlive:=false;
  end;
 if FErr then
  goto f;
 GetDir(0, val); //� val ���� Home �����
 if ppath[1]<>#13 then
  ppath:=val+ppath; //�� �� Home
 ProcessFile; //��������� �����
end;
//��������� �������
procedure ProcessRequest;
var meth:String;
const GetMeth='GET';
//������� ���� � �����
procedure FindPath;
begin
 ppath:=copy(r, Pos(' ', r)+1, Length(r)-Pos(' ', r)-9);
end;
begin
 //������������� (��������� ����������)
 if UKAlive then
  LogMsg(llNotice, i, 'Keep-Alive mode! Waiting...');
 resph:='';
 sz:=0;
 o:=0;
 stofs:=0;
 FErr:=false;
 FormNextStr; //��������� �������
 if FErr then
  begin
   if GetLastError=0 then  //�� ���� ������ - �������� ����� ��������
    if UKAlive then
     LogMsg(llNotice, i, 'Keep-Alive timeout')
    else
     LogMsg(llNotice, i, rtout);
   Exit;
  end;
 LogMsg(llAll, i, 'Processing request');
 UKAlive:=false;
 meth:=r;
 while Pos(' ', meth)<>0 do //���� �������
  begin
   Delete(meth, Pos(' ', meth), 1);
   inc(stofs);
  end;
 if meth='' then //������ ������?
  begin
   LogMsg(llNotice, i, 'Request is empty');
   Exit;
  end;
 LogMsg(llNotice, i, 'Request: '+r);
 //������ HTTP
 HttpV:=copy(r, Length(r)-7, 8);
 HeadOP:=false;
 PartOP:=false;
 PostOP:=false;
 PostCL:=-1;
 OptOP:=false;
 Err:=false;
 if stofs<>2 then
  begin
   BReq;
   meth:='';
  end
 else
  meth:=copy(r, 1, Pos(' ', r)-1);
 if (HttpV<>'HTTP/0.9') and (HttpV<>'HTTP/1.0') and (HttpV<>'HTTP/1.1') then //�������� ������ HTTP
  begin //�������� �� ����
   HttpV:='HTTP/1.1';
   resph:='505 HTTP Version Not Supported';
   ppath:=#13'error505.html';
   meth:=GetMeth;
  end;
 if (resph='') and NPlugInst then
  MLoadMeth(hmod, PChar(meth));
 if meth='HEAD' then //����� HEAD. ������ �� ���������� �����������
  begin
   HeadOP:=true;
   meth:=GetMeth;
  end;
 if meth='POST' then //����� POST
  begin
   PostOP:=true;
   meth:=GetMeth;
  end;
 if (meth=GetMeth) and (resph='') then //����� GET - ����� ����
  FindPath;
 if (meth='PUT') or (meth='PATCH') or (meth='DELETE') or (meth='TRACE') or (meth='CONNECT') or (meth='LINK') or (meth='UNLINK') then
  begin //������ �����������!
   resph:='405 Method Not Allowed';
   ppath:=#13'error405.html';
   meth:=GetMeth;
   OptOP:=true;
  end;
 if meth='OPTIONS' then
  begin //����� ������ ��������, ��� �� �����
   FindPath;
   if Pos('*', ppath)<>0 then
    begin
     ppath:=#13#13;
     Err:=true;
    end;
   meth:=GetMeth;
   OptOP:=true;
  end;
 //���� �������� ����� �� GET
 if stofs<>2 then
  meth:=GetMeth;
 PAcc:=meth=GetMeth;
 if (not PAcc) and NPlugInst then
  PAcc:=MMethProc(hmod, PChar(meth));
 if not PAcc then //��� �� GET?
  begin //� ������ ������ �� ����
   resph:='501 Not Implemented';
   ppath:=#13'error501.html';
   OptOP:=true;
  end
 else
  if NPlugInst then
   FindPath;
 contr:=nil;
 GetOP; //��������� ������
end;
var le:LongWord;
//������ ������
begin
 Result:=0; //�� ��������� Return = 0
 i:=Index^; //��� �����
 Dispose(Index);
 try
  LogMsg(llAll, i, 'Listening...');
  wholen:=sizeof(sockaddr_in);
  ThreadSock[i]:=accept(ListenSocket, @who, @wholen); //���...
  if wholen<>sizeof(sockaddr_in) then //������ � WS2_32.DLL
   begin
    LogMsg(llError, i, 'Internal error!');
    MyQuit(1);
   end;
  LogMsg(llNotice, i, 'The client is accepted ('+IntToStr(ThreadSock[i])+') from '+inet_ntoa(who.sin_addr));
  ThreadBusy[i]:=true; //�� ������
  CheckThreads(i); //� ���� ���������?
  if SMode then
   begin
    sz:=0;
    o:=0;
    LogMsg(llNotice, i, 'Warning! S mode is activated!');
    repeat
     FormNextStr;
     LogMsg(llNotice, i, r);
    until r='';
   end
  else
   begin
    UKAlive:=false;
    asent:=0;
    arecv:=0;
    repeat
     KAlive:=false;
     if PlugInst then
      NPlugInst:=MInitProc(hmod);
     ProcessRequest; //��������� �������
     if NPlugInst then
      MRelProc(hmod);
     UKAlive:=true;
    until not KAlive;
   end;
  le:=GetLastError;
  LogMsg(llAll, i, 'Sent: '+IntToStr(asent)+' bytes; received: '+IntToStr(arecv)+' bytes'); //����������
  LogMsg(llAll, i, 'Closing socket '+IntToStr(ThreadSock[i]));
  if closesocket(ThreadSock[i])=SOCKET_ERROR then //��������� �����
   LogMsg(llError, i, 'Error '+IntToStr(WSAGetLastError)+': '+SysErrorMessage(WSAGetLastError));
  SetLastError(le); //��������� ������
  ThreadSock[i]:=0;
  CheckThreads(i); //��������� �� ��������� ������
 finally
  if GetLastError<>0 then //���� ������?
   LogMsg(llError, i, 'Raised exception! Error '+IntToStr(GetLastError)+': '+SysErrorMessage(GetLastError));
{$I-}
  Close(ThreadFl[i]); //�� �� ������� ����?
{$I+}
  if IOResult=0 then
   LogMsg(llNotice, i, fhsbc); //� ������ �� �������
  //��� ���
  LogMsg(llNotice, i, 'Terminating');
  InterlockedDecrement(PInteger(@ThreadBe[i])^);
  InterlockedDecrement(ThreadCount);
 end;
end;

//��������� ��� ������
procedure TerminateAllThreads(s:Integer);
var i:Integer;
    e:LongWord;
begin
 while true do
  begin
   //���...
   WaitForSingleObject(TerminateAllThreadsLockE, INFINITE);
   if InterlockedIncrement(TerminateAllThreadsLock)=1 then
    break;
   //�� ���� �������
   InterlockedDecrement(TerminateAllThreadsLock);
  end;
 //����� ��� ����
 if not ResetEvent(TerminateAllThreadsLockE) then
  Panic;
 e:=0;
 for i:=1 to MAX_L do
  if ThreadBe[i] and (ThreadID[i]<>GetCurrentThreadID) then
   begin //���� �� ���������
    if (e<>GetLastError) and (GetLastError<>0) then
     e:=GetLastError; //� e ��������� ������
    //������� ������������ �����
    if SuspendThread(ThreadHnd[i])=INFINITE then
     begin
      LogMsg(llError, s, 'Thread '+IntToStr(i)+' has not been suspended. Error '+IntToStr(GetLastError)+'! '+SysErrorMessage(GetLastError));
      continue;
     end;
    if LogMsgLockT=ThreadID[i] then
     begin
      LogMsgLockT:=0;
      if not SetEvent(LogMsgLockE) then
       Panic;
      InterlockedDecrement(LogMsgLock);
     end;
    if CheckThreadsLockT=ThreadID[i] then
     begin
      CheckThreadsLockT:=0;
      InterlockedDecrement(CheckThreadsLock);
     end;
    LogMsg(llAll, s, 'Thread '+IntToStr(i)+' has been suspended');
{$I-}
    Close(ThreadFl[i]); //�� �� ����� ������� ����?
{$I+}
    if IOResult=0 then
     LogMsg(llAll, s, fhsbc); //�� ��� �������
    if ThreadSock[i]<>0 then //�� �� ������ �����
     if (closesocket(ThreadSock[i])=SOCKET_ERROR) and (not CloseHandle(ThreadSock[i])) then
      LogMsg(llError, s, 'Can''t close socket! Error '+IntToStr(WSAGetLastError)+': '+SysErrorMessage(WSAGetLastError))
     else
      LogMsg(llAll, s, 'Socket of thread '+IntToStr(i)+' has been closed');
    if not (TerminateThread(ThreadHnd[i], INFINITE) or CloseHandle(ThreadHnd[i])) then
     begin //�� ���������� ���������? ����� ������ �����
      LogMsg(llError, s, 'Can''t terminate thread! Error '+IntToStr(GetLastError)+': '+SysErrorMessage(GetLastError));
      continue;
     end;
    //������ ��� ���
    LogMsg(llNotice, s, 'Thread '+IntToStr(i)+' has been terminated');
    InterlockedDecrement(PInteger(@ThreadBe[i])^);
    InterlockedDecrement(ThreadCount);
   end;
 //����� ���� ������?
 if e<>0 then
  SetLastError(e);
 //���������!
 if not SetEvent(TerminateAllThreadsLockE) then
  Panic;
 TerminateAllThreadsLock:=0;
end;

//������� ����� �����
procedure CreateThreadListener(f:Integer);
procedure InternalProc(c:Integer);
var i, j:Integer;
    p:^Integer;
const s=-2;
begin
 //���� ��������� �����
 i:=-1;
 for j:=1 to MAX_L do
  if not ThreadBe[j] then
   begin
    i:=j;
    break;
   end;
 if i=-1 then
  begin //�� �����
   if c=5000 then
    begin //��� 5 ����� ���
     LogMsg(llError, s, 'Request has not been processed for 5 seconds! Terminating threads!');
     TerminateAllThreads(s); //�������� �� ��...
     Exit;
    end;
   //���� ���...
   if c=0 then
    LogMsg(llError, s, 'Number of threads exceeds the limit. Check your computer to a network attack');
   LogMsg(llAll, s, 'Waiting for a second...');
   Sleep(1000);
   LogMsg(llAll, s, 'Trying again');
   InternalProc(c+1000); //����� �������
   Exit;
  end;
 //������ ����� �����
 LogMsg(llNotice, s, 'Starting new thread (number '+IntToStr(i)+')');
 //������������ ���
 new(p);
 p^:=i;
 InterlockedIncrement(ThreadCount);
 j:=InterlockedIncrement(PInteger(@ThreadBe[i])^) and $FF;
 ThreadBusy[i]:=false;
 ThreadHnd[i]:=BeginThread(nil, 0, @ThreadProc, p, 4, ThreadID[i]);
 if (ThreadHnd[i]<>0) and (j=1) then
  begin //��������� �����
   ThreadSock[i]:=0;
   LogMsg(llAll, s, 'Resuming thread '+IntToStr(i));
   if ResumeThread(ThreadHnd[i])<>INFINITE then
    Exit;
  end;
 //���� ������. ���������� �� �������
 InterlockedDecrement(PInteger(@ThreadBe[i])^);
 InterlockedDecrement(ThreadCount);
 LogMsg(llError, s, 'Error '+IntToStr(GetLastError)+'! '+SysErrorMessage(GetLastError));
 if ThreadHnd[i]<>0 then
  begin //���� ��� ���������
   LogMsg(llError, s, 'Terminating thread '+IntToStr(i));
   if not (TerminateThread(ThreadHnd[i], 255) or CloseHandle(ThreadHnd[i])) then
    begin
     LogMsg(llError, s, 'Error '+IntToStr(GetLastError)+': '+SysErrorMessage(GetLastError));
     MyQuit(GetLastError);
    end;
  end;
end;
begin
 InternalProc(0);
end;

{=======�������� ���������=======}

//����� � �����
function MIntToStr(i:Integer):String;
begin
 if i>9 then
  Result:=IntToStr(i)
 else
  Result:='0'+IntToStr(i);
end;

//������������� ��������� �����
function FormatSysTime(t:TSystemTime):String;
const dow:array[0..6] of String = ('Sun', 'Mon', 'Tus', 'Wed', 'Thu', 'Fri', 'Sat');
const mon:array[1..12] of String = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
//������ �� RFC2068
begin
 Result:=dow[t.wDayOfWeek]+', '+IntToStr(t.wDay)+' '+mon[t.wMonth]+' '+
         IntToStr(t.wYear)+' '+MIntToStr(t.wHour)+':'+MIntToStr(t.wMinute)+':'+
         MIntToStr(t.wSecond)+' GMT';
end;

var t:TSystemTime;
    tlock:Integer=0;

//�������� ��������� �����
procedure GetSystemTime_;
begin
 if InterlockedIncrement(tlock)=1 then
  GetSystemTime(t);
 InterlockedDecrement(tlock);
end;

//�������� ���� � �����
function GetCurDateTime:String;
//������ �� ������
begin
 GetSystemTime_;
 Result:=MIntToStr(t.wDay)+'.'+MIntToStr(t.wMonth)+'.'+IntToStr(t.wYear)+' '+
         MIntToStr(t.wHour)+':'+MIntToStr(t.wMinute)+':'+MIntToStr(t.wSecond);
end;

//��������� ���
procedure OpenLog(var F:Text;path:String);
begin
 Assign(F, path);
{$I-}
 Append(F);
{$I+}
 if IOResult<>0 then
  begin //����� �� ����������?
{$I-}
   Rewrite(F);
{$I+}
   if IOResult<>0 then
    begin //�� ���� �������
     writeln('Fatal error! Can''t open log "'+path+'"! Error ', GetLastError, ': '+SysErrorMessage(GetLastError));
     MyHalt(GetLastError);
    end;
  end;
end;

var i:Integer;
    c:Integer=-1;
    F, SysLog:Text;
    cll, fll:LogLev;
    flpath, s:String;
    SHOWCON:Integer;
    consolev:Boolean=true;

//������
procedure Panic_;
var j:Integer;
begin
 for j:=1 to MAX_L do
  if ThreadBe[j] then
   if SuspendThread(ThreadHnd[j])=INFINITE then
    writeln('Panic: Error ', GetLastError, ': '+SysErrorMessage(GetLastError));
 writeln(#13'Kernel panic?');
 SHOWCON:=0;
 CheckThreadsLock:=0;
 CheckThreadsLockT:=0;
 LogMsgLock:=0;
 SetEvent(LogMsgLockE);
 LogMsgLockT:=0;
 TerminateAllThreadsLock:=0;
 SetEvent(TerminateAllThreadsLockE);
 TerminateAllThreads(SYS);
end;

//�������� ��� ����� �� ������ ������
function FormLogFile(i:Integer):String;
begin
 Result:=flpath+'\Thread'+IntToStr(i)+'.log';
end;

//�������� ��������������� �����
function GetFormatedTime:String;
begin
 GetSystemTime_;
 Result:=FormatSysTime(t);
end;

//�������� � ���
procedure LogMsg(lev:LogLev;from:Integer;msg:String);
var fromstr, logstr:String;
begin
 //���������� �� ���� �� ��������, ��� � � TerminateAllThreads
 while true do
  begin
   WaitForSingleObject(LogMsgLockE, INFINITE);
   if InterlockedIncrement(LogMsgLock)=1 then
    break;
   InterlockedDecrement(LogMsgLock);
  end;
 if not ResetEvent(LogMsgLockE) then
  Panic;
 LogMsgLockT:=GetCurrentThreadId;
 case from of //������ ���������?
  -1: fromstr:='SYSTEM';
  -2: fromstr:='CreateThreadListener';
 else
  fromstr:='Thread '+IntToStr(from);
 end;
 if ord(lev)>=ord(fll) then //�������� � ����
  begin
   logstr:=' -- '+GetCurDateTime+' '+fromstr+': '+msg;
   writeln(F, logstr); //����� ���
   if from>0 then
    writeln(ThreadLog[from], logstr) //��� ������
   else
    writeln(SysLog, logstr); //��� �������
  end;
 if consolev then
  if ord(lev)>=ord(cll) then
   begin
    msg:=msg+#13#10;
    if InterlockedIncrement(SHOWCON)<>1 then
     msg:=msg+'>';
    InterlockedDecrement(SHOWCON);
    write(#13+fromstr+': '+msg); //�� �����
   end;
 LogMsgLockT:=0;
 if not SetEvent(LogMsgLockE) then
  Panic;
 asm
  push OFFSET LogMsgLock
  call InterlockedDecrement
 end;
// InterlockedDecrement(LogMsgLock);
end;

//��������
procedure MyWait;
const WAIT='Waiting...';
begin
 write(WAIT); //�������
 Sleep(4500); //���
 write(#13, ' ':Length(WAIT), #13); //�������
 Sleep(500);  //��������
 writeln;
end;

var LEP:Pointer;

//���������� �����
procedure MyExit(ReturnCode:Integer);
var k:Integer;
    le:LongWord;
begin
 le:=GetLastError;
 TerminateAllThreads(SYS); //��������� ������
 LogMsg(llError, SYS, 'Exit code: '+IntToStr(ReturnCode));
 LogMsg(llError, SYS, 'Error code: '+IntToStr(le));
 //��������� ����
 Close(F);
 Close(SysLog);
 for k:=1 to MAX_L do
  Close(ThreadLog[k]);
 //��������� �����
 closesocket(ListenSocket);
 MyWait;
 ExitProc:=LEP;
end;

//����������� ����������
procedure WExit;
begin
 Panic_;
 LogMsg(llError, SYS, 'Fatal error at: '+IntToStr(LongWord(ErrorAddr)));
 MyExit(ExitCode);
end;

//���������� �����
procedure MyQuit(ReturnCode:Integer);
begin
 //����� �� ������
 LogMsg(llError, SYS, 'DoHalt command!');
 MyExit(ReturnCode);
 Halt(ReturnCode);
end;

//��������� �����
procedure MyHalt(ReturnCode:Integer);
begin
 //���� �� ������ �����������
 MyWait;
 Halt(ReturnCode);
end;

//�������� ����
procedure ShowLogo;
//������� �������
procedure ShowSpace;
begin
 write(' ':(((80-Length(SERV)-2) div 2)-1));
end;
//������� ><
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
 ShowSubLogo;
 ShowSpace;
 write('>'+SERV+'<'); //������� ��������
 writeln;
 ShowSubLogo;
end;

var Data:WSADATA;        //������ � WS2_32.DLL
    Port:Word;           //����
    service:sockaddr_in; //����� ������

const
 rset:array[1..7] of String=('Port=', 'IP=',  'ListenersAmount=', 'ConsoleLogLevel=', 'FileLogLevel=', 'Keep-Alive-Timeout=', 'Read-Timeout=');

//�������� ����� ���������
procedure WriteNewConf;
var rans:array[1..7] of String;
    n:Byte;
//��������� � ����������
procedure PromptConf;
begin
 //Port
 rans[1]:='X';
 while StrToInt(rans[1])<>Port do
  begin
   write('Port: ');
   readln(rans[1]);
   Port:=StrToInt(rans[1]);
  end;
 //IP
 write('IP: ');
 readln(rans[2]);
 flpath:=rans[2];
 //Listeners amount
 c:=-1;
 while (c<0) or (c>MAX_L) do
  begin
   write('Listeners Amount: ');
   readln(rans[3]);
   c:=StrToInt(rans[3]);
  end;
 //WLogLevel
 i:=-1;
 writeln('0=ALL, 1=NOTICE, 2=ERROR');
 while not (i in [ord(llAll), ord(llNotice), ord(llError)]) do
  begin
   write('Level of logging in window: ');
   readln(rans[4]);
   i:=StrToInt(rans[4]);
  end;
 cll:=LogLev(i);
 //FLogLevel
 i:=-1;
 while not (i in [ord(llAll), ord(llNotice), ord(llError)]) do
  begin
   write('Level of logging in file: ');
   readln(rans[5]);
   i:=StrToInt(rans[5]);
  end;
 fll:=LogLev(i);
 write('Keep-Alive timeout: ');
 readln(rans[6]);
 KTimeOut:=StrToInt(rans[6]);
 rans[6]:=IntToStr(KTimeOut);
 write('Read timeout: ');
 readln(rans[7]);
 BTimeOut:=StrToInt(rans[7]);
 rans[7]:=IntToStr(BTimeOut);
end;
begin
 writeln('Writing new config file...');
 //��� ��������� �� default
 rans[1]:=IntToStr(Port);
 rans[2]:=flpath;
 rans[3]:=IntToStr(c);
 rans[4]:=IntToStr(ord(cll));
 rans[5]:=IntToStr(ord(fll));
 rans[6]:=IntToStr(KTimeOut);
 rans[7]:=IntToStr(BTimeOut);
{$I-}
 Rewrite(F);
{$I+}
 if IOResult<>0 then
  begin //�� ���� �������� ������? ������ ������
   writeln('Can''t write config file');
   PromptConf;
   Exit;
  end;
 //����� �� �� default?
 write('Recomended settings: ');
 for n:=1 to 7 do
  begin
   write(rset[n], rans[n]);
   if n<>7 then
    write('; ')
   else
    writeln;
  end;
 repeat
  write('Accept? [Y/n] ');
  readln(flpath);
 until Length(flpath)>0;
 if (UpCase(flpath[1])='N') and (Length(flpath)=1) then
  PromptConf //������
 else
  flpath:=rans[2];
 for n:=1 to 7 do
  writeln(F, rset[n], rans[n]); //�����
 Close(F); //OK
end;

//������ �������
procedure ReadConf;
var mt:String;
    n:Byte;
    ln, tp:Longint;
    m:LongWord;
begin
 writeln('Reading config file...');
 ln:=0;
 while not Eof(F) do
  begin
   inc(ln);
   readln(F, mt); //�������� ������
   //������� ������ �������
   if Pos(';', mt)<>0 then
    mt:=copy(mt, 1, Pos(';', mt)-1);
   DelStr(mt, '  ', 1);
   while (Length(mt)>0) and (mt[1]=' ') do
    Delete(mt, 1, 1);
   while (Length(mt)>0) and (mt[Length(mt)]=' ') do
    Delete(mt, Length(mt), 1);
   tp:=Pos(' =', mt);
   if tp<>0 then
    Delete(mt, tp, 1);
   tp:=Pos('= ', mt);
   if tp<>0 then
    Delete(mt, tp+1, 1);
   if mt='' then //������ ������
    continue;
   for n:=1 to 7 do //���� ��������
    if copy(mt, 1, Length(rset[n]))=rset[n] then
     begin
      mt:=copy(mt, Length(rset[n])+1, Length(mt)-Length(rset[n]));
      case n of
       1:if StrToInt(mt)>0 then
          Port:=StrToInt(mt);
       2:flpath:=mt;
       3:if Byte(StrToInt(mt)) in [0..MAX_L] then
          c:=Byte(StrToInt(mt));
       4:if (StrToInt(mt) in [ord(llAll), ord(llNotice), ord(llError)]) then
          cll:=LogLev(StrToInt(mt));
       5:if (StrToInt(mt) in [ord(llAll), ord(llNotice), ord(llError)]) then
          fll:=LogLev(StrToInt(mt));
       6:KTimeOut:=StrToInt(mt);
       7:BTimeOut:=StrToInt(mt);
      end;
      mt:='';
      break;
     end;
   if mt<>'' then
    if copy(mt, 1, 7)='Plugin=' then
     begin
      m:=LoadLibrary(PChar(copy(mt, 8, Length(mt)-7)));
      PlugInst:=m<>0;
      if PlugInst then
       begin
        @MGetInfo:=GetProcAddress(m, 'MGetInfo');
        @MInitProc:=GetProcAddress(m, 'MInitProc');
        @MRelProc:=GetProcAddress(m, 'MRelProc');
        @MMethProc:=GetProcAddress(m, 'MMethProc');
        @MHeadProc:=GetProcAddress(m, 'MHeadProc');
        @MLoadPostProc:=GetProcAddress(m, 'MLoadPostProc');
        @MLoadGetProc:=GetProcAddress(m, 'MLoadGetProc');
        @MLoadMeth:=GetProcAddress(m, 'MLoadMeth');
        @MQueryProc:=GetProcAddress(m, 'MQueryProc');
        @MUpdateParamsProc:=GetProcAddress(m, 'MUpdateParamsProc');
        @MGetHLine:=GetProcAddress(m, 'MGetHLine');
        @MSetPosProc:=GetProcAddress(m, 'MSetPosProc');
        @MReadProc:=GetProcAddress(m, 'MReadProc');
        @MConfProc:=GetProcAddress(m, 'MConfProc');    
        @MGetSMeth:=GetProcAddress(m, 'MGetSMeth');
        PlugInst:=(@MGetInfo<>nil) and (@MInitProc<>nil) and (@MRelProc<>nil) and
                  (@MMethProc<>nil) and (@MHeadProc<>nil) and (@MLoadPostProc<>nil) and
                  (@MLoadGetProc<>nil) and (@MLoadMeth<>nil) and (@MQueryProc<>nil) and
                  (@MUpdateParamsProc<>nil) and (@MGetHLine<>nil) and (@MSetPosProc<>nil) and
                  (@MReadProc<>nil) and (@MConfProc<>nil) and (@MGetSMeth<>nil);
       end;
      if not PlugInst then
       begin
        writeln('Plugin is not loaded! (Line ', ln, ')');
        MyHalt(4);
       end
      else
       writeln('Loaded plugin: '+MGetInfo);
     end
    else
     if not (PlugInst and MConfProc(PChar(mt))) then
      begin //�� �����
       writeln('Error at config file! (Line ', ln , ')');
       MyHalt(3);
      end;
  end;
 Close(F); //��������� ����
end;

begin
 SetErrorMode(1);
 //������������� Home ��� �����, � ������� ����� Server.exe
 flpath:=ParamStr(0);
 while (Length(flpath)>0) and (flpath[Length(flpath)]<>'\') do
  Delete(flpath, Length(flpath), 1);
 ChDir(flpath);
 //�������� ����
 ShowLogo;
 //�������� ������
 writeln(#13#10'--------------------------------'#13#10'Copyright (c) 2009 Ivanov Viktor'#13#10'--------------------------------'#13#10#13#10'Loading...');
 //��������� default-�������� ����������
 Port:=80;
 c:=MAX_L;
 flpath:='0.0.0.0';
 cll:=llAll;
 fll:=llNotice;
 KTimeOut:=15000;
 BTimeOut:=5000;
 LogMsgLock:=0;
 LogMsgLockE:=CreateEvent(nil, true, true, 'LogMsgLock');
 LogMsgLockT:=0;
 TerminateAllThreadsLock:=0;
 TerminateAllThreadsLockE:=CreateEvent(nil, true, true, 'TerminateAllThreadsLock');
 CheckThreadsLock:=0;
 CheckThreadsLockT:=0;
 Sleep(200);
 FileMode:=0;
 //���� config.conf
 Assign(F, 'config.conf');
{$I-}
 Reset(F);
{$I+}
 if IOResult<>0 then
  WriteNewConf //��� - �������
 else
  ReadConf;
 Sleep(200);
 writeln('Initialization...');
 if WSAStartUp(514, @Data)<0 then //Winsock 2.2
  begin
   writeln('Unsupported version of WinSock!');
   MyHalt(2);
  end;
 //������ �����
 ListenSocket:=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 service.sin_family:=AF_INET;
 service.sin_port:=htons(port);
 service.sin_addr.S_addr:=inet_addr(PChar(flpath));
 if bind(ListenSocket, Psockaddr(@service), sizeof(sockaddr))=SOCKET_ERROR then
  begin
   writeln('Error ', WSAGetLastError, ': '+SysErrorMessage(WSAGetLastError));
   MyHalt(WSAGetLastError);
  end;
 listen(ListenSocket, 1);
 //������. ��������! �� ��������� ���������� � ������� ����!
 writeln(#13#10'Don''t close this window! Enter QUIT to safe exit');
 //���...
 MyWait;
 //���� ����� ��� �����
 flpath:=GetEnvironmentVariable('APPDATA');
 if flpath[Length(flpath)]<>'\' then
  flpath:=flpath+'\';
 flpath:=flpath+'VPSERVER';
 if not DirectoryExists(flpath) then
  MkDir(flpath); //����� ��� - �������
 if not DirectoryExists(flpath) then
  begin //�� ����� ���? �� ���� �������
   writeln('Error! Can''t create directory!');
   MyHalt(1);
  end;
 //������� ����������
 ThreadCount:=0;
 FillChar(ThreadBe, MAX_L*sizeof(Boolean), 0);
// FillChar(ThreadBusy, MAX_L*sizeof(Boolean), 0);
// FillChar(ThreadID, MAX_L*sizeof(LongWord), 0);
// FillChar(ThreadHnd, MAX_L*sizeof(LongWord), 0);
 //��������� ����
 OpenLog(F, flpath+'\log.log');
 OpenLog(SysLog, flpath+'\sys.log');
 for i:=1 to MAX_L do
  OpenLog(ThreadLog[i], FormLogFile(i));
 //����� �������� ����������
 s:='>>>> Executing server at '+GetCurDateTime+' <<<<';
 writeln(F, s);
 writeln(SysLog, s);
 for i:=1 to MAX_L do
  writeln(ThreadLog[i], s);
 SHOWCON:=0;
 LogMsg(llError, SYS, 'Server version: '+VER);
 LogMsg(llError, SYS, 'Port '+IntToStr(Port)+'; IP '+inet_ntoa(service.sin_addr));
 LogMsg(llError, SYS, 'Initial listeners amount is '+IntToStr(c));
 LogMsg(llError, SYS, 'Log folder: '+flpath);
 LogMsg(llError, SYS, 'General log: '+flpath+'\log.log');
 LogMsg(llError, SYS, 'System log: '+flpath+'\sys.log');
 LogMsg(llError, SYS, 'Level of logging in window is '+IntToStr(ord(cll)));
 LogMsg(llError, SYS, 'Level of logging in file is '+IntToStr(ord(fll)));
 LogMsg(llError, SYS, 'Keep-Alive timeout is '+IntToStr(KTimeOut));
 LogMsg(llError, SYS, 'Read timeout is '+IntToStr(BTimeOut));
 LEP:=ExitProc;
 ExitProc:=@WExit;
 mx:=c;
 if mx=0 then
  inc(mx);
 //������ �������
 CheckThreads(SYS);
 flpath:='';
 while flpath<>'QUIT' do
  begin
   if InterlockedIncrement(SHOWCON)=1 then
    write('>');
   readln(s); //��� ENTER
   InterlockedDecrement(SHOWCON);
   DelStr(s, '  ', 1);
   if s='' then
    continue;
   flpath:=UpString(s);
   if Pos(' ', s)<>0 then
    begin
     flpath:=copy(flpath, 1, Pos(' ', s)-1);
     Delete(s, 1, Pos(' ' , s));
    end
   else
    s:='';
   if flpath='SMODE' then
    begin
     LogMsg(llError, SYS, 'Switching S mode');
     TerminateAllThreads(SYS);
     CheckThreads(SYS);
     SMode:=not SMode;
     LogMsg(llError, SYS, 'Switch complete. Current state is '+IntToStr(ord(SMode)));
    end
   else
    if flpath='HELP' then
     writeln('See readme.txt')
    else
     if (flpath='SHOW') or (flpath='SHOWALL') then
      begin
       c:=0;
       for i:=1 to MAX_L do
        begin
         if ThreadBe[i] then
          if ThreadBusy[i] then
           begin
            write('|', i:4, 'B':2);
            inc(c);
           end
          else
           begin
            write('|', i:4, 'F':2);
            inc(c);
           end
         else
          if flpath='SHOWALL' then
           begin
            write('|', i:4, 'N':2);
            inc(c);
           end;
         if (c=10) or ((i=MAX_L) and (c<>0)) then
          begin
           writeln('|');
           c:=0;
          end;
        end;
       write('B = busy, F = free');
       if flpath='SHOWALL' then
        write(', N = not used');
       writeln;
      end
     else
      if flpath='LLEV' then
       if Pos(' ', s)=0 then
        writeln('Console: ', ord(cll), '; File: ', ord(fll), #13#10'Usage: LLEV CLL FLL')
       else
        begin
         flpath:=copy(s, 1, Pos(' ', s)-1);
         Delete(s, 1, Length(flpath)+1);
         c:=StrToInt(flpath);
         if c in [ord(llAll), ord(llNotice), ord(llError)] then
          begin
           cll:=LogLev(c);
           LogMsg(llError, SYS, 'Console log level was changed to '+IntToStr(ord(cll)));
          end;
         c:=StrToInt(s);
         if c in [ord(llAll), ord(llNotice), ord(llError)] then
          begin
           fll:=LogLev(c);
           LogMsg(llError, SYS, 'File log level was changed to '+IntToStr(ord(fll)));
          end;
        end
      else
       if flpath='CONSOLEV' then
        begin
         consolev:=not consolev;
         LogMsg(llError, SYS, 'CONSOLEV state was changed to '+IntToStr(ord(consolev)));
         if not consolev then
          writeln('Current state of CONSOLEV is diasbled');
        end
       else
        if flpath='RESETT' then
         begin
          Panic_;
          CheckThreads(SYS);
         end
        else
         if flpath<>'QUIT' then
          writeln('Invalid command!');
  end;
 LogMsg(llError, SYS, 'DoExit command!');
 MyExit(0); //�����
end.
