unit WSUtils;

interface

uses {$IFNDEF MSWINDOWS}Sockets{$ELSE}WinSock2{$ENDIF}, STypes, SUtils;

function ListenPort(const IP:String;const Port:Word;out ListenSocket:TSocket):LongWord;
function ConnectToPort(const IP:String;const Port:Word;out ConnectSocket:TSocket):LongWord;
function AcceptConnection(const ListenSocket:TSocket;out From:String;out ClientSocket:TSocket):LongWord;
function CreateDuplicatedSocket(out Socket:TSocket;const Info:TSocketInfo):LongWord;
procedure StopConnection(var Socket:TSocket);
function DuplicateSocket(const Socket:TSocket;const PID:LongWord;out Info:TSocketInfo):LongWord;
procedure InitSockRecord(out SocketRecord:TSockRecord;const Socket:TSocket;const Wait:LongWord);
function SendBuf(var SocketRec:TSockRecord;var buf;const len:LongWord;out TimeOut:Boolean;out RealSent:LongWord):LongWord;
function RecvBuf(var SocketRec:TSockRecord;var buf;const len:LongWord;out TimeOut:Boolean;out RealRecv:LongWord):LongWord;
procedure DestroySockRecord(var SocketRecord:TSockRecord;out Sent, Recv:LongWord);
procedure AssignSocket(var F:TextFile;const Socket:TSocket;const Wait:LongWord);
function GetFileSocket(var F:TextFile):TSocket;
function GetFileWait(var F:TextFile):LongWord;
function GetFileSockRecord(var F:TextFile):PSockRecord;
function GetSocketError:LongWord;
procedure IgnoreIntr(); overload;
procedure IgnoreIntr(const Error:LongWord); overload;

implementation

{$IFNDEF MSWINDOWS}
function WSAGetLastError:LongWord;
begin
 WSAGetLastError:=socketerror;
end;
{$ELSE}
procedure IgnoreIntr();
var l:LongWord;
begin
 l:=WSAGetLastError;
 if (l=WSAECONNABORTED) or (l=WSAEINTR) or (l=WSAECONNREFUSED) or (l=WSAECONNRESET) or (l=WSAENETRESET) or (l=WSA_OPERATION_ABORTED) then
  WSASetLastError(0);
end;

procedure IgnoreIntr(const Error:LongWord);
begin
 IgnoreIntr;
 if WSAGetLastError=0 then
  SetLastError(Error);
end;
{$ENDIF}

function GetSocketError:LongWord;
begin
 GetSocketError:=WSAGetLastError;
end;

function ListenPort(const IP:String;const Port:Word;out ListenSocket:TSocket):LongWord;
var
 service:TSockAddr;
begin
 ListenSocket:=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 if ListenSocket<>INVALID_SOCKET then
  begin
   service.sin_family:=AF_INET;
   service.sin_port:=htons(Port);
   service.sin_addr.S_addr:=inet_addr(PChar(IP));
   if (bind(ListenSocket, @service, sizeof(service))=SOCKET_ERROR) then
    closesocket(ListenSocket)
   else
    listen(ListenSocket, SOMAXCONN);
  end;
 ListenPort:=WSAGetLastError;
end;

function ConnectToPort(const IP:String;const Port:Word;out ConnectSocket:TSocket):LongWord;
var
 service:TSockAddr;
begin
 ConnectSocket:=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 if ConnectSocket<>INVALID_SOCKET then
  begin
   service.sin_family:=AF_INET;
   service.sin_port:=htons(Port);
   service.sin_addr.S_addr:=inet_addr(PChar(IP));
   if connect(ConnectSocket, @service, sizeof(service))=SOCKET_ERROR then
    closesocket(ConnectSocket);
  end;
 ConnectToPort:=WSAGetLastError;
end;

function AcceptConnection(const ListenSocket:TSocket;out From:String;out ClientSocket:TSocket):LongWord;
var
 service:TSockAddr;
 s:LongWord;
begin
 s:=sizeof(service);
 ClientSocket:=accept(ListenSocket, @service, @s);
 if ClientSocket<>INVALID_SOCKET then
  From:=inet_ntoa(service.sin_addr);
 AcceptConnection:=WSAGetLastError;
end;

{$IFDEF MSWINDOWS}
function SendRecvBuf(var Ride:TRide;const m:Boolean;const Socket:TSocket;var Buf;const Len:LongWord;out Total:LongWord;const Wait:LongWord;out TimeOut:Boolean):LongWord;
var
 Overlap:TWSAOverlapped;
 Buffer:WSABUF;
 Bytes:LongWord;
 Event:WSAEVENT;
 Flags:LongWord;
 Res:Integer;
begin
 StartRide(Ride);
 Event:=WSACreateEvent;
 FillChar(Overlap, sizeof(Overlap), 0);
 Overlap.hEvent:=Event;
 Total:=0;
 Flags:=0;
 Buffer.buf:=@Buf;
 Buffer.len:=len;
 TimeOut:=false;
 if m then
  Res:=WSASend(Socket, @Buffer, 1, Bytes, Flags, @Overlap, nil)
 else
  Res:=WSARecv(Socket, @Buffer, 1, Bytes, Flags, @Overlap, nil);
 if Res=SOCKET_ERROR then
  if WSAGetLastError=WSA_IO_PENDING then
   begin
    TimeOut:=WSAWaitForMultipleEvents(1, @Event, false, Wait, false)=WSA_WAIT_TIMEOUT;
    if not TimeOut then
     WSAGetOverlappedResult(Socket, @Overlap, @Total, false, flags);
   end
  else
 else
  Total:=Bytes;
 WSACloseEvent(Event);
 StopRide(Ride);
 if WSAGetLastError=WSA_IO_PENDING then
  WSASetLastError(0);
 SendRecvBuf:=WSAGetLastError;
end;
{$ENDIF}

function SendBuf(var SocketRec:TSockRecord;var buf;const len:LongWord;out TimeOut:Boolean;out RealSent:LongWord):LongWord;
begin
 SendBuf:=SendRecvBuf(SocketRec.Ride, true, SocketRec.Socket, buf, len, RealSent, SocketRec.Wait, TimeOut);
 inc(SocketRec.Sent, RealSent);
end;

function RecvBuf(var SocketRec:TSockRecord;var buf;const len:LongWord;out TimeOut:Boolean;out RealRecv:LongWord):LongWord;
begin
 RecvBuf:=SendRecvBuf(SocketRec.Ride, false, SocketRec.Socket, buf, len, RealRecv, SocketRec.Wait, TimeOut);
 inc(SocketRec.Recv, RealRecv);
end;

procedure InitSockRecord(out SocketRecord:TSockRecord;const Socket:TSocket;const Wait:LongWord);
begin
 FillChar(SocketRecord, sizeof(SocketRecord), 0);
 SocketRecord.Socket:=Socket;
 SocketRecord.Wait:=Wait;
 with SocketRecord do
  begin
   Sent:=0;
   Recv:=0;
   Ride:=RegisterRide;
  end;
end;

procedure DestroySockRecord(var SocketRecord:TSockRecord;out Sent, Recv:LongWord);
begin
 Sent:=SocketRecord.Sent;
 Recv:=SocketRecord.Recv;
 UnregisterRide(SocketRecord.Ride);
end;

procedure StopConnection(var Socket:TSocket);
begin
 closesocket(Socket);
end;

{$IFDEF MSWINDOWS}
function DuplicateSocket(const Socket:TSocket;const PID:LongWord;out Info:TSocketInfo):LongWord;
begin
 DuplicateSocket:=WSADuplicateSocket(Socket, PID, @Info);
end;

function CreateDuplicatedSocket(out Socket:TSocket;const Info:TSocketInfo):LongWord;
begin
 Socket:=WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, @Info, 0, WSA_FLAG_OVERLAPPED);
 CreateDuplicatedSocket:=WSAGetLastError;
end;
{$ENDIF}

{----------------------Socket files}

function WSNOPProc(var F:TTextRec):Integer;
begin
 WSNOPProc:=0;
end;

function WSFileIn(var F:TTextRec):Integer;
var
 NoE:Boolean;
begin
 F.BufEnd:=0;
 F.BufPos:=0;
 WSFileIn:=RecvBuf(PSockRecord(Pointer(@F.UserData)^)^, F.BufPtr^, F.BufSize, NoE, {$IFDEF FPC}PLongWord(@F.BufEnd)^{$ELSE}F.BufEnd{$ENDIF});
 if NoE then
  WSFileIn:=WSA_WAIT_TIMEOUT;
end;

function WSFileOut(var F:TTextRec):Integer;
var
 Dummy:LongWord;
 NoE:Boolean;
begin
 WSFileOut:=0;
 if F.BufPos<>0 then
  begin
   WSFileOut:=SendBuf(PSockRecord(Pointer(@F.UserData)^)^, F.BufPtr^, F.BufPos, NoE, Dummy);
   if NoE then
    WSFileOut:=WSA_WAIT_TIMEOUT;
   F.BufPos:=0;
  end;
end;

function WSFileOpen(var F:TTextRec):Integer;
begin
 WSFileOpen:=-1;
 F.BufEnd:=0;
 case F.Mode of
  fmInput:F.InOutFunc:=@WSFileIn;
  fmOutput:F.InOutFunc:=@WSFileOut;
 else
  Exit;
 end;
 F.BufSize:=BufS;
 GetMem(F.BufPtr, F.BufSize);
 New(PSockRecord(Pointer(@F.UserData)^));
 InitSockRecord(PSockRecord(Pointer(@F.UserData)^)^, F.Handle, PLongWord(@F.UserData[sizeof(Pointer)+Low(F.UserData)])^);
 F.FlushFunc:=@WSNOPProc;
{$IFDEF FPC}
 F.LineEnd:=#13#10;
{$ELSE}
 F.Flags:=tfCRLF;
{$ENDIF}
 WSFileOpen:=0;
end;

function WSFileClose(var F:TTextRec):Integer;
var
 Dummy:LongWord;
begin
 F.Mode:=fmClosed;
 DestroySockRecord(PSockRecord(Pointer(@F.UserData)^)^, Dummy, Dummy);
 Dispose(PSockRecord(Pointer(@F.UserData)^));
 FreeMem(F.BufPtr);
 WSFileClose:=0;
end;

procedure AssignSocket(var F:TextFile;const Socket:TSocket;const Wait:LongWord);
begin
 FillChar(F, sizeof(TTextRec), 0);
 with TTextRec(F) do
  begin
   Mode:=fmClosed;
   OpenFunc:=@WSFileOpen;
   CloseFunc:=@WSFileClose;
   Handle:=Socket;
   Name:='CON';
   PLongWord(@UserData[sizeof(Pointer)+Low(UserData)])^:=Wait;
  end;
end;

function GetFileSocket(var F:TextFile):TSocket;
begin
 GetFileSocket:=TTextRec(F).Handle;
end;

function GetFileWait(var F:TextFile):LongWord;
begin
 GetFileWait:=PLongWord(@TTextRec(F).UserData[sizeof(Pointer)+Low(TTextRec(F).UserData)])^;
end;

function GetFileSockRecord(var F:TextFile):PSockRecord;
begin
 GetFileSockRecord:=PSockRecord(Pointer(@TTextRec(F).UserData)^);
end;

{-------------------------------End}

var Data:TWSAData;

initialization
 if WSAStartup(WINSOCK_VERSION, Data)<>0 then
  begin
   writeln('Error: версия WinSock не поддерживается');
   MyHalt(7);
  end;
finalization
 WSACleanup;
end.
