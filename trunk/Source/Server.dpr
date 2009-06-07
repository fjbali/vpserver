program Server;

{$APPTYPE CONSOLE}
{$H+} {Использум длинные строки!}

{=======Объявление типов=======}

type
 PWSABUF=^WSABUF;     //Структура для буфера
 WSABUF=record
  len:Longint;
  buf:Pointer;
 end;
 PWSAEVENT=^WSAEVENT; //"Случаи" для ожидания
 WSAEVENT=LongWord;
 PWSAOVERLAPPED=^WSAOVERLAPPED; //Структура для ожидания
 WSAOVERLAPPED=record
  Internal:LongWord;
  InternalHigh:LongWord;
  Offset:LongWord;
  OffsetHigh:LongWord;
  hEvent:WSAEVENT;
 end;
 PSOCKET=^TSOCKET;    //Дескриптор сокета
 TSOCKET=Integer;
 PWSADATA=^WSADATA;   //Данные о WS2_32.DLL
 WSADATA=record
  wVersion:Word;
  wHighVersion:Word;
  szDescription:array[0..256] of Char;
  szSystemStatus:array[0..128] of Char;
  iMaxSockets:Word;
  iMaxUpdDg:Word;
  lpVendorInfo:PChar;
 end;
 Pin_addr=^in_addr;   //Адрес компьютера
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
 sockaddr_in=record   //Адрес входящего сокета сокета
  sin_family:Smallint;
  sin_port:Word;
  sin_addr:in_addr;
  sin_zero:array[1..8] of Char;
 end;
 Psockaddr=^sockaddr; //Адрес сокета
 sockaddr=record
  sa_family:Word;
  sa_data:array[0..13] of Char;
 end;
 PSystemTime=^TSystemTime; //Время
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
 TFileTime=record     //Время файла
  dwLowDateTime:LongWord;
  dwHighDateTime:LongWord;
 end;
 TWin32FindData=record //Данные о файле
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
 LogLev=(llAll, llNotice, llError); //Уровни лога

{=======Функции плагина=======}

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

{=======Основные константы=======}

const
 AF_INET=2;                //Мы по сети
 SOCK_STREAM=1;            //Мы по сокетам
 IPPROTO_TCP=6;            //Мы по TCP
 SOCKET_ERROR=-1;          //Для ошибок
 WSA_IO_PENDING=997;       //Ждать завершения IO
 INFINITE=$FFFFFFFF;       //Ждать до потери пульса
 WSA_INFINITE=INFINITE;    //-|-
 SYS=-1;                   //Говорит система
 MAX_L=151;                //Колличество потоков
 VER='2.74alpha';          //Версия
 SERV='VPSERVER '+VER;     //Имя сервера

{=======API-функции=======}

//Инициализация
function WSAStartup(wVersionRequested:Integer;lpWSAData:PWSADATA):Integer; stdcall; external 'WS2_32.DLL';
//Резервирование дескриптора для сокета
function socket(af, stype, protocol:Integer):TSOCKET; stdcall; external 'WS2_32.DLL';
//Преобразование порта
function htons(hostshort:Word):Word; stdcall; external 'WS2_32.DLL';
//Строка по IP
function inet_ntoa(addr:in_addr):PChar; stdcall; external 'WS2_32.DLL';
//Последняя ошибка
function WSAGetLastError:Integer; stdcall; external 'WS2_32.DLL';
//IP по строке
function inet_addr(cp:PChar):Longint; stdcall; external 'WS2_32.DLL';
//Привязать к сокету адрес
function bind(s:TSocket;name:Psockaddr;namelen:Integer):Integer; stdcall; external 'WS2_32.DLL';
//Слушать
function listen(s:TSocket;backlog:Integer):Integer; stdcall; external 'WS2_32.DLL';
//Ждать входящих
function accept(s:TSocket;addr:Psockaddr;addrlen:PInteger):TSocket; stdcall; external 'WS2_32.DLL';
//Создать "случай"
function WSACreateEvent:WSAEVENT; stdcall; external 'WS2_32.DLL';
//Получить буфер
function WSARecv(s:TSocket;lpBuffers:PWSABUF;dwBufferCount:LongWord;
                 lpNumberOfBytesRecvd:PLongWord;lpFlags:
                 PLongWord;lpOverlapped:PWSAOVERLAPPED;lpCompletionRoutine:Pointer):Integer; stdcall; external 'WS2_32.DLL';
//Отправить буфер
function WSASend(s:TSocket;lpBuffers:PWSABUF;dwBufferCount:LongWord;
                 lpNumberOfBytesSent:PLongWord;lpFlags:LongWord;
                 lpOverlapped:PWSAOVERLAPPED;lpCompletionRoutine:Pointer):Integer; stdcall; external 'WS2_32.DLL';
//Ждать все "случаи"
function WSAWaitForMultipleEvents(cEvents:LongWord;const lphEvents:PWSAEVENT;fWaitAll:Boolean;dwTimeout:LongWord;fAlertable:Boolean):LongWord; stdcall; external 'WS2_32.DLL';
//Сбросить "случай"
function WSAResetEvent(hEvent:WSAEVENT):Boolean; stdcall; external 'WS2_32.DLL';
//Получить результат
function WSAGetOverlappedResult(s:TSOCKET;lpOverlapped:PWSAOVERLAPPED;lpcbTransfer:PLongWord;fWait:Boolean;lpdwFlags:PLongWord):Boolean; stdcall; external 'WS2_32.DLL';
//Закрыть сокет
function closesocket(s:TSocket):Integer; stdcall; external 'WS2_32.DLL';
//Закрыть "случай"
function WSACloseEvent(hEvent:WSAEVENT):Boolean; stdcall; external 'WS2_32.DLL';
//Увеличить, блокируя
function InterlockedIncrement(var Addend:Integer):Integer; stdcall; external 'kernel32.dll';
//Уменьшить, блокируя
function InterlockedDecrement(var Addend:Integer):Integer; stdcall; external 'kernel32.dll';
//Последняя ошибка
function GetLastError:LongWord; stdcall; external 'kernel32.dll';
//Формировать строку
function FormatMessage(dwFlags:LongWord;lpSource:Pointer;dwMessageId:LongWord;dwLanguageId:LongWord;
                       lpBuffer:PChar;nSize:LongWord;Arguments:Pointer):LongWord; stdcall; external 'kernel32.dll' name 'FormatMessageA';
//Ждать
procedure Sleep(dwMilliseconds:LongWord); stdcall; external 'kernel32.dll';
//Возобновить поток
function ResumeThread(hThread:LongWord):LongWord; stdcall; external 'kernel32.dll';
//Пристановить поток
function SuspendThread(hThread:LongWord):LongWord; stdcall; external 'kernel32.dll';
//Завершить поток
function TerminateThread(hThread:LongWord;dwExitCode:LongWord):Boolean; stdcall; external 'kernel32.dll';
//Получить переменную из окружения
function GetEnvironmentVariableA(lpName:PChar;lpBuffer:PChar;nSize:LongWord):LongWord; stdcall; external 'kernel32.dll';
//Получить атрибут файла
function GetFileAttributesA(lpFileName:PChar):LongWord; stdcall; external 'kernel32.dll';
//Закрыть дескриптор
function CloseHandle(hObject:LongWord):Boolean; stdcall; external 'kernel32.dll';
//Получить идентификатор текущего потока
function GetCurrentThreadId:LongWord; stdcall; external 'kernel32.dll';
//Получить системное время (GMT)
procedure GetSystemTime(var lpSystemTime:TSystemTime); stdcall; external 'kernel32.dll';
//Найти файл
function FindFirstFileA(lpFileName:PChar;var lpFindFileData:TWin32FindData):LongWord; stdcall; external 'kernel32.dll' name 'FindFirstFileA';
//Закрыть поиск
function FindClose(hFindFile:LongWord):Boolean; stdcall; external 'kernel32.dll';
//Получить системное время из времени файла
function FileTimeToSystemTime(const lpFileTime:TFileTime;var lpSystemTime:TSystemTime):Boolean; stdcall; external 'kernel32.dll' name 'FileTimeToSystemTime';
//Создать "случай"
function CreateEvent(lpEventAttributes:Pointer;bManualReset, bInitialState:Boolean;lpName:PChar):LongWord; stdcall; external 'kernel32.dll' name 'CreateEventA';
//Установить "случай"
function SetEvent(hEvent:LongWord):Boolean; stdcall; external 'kernel32.dll';
//Сбросить "случай"
function ResetEvent(hEvent:LongWord):Boolean; stdcall; external 'kernel32.dll';
//Ждать "случая"
function WaitForSingleObject(hHandle:LongWord;dwMilliseconds:LongWord):LongWord; stdcall; external 'kernel32.dll';
//Загрузить библиотеку
function LoadLibrary(lpLibFileName:PChar):LongWord; stdcall; external 'kernel32.dll' name 'LoadLibraryA';
//Найти процедуру
function GetProcAddress(hModule:LongWord;lpProcName:PChar):Pointer; stdcall; external 'kernel32.dll' name 'GetProcAddress';
//Режим ошибок
function SetErrorMode(uMode:LongWord):LongWord; stdcall; external 'kernel32.dll';

{=======Вспомогательные функции=======}

//Получить описание ошибки
function SysErrorMessage(ErrorCode:Integer):String;
var Buffer:array[0..255] of Char;
    Len:Integer;
begin
 Len:=FormatMessage($3200, nil, ErrorCode, 0, Buffer, sizeOf(Buffer), nil);
 while (Len>0) and (Buffer[Len-1] in [#0..#32, '.']) do
  dec(Len);
 SetString(Result, Buffer, Len);
end;
//Переделать Int в Str
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
//Перевести Int в Str
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
//Перевести Str в Int
function StrToInt(const S:string):Integer;
var E:Integer;
begin
 Val(S, Result, E);
 if E<>0 then
  Result:=-MaxInt;
end;
//Получить переменную из окружения
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
//Определить существование папки
function DirectoryExists(const Directory:String):Boolean;
var Code:Integer;
begin
 Code:=GetFileAttributesA(PChar(Directory));
 Result:=(Code<>-1) and (($10 and Code)<>0);
end;
//Получить последнее изменение файла
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
//Удалить строку из строки
procedure DelStr(var s:String;substr:String;del:Integer);
begin
 while Pos(substr, s)<>0 do
  Delete(s, Pos(substr, s), del);
end;
//Преобразовать в верхний регистр
function UpString(s:String):String;
var i:Integer;
begin
 Result:=s;
 for i:=1 to Length(s) do
  Result[i]:=UpCase(Result[i]);
end;

{=======Функции модуля======}

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

{=======Основные переменные=======}

var ListenSocket:TSOCKET;                  //Слушающий сокет
    ThreadCount:Integer;                   //Количество потоков
    ThreadBusy:array[1..MAX_L] of Boolean; //Флаг занятости
    ThreadBe:array[1..MAX_L] of Boolean;   //Флаг существования
    ThreadHnd:array[1..MAX_L] of LongWord; //Дескрипторы потоков
    ThreadID:array[1..MAX_L] of LongWord;  //Идентификаторы потоков
    ThreadSock:array[1..MAX_L] of TSocket; //Сокеты потоков
    ThreadFl:array[1..MAX_L] of File;      //Файлы потоков
    ThreadLog:array[1..MAX_L] of Text;     //Логи потоков
//    CreateThreadLock:Integer;              //Блокировка процедуры CreateThreadListener
    LogMsgLock:Integer;                    //Блокировка процедуры LogMsg
    LogMsgLockE:LongWord;                  //Ожидание для процедуры LogMsg
    LogMsgLockT:LongWord;                  //Поток процедуры LogMsg
    TerminateAllThreadsLock:Integer;       //Блокировка процедуры TerminateAllThreads
    TerminateAllThreadsLockE:LongWord;     //Ожидание для процедуры TerminateAllThreads
    KTimeOut, BTimeOut:LongWord;           //Таймауты соединений
    SMode:Boolean=false;                   //Отладочный режим
    mx:Integer;                            //Количество потоков
    CheckThreadsLock:Integer;              //Блокировка процедуры CheckThreads
    CheckThreadsLockT:LongWord;            //Поток процедуры CheckThreads

{=======Общие функции=======}

procedure Panic_; forward;                              //Паника
procedure CreateThreadListener(f:Integer); forward;     //Создать слушующего
procedure LogMsg(lev:LogLev;from:Integer;msg:String); forward; //Добавить в лог
procedure MyQuit(ReturnCode:Integer); forward;          //Принудительное завершение
procedure MyHalt(ReturnCode:Integer); forward;          //Фатальное завершение
function FormatSysTime(t:TSystemTime):String; forward;  //Форматировать время/дату
function GetFormatedTime:String; forward;               //Получить форматированное время/дату

{=======Начало сервера=======}

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

//Проверить на слушателей
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
 for i:=1 to MAX_L do          //Проверка по всем потокам
  if ThreadBe[i] and (not ThreadBusy[i]) then
   begin
    f:=true;
    break;
   end;
 if not f then
  begin
   //Свободных потоков не обнаружено
   LogMsg(llAll, s, 'No threads are free! Create new!');
   CreateThreadListener(s);      //Создать новый поток
  end;
 CheckThreadsLockT:=0;
 InterlockedDecrement(CheckThreadsLock);
end;

const
 fhsbc='File has been closed'; //Сообщение о принудительном закрытии файла
 rtout='Read timeout';         //Превышен лимит ожидания

//Процедура потока
function ThreadProc(Index:PInteger):Integer;
var EventTotal:Longint;
    EventArray:array[0..63] of WSAEVENT;
    i:Integer;
    UKAlive, FErr:Boolean;
//Функция отправки/получения данных
function SendRecvBuf(var buf;len:Longint;r:Boolean):Longint;
var DataBuf:WSABUF;
    SentRecvBytes, Flags, BytesTransferred:Longint;
    AcceptOverlapped:WSAOVERLAPPED;
    EIndex:LongWord;
    Res:Integer;
    w:LongWord;
begin
 //Инициализация (обнуление переменных и запись дефолтовых значений)
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
 if r then   //Если r=true, то получить данные
  Res:=WSARecv(ThreadSock[i], @DataBuf, 1, @SentRecvBytes, @Flags, @AcceptOverlapped, nil)
 else        //Если r=false, то отправить данные
  Res:=WSASend(ThreadSock[i], @DataBuf, 1, @SentRecvBytes, Flags, @AcceptOverlapped, nil);
 if Res=SOCKET_ERROR then  //Ошибка
  if WSAGetLastError<>WSA_IO_PENDING then //Проверка на неоконченный ввод/вывод
//   begin
//    LogMsg(llError, i, 'Error '+IntToStr(WSAGetLastError)+' occured at WSASend()/WSARecv(): '+SysErrorMessage(WSAGetLastError));
    FErr:=true//;
//    Exit;    //Возвращаем 0
//   end
  else
   begin     //Ввод/вывод не окончен. Необходимо подождать
    if UKAlive then
     w:=KTimeOut
    else
     w:=BTimeOut; //Ждём 5 секунд - если плохое соединение
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
 Result:=BytesTransferred; //Возвращаем колличество переданных/принятых байт
 if WSAGetLastError=WSA_IO_PENDING then
  SetLastError(0); //Игнорируем IO_PENDING
end;
//Отправить буфер
function SendBuf(var buf;len:Longint):Longint;
begin
 Result:=SendRecvBuf(buf, len, false);
end;
//Принять буфер
function RecvBuf(var buf;len:Longint):Longint;
begin
 Result:=SendRecvBuf(buf, len, true);
end;
//Дополнительный тип для Accept-Ranges
type
 PContRang=^TContRang;
 TContRang=record
  StartR:Longint;  //Начало
  EndR:Longint;    //Конец
  Next:PContRang;  //Следующий
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
//Преобразовать строку
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
//Получить следующую строку
procedure FormNextStr;
var f:Boolean;
    ls:Word;
procedure InternalProc(k:Boolean);
var p:Longint;
begin
 if o=sz then  //Закончился буфер?
  begin        //Получаем новый
   sz:=RecvBuf(buf, 4096);
   inc(arecv, sz);
   o:=0;       //Обнуляем смещение
  end;
 for p:=o+1 to sz do //Просматриваем буфер
  if buf[p]=0 then   //Если встретили #0 - конец строки (хотя, по идее должен быть Fatal error в потоке)
   begin
    f:=true;
    break;
   end
  else
   begin
    if not (buf[p] in [10, 13]) then  //Добавляем символ
     begin
      r:=r+chr(buf[p]);
      inc(ls);
     end;
    //Проверка на конец строки (#13, #10, #13#10)
    if ((buf[p]=10) and ((p=0) or (buf[p-1]<>13)) and ((p=sz) or (buf[p+1]<>13))) or
       ((buf[p]=13) and ((p=0) or (buf[p-1]<>10)) and ((p=sz) or (buf[p+1]<>10))) or
       ((buf[p]=10) and (p>0) and (buf[p-1]=13)) then
     begin
      f:=true;
      break;
     end;
   end;
 o:=p;  //Обновляем смещение
 if (not f) and (ls<255) and k then  //Прошли весь буфер, но не нашли конец строки?
  InternalProc(false);  //Дополнить
end;
begin
 ls:=0;  //Длина строки = 0
 r:='';  //Обнуляем строку
 f:=false; //Нет конца
 InternalProc(true);
end;
//Удалить кучу
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
//Обработка файла
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
 //Если папка, то дополнить путь до индексного файла
 if ppath[Length(ppath)]='\' then
  ppath:=ppath+'index.html';
 PAcc:=false;
 mp:=false;
 md:=0;
 if NPlugInst and (not Err) then
  PAcc:=MQueryProc(hmod, PartOP, OptOP, KAlive, PostOP, PChar(ppath));
 if (ppath[1]<>#13) and (not PAcc) then //Проверяем на спец-символ
  begin
   Assign(ThreadFl[i], ppath);
   //Безопасно открываем файл
{$I-}
   Reset(ThreadFl[i], 1);
{$I+}
   if IOResult<>0 then //Не получилось
    begin
     if DirectoryExists(ppath) then
      ppath:=ppath+'\' //Существует папка с тем же именем
     else
      begin            //Отправить 404 File Not Found
       OptOP:=false;
       if Err then
        ppath:=#13     //Не нашли error404.html. Юзаем спец-символ
       else
        begin
         LogMsg(llAll, i, Req+ppath); //Сообщаем, что был запрос на такой-то файл
         ppath:=val+'\error404.html'; //А сами ищем error404.html
        end;
       Err:=true;      //Была ошибка
      end;
     ProcessFile;      //Попробовать снова
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
 if PartOP and (not Err) and (ppath[1]<>#13) then  //Перебираем список
  begin
   if enofs=-1 then
    enofs:=tofs;
   //Некорректные данные?
   if (stofs<0) or (enofs>tofs) then
    PartOP:=false;  //Запретить использовать Range
   curr:=contr;
   while curr<>nil do
    begin
     //Исправляем данные
     if (curr^.EndR+2) in [1, 0] then
      begin
       if curr^.EndR=-2 then
        curr^.StartR:=tofs-curr^.StartR+1;
       curr^.EndR:=tofs;
      end;
     if (curr^.StartR>curr^.EndR) or (curr^.StartR<0) then
      PartOP:=false;                       //Некорректные данные
     curr:=curr^.Next;
     mp:=mp or (curr<>nil);
     inc(ac);
    end;
  end;
 if ((not PartOP) or (ppath[1]=#13)) and (contr<>nil) then       //Ошибка
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
 //Получаем главный заголовок
 if resph='' then  //Уже был установлен?
  if Err then      //А была ошибка?
   resph:='404 Not Found' //Да - файл не найден
  else
   if ppath[1]=#13 then   //Ошибок не было, а содержимое есть?
    resph:='204 No Content' //Установлен спец-символ - ничего не отправлять
   else
    begin
     if PartOP then //Используется Content-Range?
      resph:='206 Partial Content' //Да
     else
      resph:='200 OK'; //Просто файл
     LogMsg(llAll, i, Req+ppath); //Был запрос на такой-то файл
    end;
 //Формируем ответ
 Resp:=HttpV+' '+resph; //HTTP/1.X XXX XXXXXXX
 LogMsg(llNotice, i, 'Response: '+Resp); //Мы отвечаем вот это
 Resp:=Resp+nl+'Date: '+GetFormatedTime+nl+'Server: '+SERV+nl; //Информация о сервере (ID и дата)
 rcont:='';
 //Собщить о том, что поддерживает сервер?
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
   //Отправляем файл
   r:='';
   rcl:=tofs+1; //Размер содержимого
   if not Err then
    if not PAcc then
     begin //Сообщаем данные о файле и факт возможности использования Range
      Resp:=Resp+'Last-Modified: '+FormatSysTime(FileLastWriteDate(ppath))+nl;
      Resp:=Resp+acrc+'bytes'+nl;
     end
    else
   else //Использовать Range нельзя
    Resp:=Resp+acrc+'none'+nl;
   if PartOP then //Если используем Range
    if not mp then
     begin
      rcl:=contr^.EndR-contr^.StartR+1;
      Resp:=Resp+crb+IntToStr(contr^.StartR)+'-'+IntToStr(contr^.EndR)+'/'+IntToStr(tofs+1)+nl;
     end
    else
   else
    if rcl>0 then
     begin //Не используем Range
      new(contr); //Создаём имитацию Range
      contr^.StartR:=0;
      contr^.EndR:=rcl-1;
      contr^.Next:=nil;
      inc(ac);
     end;
   if OptOP then
    rcl:=0;
   if not PAcc then
    begin
     //Получаем расширение (всё до последней точки)
     for j:=Length(ppath) downto 1 do
      if ppath[j] in ['.', '\'] then
       break
      else
       r:=ppath[j]+r;
     if ppath[j]='.' then //Если добрались до точки
      begin
       Assign(Mime, 'mime.types');  //Открываем файл с mime
{$I-}
       Reset(Mime);
{$I+}
       if IOResult=0 then
        begin
         while not Eof(Mime) do
          begin  //Ищем наше расширение
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
     if rcont<>'' then //Нашли - отправляем
      Resp:=Resp+cnt+rcont+nl;
    end;
  end
 else
  if Err then
   Resp:=Resp+clst+'0'+nl; //Если есть спец-символ, то длина = 0
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
 //Отправляем ответ
 LogMsg(llAll, i, 'Sending response...');
 o:=0;
 if HeadOP or (OptOP and (not Err)) then //Не отправлять тело для HEAD и OPTIONS
  ac:=0;
 New(curr);          //Создаём данные для отправки заголовка
 curr^.Next:=contr;
 curr^.StartR:=-1;
 curr^.EndR:=-1;
 contr:=curr;
 inc(ac);
 Err:=false;
 while ac>0 do
  begin //Отправляем по частям
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
   if ms then   //Заголовок
    begin
     mr:=1;
     mc:=Length(Resp);
    end
   else         //Файл
    begin
     if PAcc then
      Err:=MSetPosProc(hmod, curr^.StartR)
     else
      Seek(ThreadFl[i], curr^.StartR); //Прыгаем на начало
     mr:=curr^.StartR;
     mc:=curr^.EndR;
    end;
   while (mc>=mr) and (not Err) do
    begin
     j:=4096-o; //Определяем максимальный размер
     sz:=mc-mr+1; //Определяем нужный размер
     if sz<j then //Если нам нужно меньше, то не юзаем лишнее
      j:=sz;
     if j>0 then
      if ms then       //Копируем заголовок в буфер
//       for t:=mr to j+mr do
//        buf[o+t]:=ord(Resp[t])
       move(Resp[mr], buf[o+mr], j)
      else
       begin           //Читаем файл в буфер
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
      begin //Не заполнили буфер. Надо дозаполнить
       inc(o, j);
       continue;
      end;
     if SendBuf(buf, j+o)<>(j+o) then
      begin //Потеряли информацию
       Err:=true;
       break;
      end;
     inc(asent, j);
     inc(asent, o);
     o:=0;
    end;
   if Err then
    break; //У нас ведь есть вложенный цикл
   curr:=curr^.Next;
  end;
 DeleteList;
 if ppath[1]<>#13 then
  Close(ThreadFl[i]); //Закрываем файл
 LogMsg(llNotice, i, 'OK. Result flag: '+IntToStr(ord(Err)*10+ord(FErr))); //Коетроль ошибки ввода/вывода
end;
//Плохой запрос
procedure BReq;
begin
 HttpV:='HTTP/1.1';
 resph:='400 Bad Request';
 ppath:=#13'error400.html';
end;
//Обработка метода GET
procedure GetOP;
var hn:String;
    IsHost:Boolean;
//Установка вхоста
procedure SetHost(val:String);
begin
 if IsHost then
  Exit; //Два раза установить хост нельзя. BUG VPSERVER 1.0
 ppath:=val+ppath;
 IsHost:=true;
 LogMsg(llNotice, i, 'Host: '+val);
end;
label h, f; //Пришлось использовать метки (чтобы не переписывать весь код)
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
  ppath:=copy(ppath, 1, Pos('?', ppath)-1); //Нам GET-параметры не нужны
 if Pos('#', ppath)<>0 then
  ppath:=copy(ppath, 1, Pos('#', ppath)-1); //Это в принципе не может быть, но бережённого Бог бережёт
 ReformStr(ppath); //BUG ALL VPSERVER - поддержка %xy
 IsHost:=false;
 if Pos('://', ppath)<>0 then //Поддержка абсолютного URL
  begin
   LogMsg(llNotice, i, 'Warning! Absolute URL!');
   Delete(ppath, 1, Pos('://', ppath)+3);
   val:=copy(ppath, 1, Pos('/', ppath)-1);
   Delete(ppath, 1, Pos('/', ppath));
   goto h; //Установить хост
  end;
 while true do
  begin
   FormNextStr; //Получаем следующую строку
   if r='' then
    break;      //EOF
   hn:=copy(r, 1, Pos(':', r)-1); //Название
   val:=copy(r, Pos(':', r)+2, Length(r)-Pos(':', r)-1); //Значение
   ReformStr(val); //BUG ALL VPSERVER - поддержка %xy
   PAcc:=false;
   if NPlugInst then
    begin     
     StrToBuf(val);
     PAcc:=MHeadProc(hmod, PChar(hn), PChar(@rbuf));
     BufToStr(val);
    end;
   if hn='Host' then
    begin  //Выбираем хост
h:   if ppath[1]=#13 then
      continue; //Была ошибка
     if Pos(':', val)<>0 then
      val:=copy(val, 1, Pos(':', val)-1); //Указан порт. Нам он не нужен
     DelStr(val, '\', 1);
     DelStr(val, '/', 1);
     //Это IP?
     if inet_addr(PChar(val))<>-1 then
      val:='localhost'; //Ссылаемся на default-хост
     SetHost(val); //Установить хост
     continue;
    end;
   if hn='User-Agent' then
    begin //Показать кто клиент
     LogMsg(llAll, i, 'User agent: '+val);
     continue;
    end;
   if hn='Referer' then
    begin //Показать откуда перешёл
     LogMsg(llAll, i, 'Referer: '+val);
     continue;
    end;
   if hn='From' then
    begin //Показать e-mail
     LogMsg(llAll, i, 'From: '+val);
     continue;
    end;
   if hn='Range' then
    begin //Установить Range
     if copy(val, 1, 6)<>'bytes=' then
      continue; //Кроме bytes мы ничего не поддерживаем
     //Удаляем лишнее
     Delete(val, 1, 6);
     DelStr(val, ' ', 1);
     DeleteList;
     //Перывый элемент
     new(curr);
     curr^.StartR:=-1;
     contr:=curr;
     lr:=nil;
     while val<>'' do
      begin
       //Получаем подстроку
       if Pos(',', val)<>0 then
        hn:=copy(val, 1, Pos(',', val)-1)
       else
        hn:=val;
       //Удаляем её из основной
       Delete(val, 1, Length(hn));
       if Length(val)<>0 then
        Delete(val, 1, 1); //Удаляем запятую
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
       lr^.Next:=curr;  //Следующий элемент
      end;
     //Удаляем лишний элемент
     Dispose(curr);
     if lr<>nil then
      lr^.Next:=nil
     else
      contr:=nil;
     //Фильтруем, а заодно считаем начало и конец
     lr:=nil;
     curr:=contr;
     stofs:=-1;
     enofs:=-1;
     while curr<>nil do
      if curr^.StartR=-1 then  //Лишний элемент
       if lr=nil then //В начале?
        begin
         contr:=curr^.Next;
         Dispose(curr);
         curr:=contr;
        end
       else
        begin //Нет?
         lr^.Next:=curr^.Next;
         Dispose(curr);
         curr:=lr^.Next;
        end
      else
       begin
        if (curr^.StartR<stofs) or (stofs=-1) then
         stofs:=curr^.StartR; //Обновляем начало
        if curr^.EndR>enofs then
         enofs:=curr^.EndR; //Обновляем конец
        lr:=curr;
        curr:=lr^.Next; //Следующий элемент
       end;
     if stofs<>-1 then //Есть начало?
      PartOP:=true; //Включаем Range
     continue;
    end;
   if hn='Connection' then
    begin  //Устанавливаем режим подключения
     if Pos('Keep-Alive', val)=1 then //Есть Keep-Alive
      KAlive:=true
     else
      if Pos('close', val)=1 then //Есть close
       KAlive:=false;
     if (val<>'close') and (val<>'Keep-Alive') then //Неизвесный тип
      LogMsg(llAll, i, 'FIXME: "Connection: '+val+'" Not supported connection mode');
     continue;
    end;
   if hn='Content-Length' then
    begin //Для метода POST
     if PostOP or OptOP or PAcc then  //Метод POST/OPTIONS?
      begin  //Да - устанавливаем длину
       PostCL:=StrToInt(val);
       continue;
      end;
     //Ошибка
     LogMsg(llNotice, i, 'Warning! Unexpected header! 400 Bad Request for safe end');
     ppath:=#13#10;
    end;
   if Pos('Accept', hn)=1 then
    continue; //Игнорируем все Accept-XXXX
   //Неизвестный заголовок
   if not PAcc then
    LogMsg(llAll, i, 'FIXME: "'+hn+': '+val+'" Header has been ignored');
  end;
 if FErr then //Ошибка IO
  begin
f: if GetLastError=0 then //Не было ошибки - превышен лимит ожидания
    LogMsg(llError, i, rtout);
   Exit;
  end;
 if ppath='' then //Длина строки не меньше 1
  ppath:='.';
 IsHost:=IsHost or (ppath[1]=#13);
 if (not IsHost) and (HttpV<>'HTTP/1.1') then //Указание Host необходимо только для HTTP1.1
  SetHost('localhost');
 //Ошибка если не установлен хост, неуместный заголовок для POST, отсутствие заголовка для POST
 if (not IsHost) or (PostOP and (PostCL=-1)) or (ppath=#13#10) then
  BReq;
 //Реальная страница?
 if ppath[1]<>#13 then
  begin //Да
   while Pos('/', ppath)<>0 do     //Заменяем / на \
    ppath[Pos('/', ppath)]:='\';
   DelStr(ppath, '\\', 1);         //Заменяеи \\ на \
   if ppath[1]<>'\' then           //От корня
    ppath:='\'+ppath;
   DelStr(ppath, '*', 1);          //Удаляем RegEx
   DelStr(ppath, '?', 1);
   while ppath[Length(ppath)]='.' do  //Отчистка '.' Thanks to Genix
    Delete(ppath, Length(ppath), 1);
   DelStr(ppath, '\..\', 3);       //От корня
  end
 else
  begin //Есть спец-симол
   PostOP:=false;                  //Не использовать POST
   Err:=not Err;                   //Ограниченное соединение
   Delete(ppath, 1, 1); //Удаляем спец-символ
   if ppath[1]<>#13 then
    ppath:='\'+ppath; //Добавляем \
  end;
 if PostCL<>-1 then
  begin //Метод POST/OPTIONS
   if o<sz then         //Читаем тело
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
 //Если ошибка сервера или 400 Bad Request, то делаем соединение закрытым
 if (Err and ((copy(resph, 1, 1)='5') or (copy(resph, 1, 3)='400'))) or FErr then
  begin
   LogMsg(llAll, i, 'Set connection mode to "close"');
   KAlive:=false;
  end;
 if FErr then
  goto f;
 GetDir(0, val); //В val наша Home папка
 if ppath[1]<>#13 then
  ppath:=val+ppath; //Мы из Home
 ProcessFile; //Обработка файла
end;
//Обработка запроса
procedure ProcessRequest;
var meth:String;
const GetMeth='GET';
//Извлечь путь к файлу
procedure FindPath;
begin
 ppath:=copy(r, Pos(' ', r)+1, Length(r)-Pos(' ', r)-9);
end;
begin
 //Инициализация (обнуление переменных)
 if UKAlive then
  LogMsg(llNotice, i, 'Keep-Alive mode! Waiting...');
 resph:='';
 sz:=0;
 o:=0;
 stofs:=0;
 FErr:=false;
 FormNextStr; //Заголовок запроса
 if FErr then
  begin
   if GetLastError=0 then  //Не было ошибки - превышен лимит ожидания
    if UKAlive then
     LogMsg(llNotice, i, 'Keep-Alive timeout')
    else
     LogMsg(llNotice, i, rtout);
   Exit;
  end;
 LogMsg(llAll, i, 'Processing request');
 UKAlive:=false;
 meth:=r;
 while Pos(' ', meth)<>0 do //Ищем пробелы
  begin
   Delete(meth, Pos(' ', meth), 1);
   inc(stofs);
  end;
 if meth='' then //Запрос пустой?
  begin
   LogMsg(llNotice, i, 'Request is empty');
   Exit;
  end;
 LogMsg(llNotice, i, 'Request: '+r);
 //Версия HTTP
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
 if (HttpV<>'HTTP/0.9') and (HttpV<>'HTTP/1.0') and (HttpV<>'HTTP/1.1') then //Странная версия HTTP
  begin //Сообщаем об этом
   HttpV:='HTTP/1.1';
   resph:='505 HTTP Version Not Supported';
   ppath:=#13'error505.html';
   meth:=GetMeth;
  end;
 if (resph='') and NPlugInst then
  MLoadMeth(hmod, PChar(meth));
 if meth='HEAD' then //Метод HEAD. Просто не отправлять содержимого
  begin
   HeadOP:=true;
   meth:=GetMeth;
  end;
 if meth='POST' then //Метод POST
  begin
   PostOP:=true;
   meth:=GetMeth;
  end;
 if (meth=GetMeth) and (resph='') then //Метод GET - найти файл
  FindPath;
 if (meth='PUT') or (meth='PATCH') or (meth='DELETE') or (meth='TRACE') or (meth='CONNECT') or (meth='LINK') or (meth='UNLINK') then
  begin //Методы недопустимы!
   resph:='405 Method Not Allowed';
   ppath:=#13'error405.html';
   meth:=GetMeth;
   OptOP:=true;
  end;
 if meth='OPTIONS' then
  begin //Нужно только показать, что мы можем
   FindPath;
   if Pos('*', ppath)<>0 then
    begin
     ppath:=#13#13;
     Err:=true;
    end;
   meth:=GetMeth;
   OptOP:=true;
  end;
 //Пора изменить метод на GET
 if stofs<>2 then
  meth:=GetMeth;
 PAcc:=meth=GetMeth;
 if (not PAcc) and NPlugInst then
  PAcc:=MMethProc(hmod, PChar(meth));
 if not PAcc then //Это не GET?
  begin //Я такого метода не знаю
   resph:='501 Not Implemented';
   ppath:=#13'error501.html';
   OptOP:=true;
  end
 else
  if NPlugInst then
   FindPath;
 contr:=nil;
 GetOP; //Обработка метода
end;
var le:LongWord;
//Начало потока
begin
 Result:=0; //По умолчанию Return = 0
 i:=Index^; //Наш номер
 Dispose(Index);
 try
  LogMsg(llAll, i, 'Listening...');
  wholen:=sizeof(sockaddr_in);
  ThreadSock[i]:=accept(ListenSocket, @who, @wholen); //Ждём...
  if wholen<>sizeof(sockaddr_in) then //Ошибка в WS2_32.DLL
   begin
    LogMsg(llError, i, 'Internal error!');
    MyQuit(1);
   end;
  LogMsg(llNotice, i, 'The client is accepted ('+IntToStr(ThreadSock[i])+') from '+inet_ntoa(who.sin_addr));
  ThreadBusy[i]:=true; //Мы заняты
  CheckThreads(i); //А есть свободные?
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
     ProcessRequest; //Обработка запроса
     if NPlugInst then
      MRelProc(hmod);
     UKAlive:=true;
    until not KAlive;
   end;
  le:=GetLastError;
  LogMsg(llAll, i, 'Sent: '+IntToStr(asent)+' bytes; received: '+IntToStr(arecv)+' bytes'); //Статистика
  LogMsg(llAll, i, 'Closing socket '+IntToStr(ThreadSock[i]));
  if closesocket(ThreadSock[i])=SOCKET_ERROR then //Закрываем сокет
   LogMsg(llError, i, 'Error '+IntToStr(WSAGetLastError)+': '+SysErrorMessage(WSAGetLastError));
  SetLastError(le); //Игнорирум ошибки
  ThreadSock[i]:=0;
  CheckThreads(i); //Проверить на свободные потоки
 finally
  if GetLastError<>0 then //Была ошибка?
   LogMsg(llError, i, 'Raised exception! Error '+IntToStr(GetLastError)+': '+SysErrorMessage(GetLastError));
{$I-}
  Close(ThreadFl[i]); //Мы не закрыли файл?
{$I+}
  if IOResult=0 then
   LogMsg(llNotice, i, fhsbc); //И правда не закрыли
  //Нас нет
  LogMsg(llNotice, i, 'Terminating');
  InterlockedDecrement(PInteger(@ThreadBe[i])^);
  InterlockedDecrement(ThreadCount);
 end;
end;

//Завершить все потоки
procedure TerminateAllThreads(s:Integer);
var i:Integer;
    e:LongWord;
begin
 while true do
  begin
   //Ждём...
   WaitForSingleObject(TerminateAllThreadsLockE, INFINITE);
   if InterlockedIncrement(TerminateAllThreadsLock)=1 then
    break;
   //Не наша очередь
   InterlockedDecrement(TerminateAllThreadsLock);
  end;
 //Пусть нас ждут
 if not ResetEvent(TerminateAllThreadsLockE) then
  Panic;
 e:=0;
 for i:=1 to MAX_L do
  if ThreadBe[i] and (ThreadID[i]<>GetCurrentThreadID) then
   begin //Себя не завершаем
    if (e<>GetLastError) and (GetLastError<>0) then
     e:=GetLastError; //В e последняя ошибка
    //Сначала приостановим поток
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
    Close(ThreadFl[i]); //Он не успел закрыть файл?
{$I+}
    if IOResult=0 then
     LogMsg(llAll, s, fhsbc); //Мы его закрыли
    if ThreadSock[i]<>0 then //Он не закрыл сокет
     if (closesocket(ThreadSock[i])=SOCKET_ERROR) and (not CloseHandle(ThreadSock[i])) then
      LogMsg(llError, s, 'Can''t close socket! Error '+IntToStr(WSAGetLastError)+': '+SysErrorMessage(WSAGetLastError))
     else
      LogMsg(llAll, s, 'Socket of thread '+IntToStr(i)+' has been closed');
    if not (TerminateThread(ThreadHnd[i], INFINITE) or CloseHandle(ThreadHnd[i])) then
     begin //Не получается завершить? Пусть просто висит
      LogMsg(llError, s, 'Can''t terminate thread! Error '+IntToStr(GetLastError)+': '+SysErrorMessage(GetLastError));
      continue;
     end;
    //Теперь его нет
    LogMsg(llNotice, s, 'Thread '+IntToStr(i)+' has been terminated');
    InterlockedDecrement(PInteger(@ThreadBe[i])^);
    InterlockedDecrement(ThreadCount);
   end;
 //Вдруг была ошибка?
 if e<>0 then
  SetLastError(e);
 //Следующий!
 if not SetEvent(TerminateAllThreadsLockE) then
  Panic;
 TerminateAllThreadsLock:=0;
end;

//Создать новый поток
procedure CreateThreadListener(f:Integer);
procedure InternalProc(c:Integer);
var i, j:Integer;
    p:^Integer;
const s=-2;
begin
 //Ищем свободный поток
 i:=-1;
 for j:=1 to MAX_L do
  if not ThreadBe[j] then
   begin
    i:=j;
    break;
   end;
 if i=-1 then
  begin //Не нашли
   if c=5000 then
    begin //Уже 5 сиунд ждём
     LogMsg(llError, s, 'Request has not been processed for 5 seconds! Terminating threads!');
     TerminateAllThreads(s); //Вырубить всё на...
     Exit;
    end;
   //Пока ждём...
   if c=0 then
    LogMsg(llError, s, 'Number of threads exceeds the limit. Check your computer to a network attack');
   LogMsg(llAll, s, 'Waiting for a second...');
   Sleep(1000);
   LogMsg(llAll, s, 'Trying again');
   InternalProc(c+1000); //Новая попытка
   Exit;
  end;
 //Создаём новый поток
 LogMsg(llNotice, s, 'Starting new thread (number '+IntToStr(i)+')');
 //Регистрируем его
 new(p);
 p^:=i;
 InterlockedIncrement(ThreadCount);
 j:=InterlockedIncrement(PInteger(@ThreadBe[i])^) and $FF;
 ThreadBusy[i]:=false;
 ThreadHnd[i]:=BeginThread(nil, 0, @ThreadProc, p, 4, ThreadID[i]);
 if (ThreadHnd[i]<>0) and (j=1) then
  begin //Запускаем поток
   ThreadSock[i]:=0;
   LogMsg(llAll, s, 'Resuming thread '+IntToStr(i));
   if ResumeThread(ThreadHnd[i])<>INFINITE then
    Exit;
  end;
 //Была ошибка. Возвращаем всё обратно
 InterlockedDecrement(PInteger(@ThreadBe[i])^);
 InterlockedDecrement(ThreadCount);
 LogMsg(llError, s, 'Error '+IntToStr(GetLastError)+'! '+SysErrorMessage(GetLastError));
 if ThreadHnd[i]<>0 then
  begin //Надо его завершить
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

{=======Основная программа=======}

//Нолик к числу
function MIntToStr(i:Integer):String;
begin
 if i>9 then
  Result:=IntToStr(i)
 else
  Result:='0'+IntToStr(i);
end;

//Форматировать системное время
function FormatSysTime(t:TSystemTime):String;
const dow:array[0..6] of String = ('Sun', 'Mon', 'Tus', 'Wed', 'Thu', 'Fri', 'Sat');
const mon:array[1..12] of String = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
//Формат по RFC2068
begin
 Result:=dow[t.wDayOfWeek]+', '+IntToStr(t.wDay)+' '+mon[t.wMonth]+' '+
         IntToStr(t.wYear)+' '+MIntToStr(t.wHour)+':'+MIntToStr(t.wMinute)+':'+
         MIntToStr(t.wSecond)+' GMT';
end;

var t:TSystemTime;
    tlock:Integer=0;

//Получить системное время
procedure GetSystemTime_;
begin
 if InterlockedIncrement(tlock)=1 then
  GetSystemTime(t);
 InterlockedDecrement(tlock);
end;

//Получить дату и время
function GetCurDateTime:String;
//Формат по России
begin
 GetSystemTime_;
 Result:=MIntToStr(t.wDay)+'.'+MIntToStr(t.wMonth)+'.'+IntToStr(t.wYear)+' '+
         MIntToStr(t.wHour)+':'+MIntToStr(t.wMinute)+':'+MIntToStr(t.wSecond);
end;

//Открываем лог
procedure OpenLog(var F:Text;path:String);
begin
 Assign(F, path);
{$I-}
 Append(F);
{$I+}
 if IOResult<>0 then
  begin //Файла не существует?
{$I-}
   Rewrite(F);
{$I+}
   if IOResult<>0 then
    begin //Не могу создать
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

//Паника
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

//Получить имя файла по номеру потока
function FormLogFile(i:Integer):String;
begin
 Result:=flpath+'\Thread'+IntToStr(i)+'.log';
end;

//Получить форматированное время
function GetFormatedTime:String;
begin
 GetSystemTime_;
 Result:=FormatSysTime(t);
end;

//Добавить в лог
procedure LogMsg(lev:LogLev;from:Integer;msg:String);
var fromstr, logstr:String;
begin
 //Блокировка по тому же принципу, что и в TerminateAllThreads
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
 case from of //Откуда сообщение?
  -1: fromstr:='SYSTEM';
  -2: fromstr:='CreateThreadListener';
 else
  fromstr:='Thread '+IntToStr(from);
 end;
 if ord(lev)>=ord(fll) then //Выводить в файл
  begin
   logstr:=' -- '+GetCurDateTime+' '+fromstr+': '+msg;
   writeln(F, logstr); //Общий лог
   if from>0 then
    writeln(ThreadLog[from], logstr) //Лог потока
   else
    writeln(SysLog, logstr); //Лог системы
  end;
 if consolev then
  if ord(lev)>=ord(cll) then
   begin
    msg:=msg+#13#10;
    if InterlockedIncrement(SHOWCON)<>1 then
     msg:=msg+'>';
    InterlockedDecrement(SHOWCON);
    write(#13+fromstr+': '+msg); //На экран
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

//Ожидание
procedure MyWait;
const WAIT='Waiting...';
begin
 write(WAIT); //Выводим
 Sleep(4500); //Ждём
 write(#13, ' ':Length(WAIT), #13); //Удаляем
 Sleep(500);  //Дожидаем
 writeln;
end;

var LEP:Pointer;

//Безопасный выход
procedure MyExit(ReturnCode:Integer);
var k:Integer;
    le:LongWord;
begin
 le:=GetLastError;
 TerminateAllThreads(SYS); //Завершаем потоки
 LogMsg(llError, SYS, 'Exit code: '+IntToStr(ReturnCode));
 LogMsg(llError, SYS, 'Error code: '+IntToStr(le));
 //Закрываем логи
 Close(F);
 Close(SysLog);
 for k:=1 to MAX_L do
  Close(ThreadLog[k]);
 //Закрываем сокет
 closesocket(ListenSocket);
 MyWait;
 ExitProc:=LEP;
end;

//Неожиданное завершение
procedure WExit;
begin
 Panic_;
 LogMsg(llError, SYS, 'Fatal error at: '+IntToStr(LongWord(ErrorAddr)));
 MyExit(ExitCode);
end;

//Безопасный выход
procedure MyQuit(ReturnCode:Integer);
begin
 //Выход из потока
 LogMsg(llError, SYS, 'DoHalt command!');
 MyExit(ReturnCode);
 Halt(ReturnCode);
end;

//Аварийный выход
procedure MyHalt(ReturnCode:Integer);
begin
 //Даже не успели загрузиться
 MyWait;
 Halt(ReturnCode);
end;

//Показать лого
procedure ShowLogo;
//Выводим пробелы
procedure ShowSpace;
begin
 write(' ':(((80-Length(SERV)-2) div 2)-1));
end;
//Выводим ><
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
 write('>'+SERV+'<'); //Выводим название
 writeln;
 ShowSubLogo;
end;

var Data:WSADATA;        //Данные о WS2_32.DLL
    Port:Word;           //Порт
    service:sockaddr_in; //Адрес сокета

const
 rset:array[1..7] of String=('Port=', 'IP=',  'ListenersAmount=', 'ConsoleLogLevel=', 'FileLogLevel=', 'Keep-Alive-Timeout=', 'Read-Timeout=');

//Записать новые настройки
procedure WriteNewConf;
var rans:array[1..7] of String;
    n:Byte;
//Запросить с клавиатуры
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
 //Все настройки по default
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
  begin //Не могу записать конфиг? Просто спрошу
   writeln('Can''t write config file');
   PromptConf;
   Exit;
  end;
 //Может всё по default?
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
  PromptConf //Спрошу
 else
  flpath:=rans[2];
 for n:=1 to 7 do
  writeln(F, rset[n], rans[n]); //Пишем
 Close(F); //OK
end;

//Чтение конфига
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
   readln(F, mt); //Получаем строку
   //Удаляем лишние символы
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
   if mt='' then //Пустая строка
    continue;
   for n:=1 to 7 do //Ищем параметр
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
      begin //Не нашли
       writeln('Error at config file! (Line ', ln , ')');
       MyHalt(3);
      end;
  end;
 Close(F); //Закрываем файл
end;

begin
 SetErrorMode(1);
 //Устанавливаем Home как папку, в которой лежит Server.exe
 flpath:=ParamStr(0);
 while (Length(flpath)>0) and (flpath[Length(flpath)]<>'\') do
  Delete(flpath, Length(flpath), 1);
 ChDir(flpath);
 //Показать лого
 ShowLogo;
 //Показать баннер
 writeln(#13#10'--------------------------------'#13#10'Copyright (c) 2009 Ivanov Viktor'#13#10'--------------------------------'#13#10#13#10'Loading...');
 //Установка default-значений переменных
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
 //Ищем config.conf
 Assign(F, 'config.conf');
{$I-}
 Reset(F);
{$I+}
 if IOResult<>0 then
  WriteNewConf //Нет - создать
 else
  ReadConf;
 Sleep(200);
 writeln('Initialization...');
 if WSAStartUp(514, @Data)<0 then //Winsock 2.2
  begin
   writeln('Unsupported version of WinSock!');
   MyHalt(2);
  end;
 //Создаём сокет
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
 //Готово. Внимание! Не закрывать приложение с помощью окна!
 writeln(#13#10'Don''t close this window! Enter QUIT to safe exit');
 //Ждём...
 MyWait;
 //Ищем папку для логов
 flpath:=GetEnvironmentVariable('APPDATA');
 if flpath[Length(flpath)]<>'\' then
  flpath:=flpath+'\';
 flpath:=flpath+'VPSERVER';
 if not DirectoryExists(flpath) then
  MkDir(flpath); //Такой нет - создать
 if not DirectoryExists(flpath) then
  begin //Всё равно нет? Не могу создать
   writeln('Error! Can''t create directory!');
   MyHalt(1);
  end;
 //Онуляем переменные
 ThreadCount:=0;
 FillChar(ThreadBe, MAX_L*sizeof(Boolean), 0);
// FillChar(ThreadBusy, MAX_L*sizeof(Boolean), 0);
// FillChar(ThreadID, MAX_L*sizeof(LongWord), 0);
// FillChar(ThreadHnd, MAX_L*sizeof(LongWord), 0);
 //Открываем логи
 OpenLog(F, flpath+'\log.log');
 OpenLog(SysLog, flpath+'\sys.log');
 for i:=1 to MAX_L do
  OpenLog(ThreadLog[i], FormLogFile(i));
 //Вывод основной информации
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
 //Запуск потоков
 CheckThreads(SYS);
 flpath:='';
 while flpath<>'QUIT' do
  begin
   if InterlockedIncrement(SHOWCON)=1 then
    write('>');
   readln(s); //Ждём ENTER
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
 MyExit(0); //Выход
end.
