unit SBase;

interface

{Переключатель отладочного режима сервера}
//{$DEFINE DEBUG_MODE1}

uses STypes;

{Определить режим запуска}
function LoadMode:TMode;
{Показывать лого}
procedure ShowLogo;
{Загрузить кофигурацию}
procedure LoadConfig(out Conf:TConfig);
{Запустить серверы}
procedure StartServers(const Config:TConfig;out Servers:TServers);
{Запустить диалог}
procedure StartDialogAndWait(var Config:TConfig;var Servers:TServers);
{Остановить серверы}
procedure StopServers(var Servers:TServers);
{Прочитать настройки сервера}
procedure ReadSettings(out Settings:TSettings);
{Выполнить команды}
procedure ExecuteCommands(var Settings:TSettings);

implementation

uses SUtils, SLog, PipeUtils, WSUtils, HTTP11, {$IFDEF MSWINDOWS}Windows{$ENDIF};

{Определить режим запуска}
function LoadMode:TMode;
var
 i:LongWord;
 s:String;
begin
 if ParamCount=1 then
  begin {Проверить подлинность}
   LoadMode:=mUnk;
   {Спросить MD5 произвольного числа}
   i:=Random(255);
   writeln(i);
   readln(s);
   if s<>GetMD5(i, sizeof(i)) then
    Exit;
   {Спросить MD5 режима}
   i:=StrToInt(ParamStr(1));
   readln(s);
   if (s<>GetMD5(i, sizeof(i))) or (TMode(i)<>mServer) then
    Exit;
   {Всё полинность подтверждена}
   LoadMode:=TMode(i);
   writeln(OKMsg);
{$IFDEF MSWINDOWS}
   {Указание режима для отладки}
   SetConsoleTitle(PChar('Server Mode: '+ParamStr(1)));
{$ENDIF}
   Exit;
  end
 else
  begin {Нет параметров запуска}
{$IFDEF DEBUG_MODE1}
   LoadMode:=mServer; {Отладка сервера}
{$ELSE}
   LoadMode:=mMain; {Запуск главного окна}
{$ENDIF}
   Exit;
  end;
 {Сообщить об ошибке распознавания}
 writeln(BADMsg);
end;

{Показать лого}
procedure ShowLogo;

  {Вывести пробелы}
  procedure ShowSpace;
  begin
   write(' ':(((80-Length(SERV)-2) div 2)-1));
  end;

  {Вывести ><}
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
 SetConsoleTitle(PChar(SERV)); {Устанавливаем заголовок окна}
{$ENDIF}
{Выводим лого}
 ShowSubLogo;
 ShowSpace;
 write('>'+SERV+'<'#13#10);
 ShowSubLogo;
{Выводим доп. текст}
 writeln(#13#10, LogoText);
 Sleep(200);
end;

{----------------------Config procs}

{Устанавливить команды запуска}
function SetStartupCommands(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetStartupCommands:=true;
 if val='' then
  begin
   {Заголовок секции}
   Wait:=true;
   Exit;
  end;
 {Добавляем команду}
 Conf.StartupCom:=Conf.StartupCom+val+#10;
 inc(Conf.StartupNum);
end;

{Устанавливить команды выхода}
function SetEndCommands(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetEndCommands:=true;
 if val='' then
  begin
   {Заголовок секции}
   Wait:=true;
   Exit;
  end;
 {Добавляем команду}
 Conf.EndCom:=Conf.EndCom+val+#10;
 inc(Conf.EndNum);
end;

{Установить домашнюю папку}
function SetHomeDir(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetHomeDir:=false;
 if curserv=nil then
  Exit; {Не в секции сервера}
 {Извлекаем %%}
 curserv^.Params.HomeDir:=ExpandEnvString(val);
 SetHomeDir:=true;
end;

{Установить IP сервера}
function SetIP(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetIP:=false;
 if curserv=nil then
  Exit; {Не в секции сервера}
 curserv^.Params.IP:=val;
 SetIP:=true;
end;

{Установить порт сервера}
function SetPort(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetPort:=false;
 if curserv=nil then
  Exit; {Не в секции сервера}
 curserv^.Params.Port:=StrToInt(val);
 SetPort:=true;
end;

{Установить уровень журналирования}
function SetLogLevel(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetLogLevel:=false;
 if (curserv=nil) or (Length(val)<>1) or (not (val[1] in ['0'..'2'])) then
  Exit; {Неправильная строка}
 curserv^.Params.LogLevel:=ord(val[1])-ord('0');
 SetLogLevel:=true;
end;

{Установить таймаут соединения}
function SetReadWait(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetReadWait:=false;
 if curserv=nil then
  Exit; {Не в секции сервера}
 curserv^.Params.RWait:=StrToInt(val);
 SetReadWait:=true;
end;

{Установить таймаут Keep-Alive соединения}
function SetKATimeout(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
begin
 SetKATimeout:=false;
 if curserv=nil then
  Exit; {Не в секции сервера}
 curserv^.Params.KAWait:=StrToInt(val);
 SetKATimeout:=true;
end;

{Установить секцию сервера}
function SetServer(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
var
 ServerName:String;
 tempsrv:PServerRecord;
begin
 SetServer:=false;
 if val[Length(val)]<>']' then
  Exit; {Неправильно записанная секция}
 ServerName:=val;
 {Получаем имя сервера}
 SetLength(ServerName, Length(ServerName)-1);
 {Ищем сервер}
 tempsrv:=Conf.ServerRecords;
 while tempsrv<>nil do
  begin
   if tempsrv^.Params.Name=ServerName then
    break;
   tempsrv:=tempsrv^.Next;
  end;
 if tempsrv=nil then
  begin {Не нашли}
   New(curserv);
   if Conf.ServerRecords=nil then
    Conf.ServerRecords:=curserv {Первый сервер}
   else
    begin {Добавляем сервер в кучу}
     tempsrv:=Conf.ServerRecords;
     while tempsrv^.Next<>nil do
      tempsrv:=tempsrv^.Next;
     tempsrv^.Next:=curserv;
    end;
   tempsrv:=curserv;
   tempsrv^.Next:=nil;
   if Conf.Main<>nil then
    tempsrv^.Params:=Conf.Main^.Params {Применяем параметры сервера Main}
   else
    with tempsrv^.Params do
     begin {Применяем дефолтные параметры}
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
  curserv:=tempsrv; {Устанавливаем текущий сервер}
 if ServerName='Main' then
  Conf.Main:=tempsrv;
 SetServer:=true;
end;

{-------------------------------End}

{Загрузить кофигурацию}
procedure LoadConfig(out Conf:TConfig);
var
 curserv:PServerRecord;
 Wait:Boolean;
 ind:Integer;
type
 TConfProc=function(var Conf:TConfig;var curserv:PServerRecord;val:String;var Wait:Boolean):Boolean;
const
 PRCS=9;
 {Список строк}
 ParseVals:array[0..PRCS-1] of String=(
  '[Server=', 'HomeDir=', 'IP=', 'LogLevel=', 'Port=', 'ReadWait=',
  'KeepAliveTimeout=', '[StartupCommands]', '[EndCommands]'
 );
 {Список обработчиков}
 ParseProc:array[0..PRCS-1] of TConfProc=(
  SetServer, SetHomeDir, SetIP, SetLogLevel, SetPort, SetReadWait,
  SetKATimeout, SetStartupCommands, SetEndCommands
 );
  {Парсить строку}
  function ParseLine(const val:String):Boolean;
  var
   newval:String;
  begin
   ParseLine:=false;
   Wait:=false;
   {Обрабатываем строку}
   newval:=val;
   while Pos('[ ', newval)=1 do
    Delete(newval, 2, 1);
   while Pos(' ]', newval)=(Length(newval)-1) do
    Delete(newval, Length(newval)-1, 1);
   if Pos(' =', newval)<>0 then
    Delete(newval, Pos(' =', newval), 1);
   if Pos('= ', newval)<>0 then
    Delete(newval, Pos('= ', newval)+1, 1);
   {Ищем обработчик}
   if Pos('=', newval)<>0 then
    ind:=IndexStr(copy(newval, 1, Pos('=', newval)), ParseVals)
   else
    if (newval[Length(newval)]=']') and (newval[1]='[') then
     ind:=IndexStr(newval, ParseVals)
    else
     Exit;
   if ind<0 then
    Exit;
   {Запускаем обработчик}
   Delete(newval, 1, Length(ParseVals[ind]));
   ParseLine:=ParseProc[ind](Conf, curserv, newval, Wait);
  end;

var
 F:Text;
 s:String;
 r:Boolean;
 Line:LongWord;
begin    
 ConsoleLog('Читаю настройки...');
 FillChar(Conf, sizeof(Conf), 0);
 {Открываем файл}
 Assign(F, 'config.conf');
 FileMode:=0;
{$I-}
 FileMode:=0;
 Reset(F);
{$I+}
 if IOResult<>0 then
  begin
   ConsoleLog('Error: не могу открыть файл кофигурации');
   MyHalt(2);
   Exit;
  end;
 {Сбрасываем настройки}
 curserv:=nil;
 Line:=0;
 r:=true;
 Wait:=false;
 {Читаем файл}
 while not Eof(F) do
  begin
   inc(Line);
   readln(F, s);
   {Обрабатываем строку}
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
 {Запрет на изменение файла}
// Close(F);
 if r then
  Exit;
 {Сообщаем об ошибке}
 writeln('Error: не могу обработать файл конфигурации (Строка '+IntToStr(Line)+')');
 MyHalt(1);
end;

{Найти сервер в куче}
function FindServer(const Records:PServerRecord;const Name:String):Integer;
var T:PServerRecord;
    C:Integer;
begin
 FindServer:=-1;
 T:=Records;
 C:=0;
 {Перечисляем кучу}
 while T<>nil do
  begin
   inc(C);
   if T^.Params.Name=Name then
    begin {Нашли}
     FindServer:=C;
     Exit;
    end;
   T:=T^.Next;
  end;
end;

{Получить данные о сервере по номеру}
function GetServerData(const Servers:TServers;const Num:Integer):PServerData;
begin
 GetServerData:=nil;
 if (Num<0) or (LongWord(Num)>Servers.Count) then
  Exit; {Неправильный номер}
 GetServerData:=PServerData(Pointer(@membuf(Servers.Arr)^[(Num-1)*sizeof(PServerData)+1])^);
end;

{Записать настройки сервера в файл}
procedure WriteSettings(var F:TextFile;const Settings:TSettings); forward;

{Запустить серверов}
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
 ConsoleLog('Создаю серверы...');
 {Сбрасываем данные}
 FillChar(Servers, sizeof(Servers), 0);
 P:=Config.ServerRecords;
 Servers.Count:=Config.AmServers;
 GetMem(Servers.Arr, Servers.Count*sizeof(PServerData));
 FillChar(Servers.Arr^, Servers.Count*sizeof(PServerData), 0);
 o:=0;
 {Перечисляем кучу}
 while P<>nil do
  begin
   {Запускаем процесс}
   if WinExecWithPipe(ParamStr(0)+' '+IntToStr(ord(mServer)), {$IFDEF MSWINDOWS}SW_HIDE{$ELSE}0{$ENDIF}, Pipe, PI)=0 then
    begin
     New(L);
     FillChar(L^, sizeof(L^), 0);
     if OpenPipe(L^.PipeIn, L^.PipeOut, Pipe)=0 then
      begin {Удачный запуск}
       L^.Params:=@P^.Params;
       L^.PI:=PI;
{$I-}
       {Доказываем подлинность}
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
      begin {Удаляем процесс}
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
       {Передаём настройки}
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
 NoEPar='Команда введена неверно';
 UnkSer='Неизвестный сервер: ';
 CantS='Невозможно запустить сервер ';
 SerIsNot=': сервер не создан';

{Команда HELP}
function HelpFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
begin
 ConsoleLog('Справка находится в файле README.TXT');
 HelpFunc:=0;
end;

{Команда START}
function StartFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
var
 Num:Integer;
 L:PServerData;
 Res:LongWord;
begin
 StartFunc:=1; 
 if Param='' then
  begin {Нет параметра}
   ConsoleLog(NoEPar);
   Exit;
  end;
 {Ищем сервер}
 Num:=FindServer(Config.ServerRecords, Param);
 if Num<0 then
  begin {Не нашли}
   ConsoleLog(UnkSer+Param);
   Exit;
  end;
 {Получаем данные}
 L:=GetServerData(Servers, Num);
 if L=nil then
  begin {Данных нет}
   ConsoleLog(CantS+Param+SerIsNot);
   Exit;
  end;
 {Проверяем состояние}
 if L^.IsStart then
  begin
   ConsoleLog('Сервер '+Param+' уже запущен');
   Exit;
  end;
 with L^.Params^ do {Открываем порт}
  Res:=ListenPort(IP, Port, Sock);
 if Res<>0 then
  begin {Не открыли}
   ConsoleLog(CantS+Param+': сокет не может быть создан');
   StartFunc:=Res;
   Exit;
  end;
 with L^.Params^ do {Копируем сокет для сервера}
  Res:=DuplicateSocket(Sock, L^.PI.dwProcessId, Info);
 if Res<>0 then
  begin {Не получилось}
   StopConnection(L^.Params^.Sock);
   ConsoleLog(CantS+Param+': ошибка при передаче сокета серверу');
   StartFunc:=Res;
   Exit;
  end;
{$I-}
 {Запускаем сервер}
 writeln(L^.PipeOut, TCommandOrd(cmStart));
 for Res:=1 to sizeof(L^.Params^.Info) do
  writeln(L^.PipeOut, membuf(@L^.Params^.Info)^[Res]);
 readln(L^.PipeIn, Res);
{$I+}
 {Проверка на ошибки}
 if Res=0 then
  Res:=IOResult
 else
  IOResult;
 L^.IsStart:=Res=0;
 if L^.IsStart then {Всё ОК}
  ConsoleLog('Сервер '+Param+' запущен')
 else
  begin {Есть ошибка}
   StopConnection(L^.Params^.Sock);
   ConsoleLog(CantS+Param+': ошибка сервера');
  end;
 StartFunc:=Res;
end;

{Команда STOP}
function StopFunc(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
var
 Num:Integer;
 L:PServerData;
 Res:LongWord;
begin
{Проверки те же, что и в START}
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
   ConsoleLog('Невозможно остановить сервер '+Param+SerIsNot);
   Exit;
  end;   
 if not L^.IsStart then
  begin
   ConsoleLog('Сервер '+Param+' не запущен');
   Exit;
  end;
 {Закрываем порт}
 StopConnection(L^.Params^.Sock);
{$I-}
 {Останавливаем сервер}
 writeln(L^.PipeOut, TCommandOrd(cmStop));
 readln(L^.PipeIn, Res);
{$I+}
 {Проверка на ошибки}
 if Res=0 then
  Res:=IOResult
 else
  IOResult;
 if Res<>0 then
  begin {Сообщаем об ошибке}
   ConsoleLog('Произошла ошибка на стороне сервера '+Param);
   ConsoleLog('Сервер '+Param+' работает нестабильно. Рекомендуется его перезапустить');
  end;
 L^.IsStart:=false;
 ConsoleLog('Сервер '+Param+' остановлен');
 StopFunc:=Res;
end;

{-------------------------------End}

{Запустить диалог}
procedure StartDialogAndWait(var Config:TConfig;var Servers:TServers);
type
 ComFunc=function(Param:String;var Config:TConfig;var Servers:TServers):LongWord;
const
 ACOM=3;
 {Список команд}
 coms:array[0..ACOM-1] of String=(
  'HELP', 'START', 'STOP'
 );
 {Список обработчиков}
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
 ConsoleLog('Запуск командной строки...');
 {Подготовка к диалогу}
 StartDialog;
 P1:=@Config.StartupNum;
 P2:=@Config.StartupCom;
 while true do
  begin
   if P1^>0 then
    begin {Выполнить команду из списка}
     Param:=copy(P2^, 1, Pos(#10, P2^)-1);
     Delete(P2^, 1, Length(Param)+1);
     WriteInputLine(Param);
     dec(P1^);
    end
   else
    if P1=@Config.EndNum then
     break {Выходим}
    else
     Param:=GetInputLine; {Читаем команду}
   if Param='' then
    continue; {Нет команды}
   {Обрабатываем строку}
   if Pos(' ', Param)<>0 then
    Com:=copy(Param, 1, Pos(' ', Param)-1)
   else
    Com:=Param;
   Delete(Param, 1, Length(Com));
   Crop(Param);
   Com:=UpString(Com);
   if Com='QUIT' then
    begin {Переключаем списки}
     P1:=@Config.EndNum;
     P2:=@Config.EndCom;
     continue;
    end;
   {Ищем команду}
   I:=IndexStr(Com, coms);
   if I<0 then {Не нашли}
    ConsoleLog('Error: неизвестная команда')
   else
    begin
     {Выполняем}
     R:=comp[I](Param, Config, Servers);
     if R<>0 then
      ConsoleLog(Com+': Ошибка '+IntToStr(R));
    end;
  end;
 {Сообщаем SLog, что мы отключаем дивлог}
 StopDialog;
end;

{Удалить серверы}
procedure StopServers(var Servers:TServers);
var
 I:LongWord;
 L:PServerData;
begin
 ConsoleLog('Удаляю серверы...');
 {Перечисляем кучу}
 for I:=1 to Servers.Count do
  begin
   L:=GetServerData(Servers, I);
   if L=nil then
    continue;
{$I-}
   {Отправляем команду выхода}
   writeln(L^.PipeOut, TCommandOrd(cmQuit));
   Close(L^.PipeOut);
   Close(L^.PipeIn);
{$I+}
   IOResult;
{$IFDEF MSWINDOWS}
   {Завершае программу}
   if WaitForSingleObject(L^.PI.hProcess, TermTimeout)=WAIT_TIMEOUT then
    TerminateProcess(L^.PI.hProcess, INFINITE); {Принудительно}
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

{Записать параметры}
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
 ClientThreads:Integer=0; {Счётчик потоков}

{Прочитать параметры}
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

{Поток обработки запроса}
function ProccessThread(P:Pointer):Integer;
var
 Settings:PSettingsRecord absolute P;
begin
 ProccessThread:=0;
 try
  {Запуск обработки}
  ProccessRequest(Settings^.Socket, @Settings^.Settings^.Params);  
 except
  MessageBeep(MB_ICONHAND);
 end;
 {Удаляем поток и сокет}
 StopConnection(Settings^.Socket);
 Dispose(Settings);
 InterlockedDecrement(ClientThreads);
end;

{Найти место для нового потока}
function FindNewTID(var Tids:Pointer):PThreadID;
var s, p, t:LongWord;
    N:Pointer;
    i:Boolean;
begin
 if Tids=nil then
  begin {Первый поток}
   GetMem(Tids, sizeof(TThreadID)+1);
   membuf(Tids)^[1]:=1;
   Result:=PThreadID(@membuf(Tids)^[2]);
  end
 else
  if membuf(Tids)^[1]=255 then
   begin {Переполнение}
    repeat {Ищем мёртвые души}
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
        begin {Поток не завершён}
         PThreadID(@membuf(Tids)^[s+1])^:=Result^;
         inc(s, sizeof(TThreadID));
{$IFDEF MSWINDOWS}
        end
       else
        begin {Получаем ошибку завершения потока}
         GetExitCodeThread(Result^, t);
         SetLastError(t);
         CloseHandle(Result^);
        end;
{$ENDIF}
       inc(p, sizeof(TThreadID));
      end;
     {Переформируем список}
     FreeMem(Tids);
     GetMem(Tids, s);
     move(N^, Tids^, s);
     membuf(Tids)^[1]:=(s-1) div sizeof(TThreadID);
     FreeMem(N);
     if s=p then {Ждём завершения}
      Sleep(TermTimeout);
    until s<>p;
    {Ищем место снова}
    Result:=FindNewTID(Tids);
   end
  else
   begin {Дополняем список}
    s:=membuf(Tids)^[1]*sizeof(TThreadID)+1;
    {Создаём новый список}
    GetMem(N, s+sizeof(TThreadID));
    move(Tids^, N^, s);
    {Удаляем старый}
    FreeMem(Tids);
    inc(membuf(N)^[1]);
    Tids:=N;
    Result:=PThreadID(@membuf(Tids)^[s+1]);
   end;
end;

{Удалить все потоки}
procedure CloseAllTIDS(Tids:Pointer);
var p:LongWord;
begin
 if Tids=nil then
  Exit;
 p:=1;
 {Перечисляем весь список}
 while p<>(membuf(Tids)^[1]*sizeof(TThreadID)+1) do
  begin
{$IFDEF MSWINDOWS}
   {Ждём завершения}
   if WaitForSingleObject(PThreadID(@membuf(Tids)^[p+1])^, TermTimeout)=WAIT_TIMEOUT then
    begin {Недождались}
     TerminateThread(PThreadID(@membuf(Tids)^[p+1])^, INFINITE);
     InterlockedDecrement(ClientThreads);
     SetLastError(WAIT_TIMEOUT);
    end;
   CloseHandle(PThreadID(@membuf(Tids)^[p+1])^);
{$ENDIF}
   inc(p, sizeof(TThreadID));
  end;
end;

{Серверная часть}
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
    {Ждём соединения}
    Result:=AcceptConnection(Settings^.Params.Sock, From, Socket);
    if Result<>0 then
     begin {Ошибка - завершаемся}
      {Игнорируем прерывание соединения}
      IgnoreIntr(le);
      {Удаляем потоки}
      CloseAllTIDS(tids);
      break;
     end
    else
     begin {Запускем обработчик}
      New(SettingsRecord);
      SettingsRecord^.Settings:=Settings;
      SettingsRecord^.Socket:=Socket;
      hThread:=FindNewTid(tids);
      hThread^:=BeginThread(nil, 0, ProccessThread, SettingsRecord, 0, tid);
      InterlockedIncrement(ClientThreads);
     end;
   end;
 finally
  {Удаляем список}
  if tids<>nil then
   FreeMem(tids);
 end;    
 ServerThread:=GetLastError;
end;

{--------------Server command procs}

{Команда завпуска}
procedure cmStartProc(var Settings:TSettings);
var
 R:LongWord;
begin
 if Settings.IsStart then
  begin {Уже запущен}
   writeln(1);
   Exit;
  end;
 with Settings.Params do
  begin {Загружаем параметры}
{$IFDEF DEBUG_MODE1}
   R:=ListenPort(IP, Port, Sock);
{$ELSE}
   for R:=1 to sizeof(Info) do
    readln(membuf(@Info)^[R]);
   R:=CreateDuplicatedSocket(Sock, Info);
{$ENDIF}
   if R=0 then
    begin
     {Запускаем серверную часть}
     Settings.hThread:=BeginThread(nil, 0, ServerThread, @Settings, 0, Settings.tid);
     if Settings.hThread=0 then
      R:=GetLastError;
    end;
  end;
 Settings.IsStart:=R=0;
 {Сообщить о результате}
 writeln(R);
end;

{Команда остановки сервера}
procedure cmStopProc(var Settings:TSettings);
var R:LongWord;
begin
 if not Settings.IsStart then
  begin {Не запущен}
   writeln(1);
   Exit;
  end;
 {Закрываем порт}
 StopConnection(Settings.Params.Sock);
{$IFDEF MSWINDOWS}
 {Завершаем поток}
 WaitForSingleObject(Settings.hThread, INFINITE);
 GetExitCodeThread(Settings.hThread, R);
 CloseHandle(Settings.hThread);
{$ENDIF}
 Settings.IsStart:=false;
 {Сообщить о результате}
 writeln(R);
end;
  
{-------------------------------End}


{Выполнить команды}
procedure ExecuteCommands(var Settings:TSettings);
type
 TServCommProc=procedure(var Settings:TSettings);
const
 {Список обработчиков комманд}
 cmhndrs:array[TCommand] of TServCommProc=(
  nil, cmStartProc, cmStopProc
 );
var
 Com:TCommand;
begin
 while true do
  begin
   {Принимаем команду}
   readln(TCommandOrd(Com));
   if Com=cmQuit then
    break;
   {Выполняем}
   cmhndrs[Com](Settings);
  end;
end;

{--------- Mode Server End ----------}

{$IFDEF MSWINDOWS}
{Запрет на выход}
function MyHandlerRoutine(dwCtrlType:LongWord):Boolean; stdcall;
begin
 ConsoleLog('Error: программу следует завершать только с помощью команды QUIT');
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

{Обработчики ошибок}

procedure ExceptHandler(ExceptObject:TObject;ExceptAddr:Pointer{$IFDEF FPC};FrameCount:LongInt;Frame:PPointer{$ENDIF});
begin
{$I-}
 PauseAllThreads;
 writeln('Произошло необработанное исключение');
 writeln('Адрес: ', LongWord(ExceptAddr));
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
 writeln('Произошла ошибка в системной библиотеке программы');
 writeln('Адрес: ', LongWord(Addr));
 writeln('Код ошибки: ', ErrorCode);
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
 {Запрет на выход}
 SetConsoleCtrlHandler(@MyHandlerRoutine, true);
 {Получаем загловок окна по умолчанию}
 Len:=GetConsoleTitle(nil, 0);
 SetLength(DefaultTitle, Len);
 if Len<>0 then
  GetConsoleTitle(PChar(DefaultTitle), Len);
 {Устанавливаем режим обратоки ошибок}
 SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOOPENFILEERRORBOX or SEM_NOALIGNMENTFAULTEXCEPT);
{$ENDIF}
 {Устанавливаем обработчики ошибок}
 LastExceptProc:={$IFDEF FPC}@{$ENDIF}ExceptProc;
 LastErrorProc:=@ErrorProc;
 LastExitProc:=ExitProc;
 ExceptProc:=@ExceptHandler;
 ErrorProc:=SErrorProc;
 ExitProc:=@SExitProc;
 {Добавляем свою переменную окружения}
 SUtils.SetEnvironmentVariable('VPSERVERdir', ServerDir);
 {Подгоняем под себя STDIO}
 Rewrite(Output);
 Reset(Input);
 AutoFlush(Output);
 AutoFlush(Input);
finalization
{$IFDEF MSWINDOWS}
 {Возвращаем заголовок}
 SetConsoleTitle(PChar(DefaultTitle));
{$ENDIF}
 {Возвращаем обработчики ошибок}
 if {$IFDEF FPC}@{$ENDIF}ExceptProc=@ExceptHandler then
  ExceptProc:=LastExceptProc;
 if @ErrorProc=@SErrorProc then
  ErrorProc:=LastErrorProc;
 if ExitProc=@SExitProc then
  ExitProc:=LastExitProc;
end.
