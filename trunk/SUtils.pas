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

unit SUtils;

interface

uses STypes;

{$IFNDEF MSWINDOWS}
procedure Sleep(const a:LongWord);
{$ELSE}
{$IFDEF FPC}
procedure SetLastError(const e:Integer);
{$ENDIF}
{$ENDIF}
procedure StartRide(var Ride:TRide);
procedure StopRide(var Ride:TRide);
procedure ResetRide(var Ride:TRide);
function GetMD5(const Buf;const Size:LongWord):String;
function RegisterRide:TRide;
procedure UnregisterRide(var Ride:TRide);
procedure PauseAllThreads;
function IndexStr(const AText:String;const AValues:array of string):Integer;
procedure DelStr(var s:String;const substr:String;const del:Integer);
function IntToStr(const Value:Integer):String;
function StrToInt(const S:String):Integer;
function GetEnvironmentVariable(const Name:String):String;
procedure SetEnvironmentVariable(const Name, Val:String);
function ExpandEnvString(const S:String):String;
function DirectoryExists(const Directory:String):Boolean;
function UpString(const s:String):String;
procedure MyWait;
procedure MyHalt(const ReturnCode:Integer);
procedure AutoFlush(var F:TextFile);   
procedure ReformStr(var s:String);
procedure Crop(var S:String);
function GetCurrentDateTime:TTime;
function GetRFC1123DateTime(const t:TTime):String;

implementation

uses md5{$IFDEF MSWINDOWS}, Windows{$ELSE}, SysUtils, BaseUnix{$ENDIF};
 
{$IFNDEF MSWINDOWS}
procedure Sleep(const a:LongWord);
begin
 FpSleep(a);
end;
{$ELSE}

var
 Time:TSystemTime;
 TimeLock:Integer=0;

{$IFDEF FPC}
procedure SetLastError(const e:Integer);
begin
 Windows.SetLastError(e);
end;
{$ENDIF}
{$ENDIF}

function GetMD5(const Buf;const Size:LongWord):String;
var
 pms:md5_state;
begin
 md5_init(pms);
 md5_append(pms, Buf, Size);
 GetMD5:=md5_finish(pms);
end;

function IndexStr(const AText:String;const AValues:array of string):Integer;
var
 i:Integer;
begin
 IndexStr:=-1;
 for i:=Low(AValues) to High(AValues) do
  if AText=AValues[i] then
   begin
    IndexStr:=i;
    break;
   end;
end;

procedure DelStr(var s:String;const substr:String;const del:Integer);
begin
 while Pos(substr, s)<>0 do
  Delete(s, Pos(substr, s), del);
end;

procedure StartRide(var Ride:TRide);
begin
{$IFDEF MSWINDOWS}
 while true do
  begin
   WaitForSingleObject(Ride.Event, INFINITE);
   if InterlockedIncrement(Ride.Lock)=1 then
    break;
   InterlockedDecrement(Ride.Lock);
  end;
 ResetEvent(Ride.Event);
{$ELSE}
 EnterCriticalSection(Ride);
{$ENDIF}
end;

procedure ResetRide(var Ride:TRide);
begin
{$IFDEF MSWINDOWS}
 Ride.Lock:=0;
 SetEvent(Ride.Event);
{$ELSE}
 StopRide(Ride);
{$ENDIF}
end;

procedure StopRide(var Ride:TRide);
begin
{$IFDEF MSWINDOWS}
 InterlockedDecrement(Ride.Lock);
 SetEvent(Ride.Event);
{$ELSE}
 LeaveCriticalSection(Ride);
{$ENDIF}
end;

function RegisterRide:TRide;
begin
{$IFDEF MSWINDOWS}
 Result.Lock:=0;
 Result.Event:=CreateEvent(nil, true, true, nil);
{$ELSE}
 InitCriticalSection(Result);
{$ENDIF}
end;

procedure UnregisterRide(var Ride:TRide);
begin
{$IFDEF MSWINDOWS}
 ResetRide(Ride);
 CloseHandle(Ride.Event);
{$ELSE}
 DoneCriticalSection(Ride);
{$ENDIF}
end;

function DirectoryExists(const Directory:String):Boolean;
{$IFDEF MSWINDOWS}
var
 Code:Integer;
begin
 Code:=GetFileAttributesA(PChar(Directory));
 Result:=(Code<>-1) and (($10 and Code)<>0);
end;
{$ELSE}
begin
 DirectoryExists:=SysUtils.DirectoryExists(Directory);
end;
{$ENDIF}

{$IFDEF FPC}
function IntToStr(const Value:Integer):String;
begin
 Str(Value, Result);
end;
{$ELSE}
procedure CvtInt; Assembler;
asm
 or cl, cl
 jnz @CvtLoop
@C1:
 or eax, eax
 jns @C2
 neg eax
 call @C2
 mov al, 45
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
 add dl, 48
 cmp dl, 58
 jb @D2
 add dl, 7
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
 mov al, 48
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

function IntToStr(const Value:Integer):String; Assembler;
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
{$ENDIF}

function MIntToStr(const Value:Integer):String;
begin
 Result:=IntToStr(Value);
 if odd(Length(Result)) then
  Result:='0'+Result;
end;

function StrToInt(const S:String):Integer;
var
 E:Integer;
begin
 Val(S, Result, E);
 if E<>0 then
  Result:=-MaxInt;
end;

procedure PauseAllThreads;
begin
end;

function GetEnvironmentVariable(const Name:String):String;
{$IFDEF MSWINDOWS}
var
 Len:Integer;
begin
 Result:='';
 Len:=GetEnvironmentVariableA(PChar(Name), nil, 0);
 if Len>0 then
  begin
   SetLength(Result, Len-1);
   GetEnvironmentVariableA(PChar(Name), PChar(Result), Len);
  end;
end;
{$ELSE}
begin
 Result:=SysUtils.GetEnvironmentVariable(Name);
end;
{$ENDIF}

procedure SetEnvironmentVariable(const Name, Val:String);
{$IFDEF MSWINDOWS}
begin
 SetEnvironmentVariableA(PChar(Name), PChar(Val));
end;
{$ELSE}
begin
 Result:=SysUtils.SetEnvironmentVariable(Name, Val);
end;
{$ENDIF}

{$IFDEF MSWINDOWS}
function ExpandEnvString(const S:String):String;
var
 Len:Integer;
begin
 Result:='';
 Len:=ExpandEnvironmentStringsA(PChar(S), nil, 0);
 if Len>0 then
  begin
   SetLength(Result, Len-1);
   ExpandEnvironmentStringsA(PChar(S), PChar(Result), Len);
  end;
end;
{$ENDIF}

function UpString(const s:String):String;
var
 i:Integer;
begin
 Result:=s;
 for i:=1 to Length(s) do
  Result[i]:=UpCase(Result[i]);
end;
          
procedure MyWait;
const
 WAIT='ќжидание...';
begin
 write(WAIT);
 Sleep(4500);
 write(#13, ' ':Length(WAIT), #13);
 Sleep(500);
end;

procedure MyHalt(const ReturnCode:Integer);
begin
 MyWait;
 PauseAllThreads;
 Halt(ReturnCode);
end;

procedure AutoFlush(var F:TextFile);
begin
 with TTextRec(F) do
  if Mode=fmOutput then
   FlushFunc:=InOutFunc;
end;

procedure Crop(var S:String);
begin
 while copy(s, 1, 1)=' ' do
  Delete(s, 1, 1);
 while copy(s, Length(s), 1)=' ' do
  Delete(s, Length(s), 1);
end;

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
var
 ps, ns, ls, cc, l:LongWord;
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

{$IFDEF MSWINDOWS}
procedure GetCurrentDateTimeLock;
begin
 if InterlockedIncrement(TimeLock)=1 then
  GetSystemTime(Time);
 InterlockedDecrement(TimeLock);
end;
{$ENDIF}

function GetCurrentDateTime:TTime;
begin
 GetCurrentDateTimeLock;
 Result:=Time;
end;

const
 dow:array[0..6] of String = ('Sun', 'Mon', 'Tus', 'Wed', 'Thu', 'Fri', 'Sat');
 mon:array[1..12] of String = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');

function GetRFC1123DateTime(const t:TTime):String;
begin
 Result:=dow[t.wDayOfWeek]+', '+IntToStr(t.wDay)+' '+mon[t.wMonth]+' '+
         IntToStr(t.wYear)+' '+MIntToStr(t.wHour)+':'+MIntToStr(t.wMinute)+':'+
         MIntToStr(t.wSecond)+' GMT';
end;

end.
