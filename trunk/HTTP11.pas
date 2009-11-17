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

unit HTTP11;

interface

uses STypes;

{$DEFINE DYNMIME}

procedure ProccessRequest(const Socket:TSocket;const Params:PParams);

implementation

uses SUtils, SLog, WSUtils;

{$I HTTP11T.inc}

{$I HTTP11F.inc}

{$I HTTP11T2.inc}

function ReadRequest(var Sock:TextFile;out Data:THTTPRequest):Boolean;
var
 CLine:LongWord;

  function ParseLine(const Line:String):Boolean;
  var
   t1, t2:String;
   t3:LongWord;
   Header:THeader;
  begin
   ParseLine:=false;
   if Line='' then
    Exit;
   if CLine=1 then
    begin
     t1:=Line;
     t3:=1;
     while Pos(' ', t1)<>0 do
      begin
       inc(t3);
       t1[Pos(' ', t1)]:='?';
      end;
     if t3<>3 then
      begin
       SetStatusCode(Data.PreError, 400, 'Bad Request');
       Exit;
      end;
     t1:=Line;
     t2:=copy(t1, 1, Pos(' ', t1)-1);
     Delete(t1, 1, Pos(' ', t1));
     Data.Method:=IndexStr(t2, Methods);
     t2:=copy(t1, 1, Pos(' ', t1)-1);
     Delete(t1, 1, Pos(' ', t1));
     Data.URI:=t2;
     Data.HTTPVer:=IndexStr(t1, Versions);
     if Data.HTTPVer<0 then
      begin
       SetStatusCode(Data.PreError, 505, 'HTTP Version Not Supported');
       Exit;
      end;
     if Data.Method<0 then
      begin
       SetStatusCode(Data.PreError, 501, 'Not Implemented');
       Exit;
      end;
    end
   else
    for t3:=1 to AHEAD do
     if HeaderType[t3-1] in [htGeneral, htRequest, htEntity] then
      if HeaderMatch[t3-1](Line, Header.Data) then
       begin
        Header.Header:=t3-1;
        AddHeader(Data.Headers, Header);
        break;
       end;
   ParseLine:=true;
  end;

var
 s:String;
begin
 CLine:=0; 
 FillChar(Data, sizeof(Data), 0);
 repeat
{$I-}
  readln(Sock, s);
{$I+}
  inc(CLine);
  if (IOResult<>0) or ((s<>'') and (not ParseLine(s))) then
   begin
    ReadRequest:=false;
    Exit;
   end;
 until s='';
 ReadRequest:=true;
end;

function FormErrorBody(var Response:THTTPResponse):Boolean;
var
 Code:TStatusCode;
 F:^File;
begin
 FormErrorBody:=false;
 if (not (Byte(Response.StatusCode.StatusCode div 100) in [4, 5])) or (EntityBodyLength(Response.Body)<>0) then
  Exit;
 Code:=Response.StatusCode;
 FreeResponse(Response);
 FillChar(Response, sizeof(Response), 0);
 Response.StatusCode:=Code;
 New(F);
 GetDir(0, Response.URI);
 Response.URI:=Response.URI+{$IFDEF MSWINDWOS}'\'{$ELSE}'/'{$ENDIF}+'error'+IntToStr(Code.StatusCode)+'.html';
 Assign(F^, Response.URI);
{$I-}
 FileMode:=0;
 Reset(F^, 1);
{$I+}
 if IOResult<>0 then
  with Response.Body.Stat do
   begin
    Dispose(F);
    Response.URI:='';
    Response.Body.IsDyn:=false;
    Size:=Length(Code.Description);
    GetMem(Buf, Size);
    move(PChar(Code.Description)^, Buf^, Size);
   end
 else
  begin
   SetFileBody(Pointer(F), Response.Body);
   Response.Body.Dyn.DynSeek:=nil;
  end;
 FormErrorBody:=true;
end;

procedure FillResponse(var Request:THTTPRequest;out Response:THTTPResponse;out KAlive:Boolean);
var
 Header:PHeader;
 NewH:THeader;
 I, C:LongWord;
begin
 FillChar(Response, sizeof(Response), 0);
 Response.StatusCode:=Request.PreError;
 for I:=1 to Request.Headers.Count do
  begin
   if Response.StatusCode.StatusCode<>0 then
    break;
   Header:=GetHeader(Request.Headers, I);
   if Header=nil then
    continue;
   HeaderProcess[Header^.Header](Header^.Data, Response);
  end;
 if Response.StatusCode.StatusCode=0 then
  MethodProcess[Request.Method](Request, Response);
 if Response.StatusCode.StatusCode=0 then
  SetResponseError(Response, 400, 'Bad Request');
 I:=0;
 while true do
  begin
   if FormErrorBody(Response) then
    I:=0;
   C:=Response.StatusCode.StatusCode;
   while I<>AHEAD do
    begin
     if HeaderType[I] in [htGeneral, htResponse, htEntity] then
      begin
       if HeaderAdd[I](NewH.Data, Response) then
        begin
         NewH.Header:=I;
         AddHeader(Response.Headers, NewH);
        end;
       if Response.StatusCode.StatusCode<>C then
        begin
         C:=0;
         inc(I);
         break;
        end;
      end;
     inc(I);
    end;
   if C<>0 then
    break;
  end;
 KAlive:=Response.KAlive;
end;

procedure SendResponse(var Sock:TextFile;var Data:THTTPResponse);
var
 I, RealSent:LongWord;
 Header:PHeader;
 Buf:TEntityBodyStat;
 TimeOut:Boolean;
begin
{$I-}
 writeln(Sock, 'HTTP/1.1 ', Data.StatusCode.StatusCode, ' ', Data.StatusCode.Description);
 for I:=1 to Data.Headers.Count do
  begin
   Header:=GetHeader(Data.Headers, I);
   if Header=nil then
    continue;
   HeaderPrint[Header^.Header](Sock, Header^.Data);
  end;
 writeln(Sock);
 Flush(Sock);
 if not Data.NoBody then
  begin
   if not Data.Body.IsDyn then
    begin
     Buf:=Data.Body.Stat;
     FillChar(Data.Body.Stat, sizeof(Data.Body.Stat), 0);
    end;
   while true do
    begin
     if Data.Body.IsDyn then
      Buf:=Data.Body.Dyn.DynFunct(Data.Body.Dyn.Data);
     if Buf.Size=0 then
      break;
     I:=SendBuf(GetFileSockRecord(Sock)^, Buf.Buf^, Buf.Size, TimeOut, RealSent);
     FreeMem(Buf.Buf);
     if (I<>0) or (RealSent<>Buf.Size) or TimeOut then
      break;                                          
     Buf.Size:=0;
    end;
  end;
{$I+}
 IOResult;
end;

procedure ProccessRequest(const Socket:TSocket;const Params:PParams);
var
 KAlive, TimeOut:Boolean;
 SockIn, SockOut:TextFile;
 Request:THTTPRequest;
 Response:THTTPResponse;
 p:Pointer;
begin
 AssignSocket(SockIn, Socket, Params^.RWait);
 AssignSocket(SockOut, Socket, Params^.RWait);
 FileMode:=0;
 Reset(SockIn);
 Rewrite(SockOut);
 repeat
  KAlive:=false;
  FillChar(Request, sizeof(Request), 0);
  FillChar(Response, sizeof(Response), 0);
  try
   if ReadRequest(SockIn, Request) or (Request.PreError.StatusCode<>0) then
    begin
     FillResponse(Request, Response, KAlive);
     SendResponse(SockOut, Response);
    end;
   if Response.ToRecv<>0 then
    begin
     GetMem(p, Response.ToRecv);    
     RecvBuf(GetFileSockRecord(SockIn)^, p^, Response.ToRecv, TimeOut, Response.ToRecv);
     FreeMem(p);
     if TimeOut then
      KAlive:=false;
    end;
  finally
   FreeRequest(Request);
   FreeResponse(Response);
  end;
 until not KAlive;
 Close(SockIn);
 Close(SockOut);
end;

{$IF DECLARED(MimeInit)}
initialization
 MimeInit;
{$IFEND}
{$IF DECLARED(MimeDestroy)}
finalization
 MimeDestroy;
{$IFEND}
end.
