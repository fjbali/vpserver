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

type
 PHeader=^THeader;
 THeader=record
  Header:Integer;
  Data:Pointer;
 end;
 THeaders=record
  Count:LongWord;
  Headers:Pointer;
 end;
 PBodyRange=^TBodyRange;
 TBodyRange=record
  Next:PBodyRange;
  StartR:LongWord;
  EndR:LongWord;
  Full:LongWord;
 end;
 TEntityBodyStat=record
  Buf:Pointer;
  Size:LongWord;
 end;
 TEntityBodyDyn=record
  Data:Pointer;
  FullSize:LongWord;
  DynFunct:function(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
  DynSeek:function(var Data:Pointer;const SeekVal:LongWord):Boolean;
  DynFree:procedure(var Data:Pointer);
 end;
 TEntityBody=record
  IsDyn:Boolean;
  Content:String;
  case Byte of
   0:(Dyn:TEntityBodyDyn);
   1:(Stat:TEntityBodyStat);
 end;
 TStatusCode=record
  StatusCode:Word;
  Description:String;
 end;
 THTTPRequest=record
  Method:Integer;
  URI:String;
  HTTPVer:Integer;
  PreError:TStatusCode;
  Headers:THeaders;
  Body:TEntityBody;
 end;
 THTTPResponse=record
  StatusCode:TStatusCode;
  URI:String;
  Host:String;
  Headers:THeaders;
  KAlive:Boolean;
  BodyRange:PBodyRange;
  NoBody:Boolean;
  Body:TEntityBody;
  ToRecv:LongWord;
 end;
 TMethodProcess=procedure(var Request:THTTPRequest;var Response:THTTPResponse);
 THeaderType=(htOther,  htGeneral, htRequest, htResponse, htEntity);
 THeaderMatch=function(const Header:String;out Data:Pointer):Boolean;
 THeaderAdd=function(out Data:Pointer;var Response:THTTPResponse):Boolean;
 THeaderDelete=procedure(var Data:Pointer);
 THeaderProcess=procedure(var Data:Pointer;var Response:THTTPResponse);
 THeaderPrint=procedure(var F:TextFile;var Data:Pointer);

const
 DefMime='text/plain';

procedure AddHeader(var Headers:THeaders;const Header:THeader);
var
 p:LongWord;
 N:Pointer;
begin
 if Headers.Count<>0 then
  begin
   p:=1;
   while p<(Headers.Count*sizeof(PHeader)) do
    begin
     if PHeader(Pointer(@membuf(Headers.Headers)^[p])^)^.Header=Header.Header then
      begin
       PHeader(Pointer(@membuf(Headers.Headers)^[p])^)^.Data:=Header.Data;
       break;
      end;
     inc(p, sizeof(PHeader));
    end;
   if p>(Headers.Count*sizeof(PHeader)) then
    begin
     inc(Headers.Count);
     p:=Headers.Count*sizeof(PHeader);
     GetMem(N, p);
     dec(p, sizeof(PHeader));
     move(Headers.Headers^, N^, p);
     FreeMem(Headers.Headers);
     Headers.Headers:=N;
     inc(p);
     New(PHeader(Pointer(@membuf(Headers.Headers)^[p])^));
     PHeader(Pointer(@membuf(Headers.Headers)^[p])^)^:=Header;
    end;
  end
 else
  begin
   GetMem(Headers.Headers, sizeof(PHeader));
   New(PHeader(Headers.Headers^));
   PHeader(Headers.Headers^)^:=Header;
   inc(Headers.Count);
  end;
end;

function GetHeader(const Headers:THeaders;const N:LongWord):PHeader; overload;
begin
 if N<=Headers.Count then
  GetHeader:=PHeader(Pointer(@membuf(Headers.Headers)^[(N-1)*sizeof(PHeader)+1])^)
 else
  GetHeader:=nil;
end;

function GetHeader(const Headers:THeaders;const Header:Integer):PHeader; overload;
var
 p:LongWord;
 T:PHeader;
begin
 for p:=1 to Headers.Count do
  begin
   T:=GetHeader(Headers, p);
   if T=nil then
    continue;
   if T^.Header=Header then
    begin
     GetHeader:=T;
     Exit;
    end;
  end;
 GetHeader:=nil;
end;

procedure DeleteHeaders(var Headers:THeaders); forward;

procedure FreeEntityBody(var EntityBody:TEntityBody);
begin
 if EntityBody.IsDyn then
  EntityBody.Dyn.DynFree(EntityBody.Dyn.Data)
 else
  if EntityBody.Stat.Buf<>nil then
   FreeMem(EntityBody.Stat.Buf);
 FillChar(EntityBody, sizeof(EntityBody), 0);
end;

type
 PExtBodyData=^TExtBodyData;
 TExtBodyData=record
  OriginalBody:TEntityBody;
  CurBuf:TEntityBodyStat;
  O:LongWord;
 end;

function ExtBodyDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
var
 P:Pointer;
 C, L, O2:LongWord;
begin
 GetMem(P, S);
 C:=S;
 O2:=0;
 with PExtBodyData(Data)^ do
  while C<>0 do
   if CurBuf.Buf<>nil then
    begin
     if CurBuf.Size=O then
      begin
       FreeMem(CurBuf.Buf);
       FillChar(CurBuf, sizeof(CurBuf), 0);
       O:=0;
       continue;
      end;
     if (CurBuf.Size-O)>C then
      L:=C
     else
      L:=CurBuf.Size-O;
     move(Pointer(@membuf(CurBuf.Buf)^[O+1])^, Pointer(@membuf(P)^[O2+1])^, L);
     inc(O2, L);
     inc(O, L);
     dec(C, L);
    end
   else
    begin
     if not OriginalBody.IsDyn then
      break;
     CurBuf:=OriginalBody.Dyn.DynFunct(OriginalBody.Dyn.Data, C);
     if CurBuf.Size=0 then
      break;
    end;
 Result.Size:=S-C;
 if Result.Size<>0 then
  begin
   GetMem(Result.Buf, Result.Size);
   move(P^, Result.Buf^, Result.Size);
  end;
 FreeMem(P);
end;

procedure ExtBodyDynFree(var Data:Pointer);
begin
 with PExtBodyData(Data)^ do
  begin
   FreeEntityBody(OriginalBody);
   if CurBuf.Buf<>nil then
    FreeMem(CurBuf.Buf);
  end;
 Dispose(PExtBodyData(Data));
end;

procedure ExtBody(var Body:TEntityBody);
var P:PExtBodyData;
begin
 New(P);
 FillChar(P^, sizeof(P^), 0);
 if Body.IsDyn then
  P^.OriginalBody:=Body
 else
  begin
   P^.CurBuf:=Body.Stat;
   Body.IsDyn:=true;
   FillChar(Body.Dyn, sizeof(Body.Dyn), 0);
   Body.Dyn.FullSize:=P^.CurBuf.Size;
  end;
 with Body.Dyn do
  begin
   Data:=P;
   DynFunct:=ExtBodyDynFunct;
   DynFree:=ExtBodyDynFree;
  end;
end;

type
 PFileBodyDynData=^TFileBodyDynData;
 TFileBodyDynData=record
  F:^File;
  p:LongWord;
  FS:LongWord;
 end;

function FileBodyDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
var
 D:LongWord;
 M:Pointer;
begin
 FillChar(Result, sizeof(Result), 0);
 with PFileBodyDynData(Data)^ do
  begin
   if FS<=(S+p) then
    D:=FS-p
   else
    D:=S;
   if D=0 then
    Exit;
   GetMem(M, D);
{$I-}
   BlockRead(F^, M^, D, D);
{$I+}
   if IOResult=0 then
    begin
     GetMem(Result.Buf, D);
     move(M^, Result.Buf^, D);
     Result.Size:=D;
    end;
   FreeMem(M);
   inc(p, D);
  end;
end;

function FileBodyDynSeek(var Data:Pointer;const SeekVal:LongWord):Boolean;
begin
{$I-}
 Seek(PFileBodyDynData(Data)^.F^, SeekVal);
 PFileBodyDynData(Data)^.p:=SeekVal;
{$I+}
 FileBodyDynSeek:=IOResult=0;
end;


procedure FileBodyDynFree(var Data:Pointer);
begin
 with PFileBodyDynData(Data)^ do
  begin
   Close(F^);
   Dispose(F);
  end;
 Dispose(PFileBodyDynData(Data));
end;

procedure SetFileBody(var F:Pointer;var Body:TEntityBody);
var
 D:PFileBodyDynData;
begin
 Body.IsDyn:=true;
 New(D);
 with Body.Dyn do
  begin
   D^.F:=F;
   D^.p:=0;
   Data:=D;
   DynFunct:=FileBodyDynFunct;
   DynSeek:=FileBodyDynSeek;
   DynFree:=FileBodyDynFree;
   FullSize:=FileSize(File(F^));
   D^.FS:=FullSize;
  end;
end;

procedure FreeRequest(var Request:THTTPRequest);
begin
 if Request.Headers.Count<>0 then
  DeleteHeaders(Request.Headers);
 FreeEntityBody(Request.Body);
end;

procedure FreeResponse(var Response:THTTPResponse);
var P:PBodyRange;
begin
 if Response.Headers.Count<>0 then
  DeleteHeaders(Response.Headers);
 FreeEntityBody(Response.Body);
 P:=Response.BodyRange;
 while P<>nil do
  begin
   P:=P^.Next;
   Dispose(Response.BodyRange);
   Response.BodyRange:=P;
  end;
end;

procedure SetStatusCode(var Code:TStatusCode;const StatusCode:Word;const Description:String='');
begin
 Code.StatusCode:=StatusCode;
 Code.Description:=Description;
end;

procedure SetResponseError(var Response:THTTPResponse;const Error:Word;const Description:String='');
begin
 FreeEntityBody(Response.Body);
 SetStatusCode(Response.StatusCode, Error, Description);
end;

function EntityBodyLength(const EntityBody:TEntityBody):LongWord;
begin
 if EntityBody.IsDyn then
  Result:=EntityBody.Dyn.FullSize
 else
  Result:=EntityBody.Stat.Size;
end;
