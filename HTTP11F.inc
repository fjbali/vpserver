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

const
 AVER=2;
 Versions:array[0..AVER-1] of String=(
  'HTTP/1.0', 'HTTP/1.1'
 );
 APREF=1;
 Pref:array[0..APREF-1] of String=(
  'http://'
 );

{$IFDEF DYNMIME}
{$I Dynmime.inc}
{$ELSE}
function FindMime(const URI:String):String;
var
 ms, s:String;
 Mime:TextFile;
begin
 s:=URI;
 Result:=DefMime;
{$IFDEF MSWINDOWS}
 while Pos('\', s)<>0 do
  Delete(s, 1, Pos('\', s));
 Crop(s);
{$ENDIF}
 if Pos('.', s)=0 then
  Exit;
 ms:='';
 while s[Length(s)]<>'.' do
  begin
   ms:=s[Length(s)]+ms;
   SetLength(s, Length(s)-1);
  end;
 s:=ms;
 Crop(s);
 Assign(Mime, 'mime.types');
 {$I-}
 FileMode:=0;
 Reset(Mime);
 {$I+}
 if IOResult<>0 then
  Exit;
 while not Eof(Mime) do
  begin
   readln(Mime, ms);
   if copy(ms, 1, Pos(' ', ms)-1)=s then
    begin
     Delete(ms, 1, Pos(' ', ms));
     Result:=ms;
     break;
    end;
  end;
 Close(Mime);
end;
{$ENDIF}

function FormRange(const Range:TBodyRange):String;
begin
 FormRange:=IntToStr(Range.StartR)+'-'+IntToStr(Range.EndR)+'/'+IntToStr(Range.Full);
end;

function ProccessURI(var Request:THTTPRequest;var Response:THTTPResponse):Boolean;
var
 i:Integer;
begin
 ReformStr(Request.URI);
 ReformStr(Response.Host);
 if Pos('://', Request.URI)<>0 then
  begin
   i:=IndexStr(copy(Request.URI, 1, Pos('://', Request.URI)), Pref);
   if i>=0 then
    begin
     Delete(Request.URI, 1, Length(Pref[i]));
     if Pos('/', Request.URI)=0 then
      Request.URI:=Request.URI+'/';
     Response.Host:=copy(Request.URI, 1, Pos('/', Request.URI)-1);
     Delete(Request.URI, 1, Length(Response.Host));
    end;
  end;
 if Response.Host='' then
  if Versions[Request.HTTPVer]='HTTP/1.1' then
   begin
    SetResponseError(Response, 400, 'Bad Request');
    ProccessURI:=false;
    Exit;
   end
  else
   Response.Host:='localhost';
 if Pos(':', Response.Host)<>0 then
  Response.Host:=copy(Response.Host, 1, Pos(':', Response.Host)-1);
 if copy(Request.URI, 1, 1)<>'/' then
  Request.URI:='/'+Request.URI;
 GetDir(0, Response.URI);
 Response.URI:=Response.URI+'/'+Response.Host+Request.URI;
 if Response.URI[Length(Response.URI)]='/' then
  Response.URI:=Response.URI+'index.html';
{$IFDEF MSWINDOWS}
 while Pos('/', Response.URI)<>0 do
  Response.URI[Pos('/', Response.URI)]:='\';
{$ENDIF}
 while Response.URI[Length(Response.URI)]='.' do
  SetLength(Response.URI, Length(Response.URI)-1);
 SetStatusCode(Response.StatusCode, 200, 'OK');
 ProccessURI:=true;
end;

procedure GetMP(var Request:THTTPRequest;var Response:THTTPResponse);
var
 F:^File;
begin
 if not ProccessURI(Request, Response) then
  Exit;
 New(F);
 Assign(F^, Response.URI);
{$I-}
 FileMode:=0;
 Reset(F^, 1);
{$I+}
 if IOResult<>0 then
  begin
   Dispose(F);
   SetResponseError(Response, 404, 'Not Found');
   Exit;
  end;
 SetFileBody(Pointer(F), Response.Body);
end;

procedure PostMP(var Request:THTTPRequest;var Response:THTTPResponse);
begin
end;

procedure OptionsMP(var Request:THTTPRequest;var Response:THTTPResponse);
begin
end;

function EmpDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
begin
 FillChar(Result, sizeof(Result), 0);
end;

function EmpDynSeek(var Data:Pointer;const SeekVal:LongWord):Boolean;
begin
 EmpDynSeek:=true;
end;

procedure EmpDynFree(var Data:Pointer);
begin
end;

procedure HeadMP(var Request:THTTPRequest;var Response:THTTPResponse);
begin
 GetMP(Request, Response);
 Response.NoBody:=true;
end;

{Date Header}

function DateHM(const Header:String;out Data:Pointer):Boolean;
begin
 DateHM:=false;
end;

function DateHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
begin
 DateHA:=true;
end;

procedure DateHD(var Data:Pointer);
begin
end;

procedure DateHP(var F:TextFile;var Data:Pointer);
begin
 writeln(F, 'Date: ', GetRFC1123DateTime(GetCurrentDateTime));
end;

{Host Header}

function HostHM(const Header:String;out Data:Pointer):Boolean;
begin
 HostHM:=false;
 if copy(Header, 1, 6)<>'Host: ' then
  Exit;
 New(PString(Data));
 PString(Data)^:=Header;
 Delete(PString(Data)^, 1, 6);
 HostHM:=true;
end;

procedure HostHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PString(Data));
end;

procedure HostHPC(var Data:Pointer;var Response:THTTPResponse);
begin
 Response.Host:=PString(Data)^;
end;

{Range Header}

function RangeHM(const Header:String;out Data:Pointer):Boolean;
begin
 RangeHM:=false;
 if copy(Header, 1, 7)<>'Range: ' then
  Exit;
 New(PString(Data));
 PString(Data)^:=Header;
 Delete(PString(Data)^, 1, 7);
 RangeHM:=true;
end;

procedure RangeHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PString(Data));
end;

procedure RangeHPC(var Data:Pointer;var Response:THTTPResponse);
var S, L, T:String;
    P, N:PBodyRange;
begin
 S:=PString(Data)^;
 Dispose(PString(Data));
 Data:=nil;
 Crop(S);
 if copy(S, 1, 6)<>'bytes=' then
  begin
   New(P);
   FillChar(P^, sizeof(P^), 0);
   if Response.BodyRange=nil then
    Response.BodyRange:=P
   else
    begin
     N:=Response.BodyRange;
     while N^.Next<>nil do
      N:=N^.Next;
     N^.Next:=P;
    end;
   P^.StartR:=MAXLW;
   P^.EndR:=MAXLW;
   Exit;
  end;
 Delete(S, 1, 6);
 while S<>'' do
  begin
   if Pos(',', S)<>0 then
    begin
     L:=copy(S, 1, Pos(',', S)-1);
     Delete(S, 1, 1);
    end
   else
    L:=S;
   Delete(S, 1, Length(L));
   Crop(S);
   Crop(L);
   if (Length(L)<2) or (Pos('-', L)=0) then
    break;
   New(P);
   FillChar(P^, sizeof(P^), 0);
   if Response.BodyRange=nil then
    Response.BodyRange:=P
   else
    begin
     N:=Response.BodyRange;
     while N^.Next<>nil do
      N:=N^.Next;
     N^.Next:=P;
    end;
   if L[1]='-' then
    P^.StartR:=MAXLW
   else
    begin
     T:=copy(L, 1, Pos('-', L)-1);
     Crop(T);
     P^.StartR:=StrToInt(T);
    end;
   Delete(L, 1, Pos('-', L));
   Crop(L);
   if Length(L)=0 then
    P^.EndR:=MAXLW
   else
    P^.EndR:=StrToInt(L);
  end;
end;

{Server Header}

function ServerHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
begin
 ServerHA:=true;
end;

procedure ServerHD(var Data:Pointer);
begin
end;

procedure ServerHP(var F:TextFile;var Data:Pointer);
begin
 writeln(F, 'Server: ', SERV);
end;

{Accept-Ranges Header}

type
 PPartialContentData=^TPartialContentData;
 TPartialContentData=record
  OriginalBody:TEntityBody;
  BodyRange:PBodyRange;
  State:Byte;
  bndr:String;
  URI:String;
  O:LongWord;
 end;
 PSingleRangeData=^TSingleRangeData;
 TSingleRangeData=record
  OriginalBody:TEntityBody;
  StartR:LongWord;
  Size:LongWord;
  O:LongWord;
 end;

function PartialContentDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat; forward;

procedure PartialContentDynFree(var Data:Pointer);
begin
 FreeEntityBody(PPartialContentData(Data)^.OriginalBody);
 Dispose(PPartialContentData(Data));
end;

function SingleRangeDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
var L:LongWord;
begin
 with PSingleRangeData(Data)^ do
  begin
   if (Size-O)>S then
    L:=S
   else
    L:=Size-O;
   OriginalBody.Dyn.DynSeek(OriginalBody.Dyn.Data, StartR+O);
   Result:=OriginalBody.Dyn.DynFunct(OriginalBody.Dyn.Data, L);
   inc(O, Result.Size);
  end;
end;

procedure SingleRangeDynFree(var Data:Pointer);
begin
 FreeEntityBody(PSingleRangeData(Data)^.OriginalBody);
 Dispose(PSingleRangeData(Data));
end;

function AcceptRangesHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
var Err, m:Boolean;
    P:PBodyRange;
    D:PPartialContentData;
    D2:PSingleRangeData;
begin
 AcceptRangesHA:=true;
 New(PBoolean(Data));
 with Response.Body do
  PBoolean(Data)^:=IsDyn and (@Dyn.DynSeek<>nil) and (Dyn.FullSize<>0);
 if Response.BodyRange<>nil then
  begin
   m:=false;
   Err:=not PBoolean(Data)^;
   if not Err then
    begin
     P:=Response.BodyRange;
     while true do
      begin
       P^.Full:=Response.Body.Dyn.FullSize;
       if P^.StartR=MAXLW then
        begin
         Err:=P^.EndR>Response.Body.Dyn.FullSize;
         if not Err then
          begin
           P^.StartR:=Response.Body.Dyn.FullSize-P^.EndR;
           P^.EndR:=Response.Body.Dyn.FullSize-1;
          end;
        end
       else
        if P^.EndR=MAXLW then
         begin
          Err:=P^.StartR>=Response.Body.Dyn.FullSize;
          if not Err then
           P^.EndR:=Response.Body.Dyn.FullSize-1;
         end
        else
         Err:=(P^.StartR>P^.EndR) or (P^.EndR>=Response.Body.Dyn.FullSize);
       if Err then
        break;
       P:=P^.Next;
       if P=nil then
        break
       else
        m:=true;
      end;
    end;
   if Err then
    SetResponseError(Response, 416, 'Requested Range Not Satisfiable')
   else
    begin
     if m then
      begin
       New(D);
       FillChar(D^, sizeof(D^), 0);
       D^.URI:=Response.URI;
       D^.OriginalBody:=Response.Body;
       D^.BodyRange:=Response.BodyRange;
       D^.bndr:='simple_bndr';
       FillChar(Response.Body, sizeof(Response.Body), 0);
       with Response.Body do
        begin
         IsDyn:=true;
         Content:='multipart/byteranges; boundary='+D^.bndr;
         Dyn.Data:=D;
         Dyn.DynFunct:=PartialContentDynFunct;
         Dyn.DynFree:=PartialContentDynFree;
        end;
       ExtBody(Response.Body);
      end
     else
      begin
       New(D2);
       FillChar(D2^, sizeof(D2^), 0);
       D2^.OriginalBody:=Response.Body;
       D2^.StartR:=Response.BodyRange^.StartR;
       D2^.Size:=Response.BodyRange^.EndR-D2^.StartR+1;  
       Response.Body.Dyn.Data:=D2;
       with Response.Body.Dyn do
        begin
         DynFunct:=SingleRangeDynFunct;
         DynFree:=SingleRangeDynFree;
        end;
      end;
     SetStatusCode(Response.StatusCode, 206, 'Partial Content');
    end;
  end;
end;

procedure AcceptRangesHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PBoolean(Data));
end;

procedure AcceptRangesHP(var F:TextFile;var Data:Pointer);
begin
 write(F, 'Accept-Ranges: ');
 if PBoolean(Data)^ then
  writeln(F, 'bytes')
 else
  writeln(F, 'none');
end;

{Content-Length Header}

const
 ContentLengthH='Content-Length: ';

function ContentLengthHM(const Header:String;out Data:Pointer):Boolean;
var L:PLongInt;
    T:String;
begin
 Result:=copy(Header, 1, Length(ContentLengthH))=ContentLengthH;
 if Result then
  begin
   T:=Header;
   Delete(T, 1, Length(ContentLengthH));
   Crop(T);
   New(L);
   L^:=StrToInt(T);
   if L^<0 then
    begin
     Result:=false;
     Dispose(L);
    end
   else
    Data:=L;
  end;
end;

function ContentLengthHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
var
 PL:PLongInt;
 L:LongInt;
begin
 L:=EntityBodyLength(Response.Body);
 Result:=(Response.StatusCode.StatusCode=200) or
         (Byte(Response.StatusCode.StatusCode div 100) in [4, 5]);
 if not Result then
  Exit;
 New(PL);
 PL^:=L;
 Data:=PL;
end;

procedure ContentLengthHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PLongInt(Data));
end;

procedure ContentLengthHPC(var Data:Pointer;var Response:THTTPResponse);
begin
 Response.ToRecv:=PLongInt(Data)^;
end;

procedure ContentLengthHP(var F:TextFile;var Data:Pointer);
begin
 writeln(F, ContentLengthH, PLongInt(Data)^);
end;

{Content-Range Header}

const
 ContentRangeH='Content-Range: ';

function ContentRangeHM(const Header:String;out Data:Pointer):Boolean;
begin
 Result:=false;
end;

function ContentRangeHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
begin
 Result:=Response.BodyRange<>nil;
 if Result then
  Result:=Response.BodyRange^.Next=nil;
 Data:=nil;
 if not Result then
  Exit;
 New(PString(Data));
 PString(Data)^:=FormRange(Response.BodyRange^);
end;

procedure ContentRangeHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PString(Data));
end;

procedure ContentRangeHPC(var Data:Pointer;var Response:THTTPResponse);
begin
end;

procedure ContentRangeHP(var F:TextFile;var Data:Pointer);
begin
 writeln(F, ContentRangeH, PString(Data)^);
end;

{Content-Type Header}

const
 ContentTypeH='Content-Type: ';

function ContentTypeHM(const Header:String;out Data:Pointer):Boolean;
var T:String;
begin
 Result:=copy(Header, 1, Length(ContentTypeH))=ContentTypeH;
 if Result then
  begin
   T:=Header;
   Delete(T, 1, Length(ContentLengthH));
   Crop(T);
   New(PString(Data));
   PString(Data)^:=T;
  end;
end;

function ContentTypeHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
begin
 Result:=true;
 if (Response.Body.Content='') and (Response.URI<>'') then
  Response.Body.Content:=FindMime(Response.URI);
 if Response.Body.Content='' then
  Response.Body.Content:=DefMime;
 New(PString(Data));
 PString(Data)^:=Response.Body.Content;
end;

procedure ContentTypeHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PString(Data));
end;

procedure ContentTypeHPC(var Data:Pointer;var Response:THTTPResponse);
begin
 Response.Body.Content:=PString(Data)^;
end;

procedure ContentTypeHP(var F:TextFile;var Data:Pointer);
begin
 writeln(F, ContentTypeH, PString(Data)^);
end;

{Connection Header}

const
 ConnectionH='Connection: ';
 KeepAliveV='Keep-Alive';

function ConnectionHM(const Header:String;out Data:Pointer):Boolean;
var T:String;
begin
 Result:=copy(Header, 1, Length(ConnectionH))=ConnectionH;
 if Result then
  begin
   T:=Header;
   Delete(T, 1, Length(ConnectionH));
   Crop(T);
   New(PBoolean(Data));
   PBoolean(Data)^:=(copy(T, Length(T)-Length(KeepAliveV)+1, Length(KeepAliveV))=KeepAliveV) or (Pos(KeepAliveV+',', T)<>0);
  end;
end;

function ConnectionHA(out Data:Pointer;var Response:THTTPResponse):Boolean;
begin
 Result:=true;
 New(PBoolean(Data));
 PBoolean(Data)^:=Response.KAlive;
end;

procedure ConnectionHD(var Data:Pointer);
begin
 if Data<>nil then
  Dispose(PBoolean(Data));
end;

procedure ConnectionHPC(var Data:Pointer;var Response:THTTPResponse);
begin
 Response.KAlive:=PBoolean(Data)^;
end;

procedure ConnectionHP(var F:TextFile;var Data:Pointer);
begin
 if PBoolean(Data)^ then
  writeln(F, ConnectionH, KeepAliveV)
 else
  writeln(F, ConnectionH, 'close');
end;

{---}

const
 AMETH=4;
 Methods:array[0..AMETH-1] of String=(
  'GET', 'POST', 'OPTIONS', 'HEAD'
 );
 MethodProcess:array[0..AMETH-1] of TMethodProcess=(
  GetMP, PostMP, OptionsMP, HeadMP
 );
 AHEAD=9;
 HeaderType:array[0..AHEAD-1] of THeaderType=(
  htGeneral, htRequest, htRequest, htResponse, htResponse, htEntity, htEntity, htEntity, htGeneral
 );
 HeaderMatch:array[0..AHEAD-1] of THeaderMatch=(
  DateHM, HostHM, RangeHM, nil, nil, ContentLengthHM, ContentRangeHM, ContentTypeHM, ConnectionHM
 );
 HeaderAdd:array[0..AHEAD-1] of THeaderAdd=(
  DateHA, nil, nil, ServerHA, AcceptRangesHA, ContentLengthHA, ContentRangeHA, ContentTypeHA, ConnectionHA
 );
 HeaderDelete:array[0..AHEAD-1] of THeaderDelete=(
  DateHD, HostHD, RangeHD, ServerHD, AcceptRangesHD, ContentLengthHD, ContentRangeHD, ContentTypeHD, ConnectionHD
 );
 HeaderProcess:array[0..AHEAD-1] of THeaderProcess=(
  nil, HostHPC, RangeHPC, nil, nil, ContentLengthHPC,  ContentRangeHPC, ContentTypeHPC,ConnectionHPC
 );
 HeaderPrint:array[0..AHEAD-1] of THeaderPrint=(
  DateHP, nil, nil, ServerHP, AcceptRangesHP, ContentLengthHP, ContentRangeHP, ContentTypeHP, ConnectionHP
 );

function PartialContentDynFunct(var Data:Pointer;const S:LongWord=BufS):TEntityBodyStat;
var L:LongWord;
    str:String;
begin
 FillChar(Result, sizeof(Result), 0);
 with PPartialContentData(Data)^ do
  if State=3 then
   Exit
  else
   if BodyRange=nil then
    begin
     str:='--'+bndr+'--'#13#10#13#10;
     Result.Size:=Length(str);
     GetMem(Result.Buf, Result.Size);
     move(PChar(str)^, Result.Buf^, Result.Size);
     State:=3;
    end
   else
    case State of
    0:begin
       str:='--'+bndr+#13#10+ContentTypeH;
       if OriginalBody.Content<>'' then
        str:=str+OriginalBody.Content
       else
        if URI='' then
         str:=str+DefMime
        else
         str:=str+FindMime(URI);
       str:=str+#13#10+ContentRangeH+FormRange(BodyRange^)+#13#10#13#10;
       Result.Size:=Length(str);
       GetMem(Result.Buf, Result.Size);     
       move(PChar(str)^, Result.Buf^, Result.Size);
       inc(State);
      end;
    1:begin
       OriginalBody.Dyn.DynSeek(OriginalBody.Dyn.Data, BodyRange^.StartR+O);
       if (BodyRange^.EndR-BodyRange^.StartR+1-O)>BufS then
        L:=BufS
       else
        L:=BodyRange^.EndR-BodyRange^.StartR+1-O;
       if L=0 then
        begin
         dec(State);
         BodyRange:=BodyRange^.Next;
         O:=0;
         Result:=PartialContentDynFunct(Data);
         Exit;
        end;
       Result:=OriginalBody.Dyn.DynFunct(OriginalBody.Dyn.Data, L);
       if Result.Size<>L then
        begin
         if Result.Size<>0 then
          begin
           FreeMem(Result.Buf);
           FillChar(Result, sizeof(Result), 0);
          end;
         Exit;
        end
       else
        inc(O, L);
      end;
    end;
end;