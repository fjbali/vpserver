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

{
  Original author: Lorien - datamg@rambler.ru
  Ported by VP - viktprog@gmail.com

  Copyright (c) 2009
}

type
 PMIMETypeContent=^TMIMETypeContent;
 TMIMETypeContent=record
  Ext:String;
  Mime:String;
 end;
 PMIMETypes=^TMIMETypes;
 TMIMETypes=record
  inMemory:LongWord;
  cMIMETypes:Pointer;
 end;

var
 varMime:PMIMETypes;

function FindMime(const URI:String):String;
var
 ms, s:String;
 i:LongWord;
 c:PMIMETypeContent;
{$IFNDEF MEGA_CACHE}
 Mime:TextFile;
 mext:String;
 newMime:PMIMETypes;
{$ENDIF}
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
 for i:=1 to varMime^.inMemory do
  begin
   c:=PMIMETypeContent(Pointer(@membuf(varMime^.cMIMETypes)^[(i-1)*sizeof(PMIMETypeContent)+1])^);
   if c^.Ext=s then
    begin
     Result:=c^.Mime;
     Exit;
    end;
  end;
{$IFNDEF MEGA_CACHE}
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
   mext:=copy(ms, 1, Pos(' ', ms)-1);
   Delete(ms, 1, Length(mext)+1);
   if mext=s then
    begin
     New(c);
     New(newMime);
     newMime^.inMemory:=varMime^.inMemory+1;
     GetMem(newMime^.cMIMETypes, sizeof(PMIMETypeContent)*newMime^.inMemory);
     if varMime^.inMemory<>0 then
      begin
       move(varMime^.cMIMETypes^, newMime^.cMIMETypes^, sizeof(PMIMETypeContent)*varMime^.inMemory);
       FreeMem(varMime^.cMIMETypes);
      end;
     PMIMETypeContent(Pointer(@membuf(newMime^.cMIMETypes)^[varMime^.inMemory*sizeof(PMIMETypeContent)+1])^):=c;
     c^.Ext:=mext;
     c^.Mime:=ms;
     Dispose(varMime);
     varMime:=newMime;
     Result:=ms;
     break;
    end;
  end;
 Close(Mime);
{$ENDIF}
end;

procedure MimeInit;
begin
 New(varMime);
 FillChar(varMime^, sizeof(varMime^), 0);
{$IFDEF MEGA_CACHE}
{$ENDIF}
end;

procedure MimeDestroy;
var
 i:LongWord;
begin
 if varMime^.cMIMETypes<>nil then
  begin
   for i:=1 to varMime^.inMemory do
    Dispose(PMIMETypeContent(Pointer(@membuf(varMime^.cMIMETypes)^[(i-1)*sizeof(PMIMETypeContent)+1])^));
   FreeMem(varMime^.cMIMETypes);
  end;
 Dispose(varMime);
end;
