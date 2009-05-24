library plugext;

var gbuf:array[Byte] of Char;

function MGetInfo:PChar; export; stdcall;
begin
 MGetInfo:=PChar(@gbuf);
end;

function MInitProc(var h:LongWord):Boolean; export; stdcall;
begin
 h:=0;
 MInitProc:=true;
end;

procedure MRelProc(h:LongWord); export; stdcall;
begin
end;

function MMethProc(h:LongWord;Meth:PChar):Boolean; export; stdcall;
begin
 MMethProc:=false;
end;

function MHeadProc(h:LongWord;HName:PChar;HVal:PChar):Boolean; export; stdcall;
begin
 MHeadProc:=false;
end;

procedure MLoadProc(h:LongWord;var Buf;Size:LongWord); export; stdcall;
begin
end;

procedure MLoadGetProc(h:LongWord;GETLine:PChar); export; stdcall;
begin
end;

procedure MLoadMeth(h:LongWord;Meth:PChar); export; stdcall;
begin
end;

function MQueryProc(h:LongWord;PartOP, OptOP, KAlive, PostOP:Boolean;ppath:PChar):Boolean; export; stdcall;
begin
 MQueryProc:=false;
end;

function MUpdateParamsProc(h:LongWord;var PartOP, OptOP, KAlive:Boolean;resph:PChar):LongWord; export;
begin
 MUpdateParamsProc:=0;
end;

function MGetHLine(h:LongWord;n:LongWord;main:Boolean):PChar; export; stdcall;
begin
 MGetHLine:=PChar(@gbuf);
end;

function MSetPosProc(h:LongWord;var ofs:LongInt):Boolean; export; stdcall;
begin
 MSetPosProc:=false;
end;

procedure MReadProc(h:LongWord;var Buf;BufSize:LongWord;var RealRead:LongInt); export; stdcall;
begin
end;

function MConfProc(s:PChar):Boolean; export; stdcall;
begin
 MConfProc:=false;
end;

procedure MLoadPostProc(h:LongWord;var Buf;Size:LongWord); stdcall;
begin
end;

exports MGetInfo, MInitProc, MRelProc, MMethProc, MHeadProc, MLoadProc, MLoadGetProc,
        MLoadMeth, MQueryProc, MUpdateParamsProc, MGetHLine, MSetPosProc, MReadProc,
        MConfProc, MLoadPostProc;

begin
 Move(PChar('plugext 1.0 Build 1 Copyright (c) Ivanov Viktor 2009')^, gbuf, 53);
end.
