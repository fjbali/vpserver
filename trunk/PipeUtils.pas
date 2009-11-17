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

unit PipeUtils;

interface

uses {$IFDEF MSWINDOWS}Windows{$ENDIF}, STypes;

{$IFDEF MSWINDOWS}
function CreateProcessWithPipe(const lpApplicationName:PChar;const lpCommandLine:PChar;const dwCreationFlags:LongWord;
 const lpEnvironment:Pointer;const lpCurrentDirectory:PChar;const StIn:TStartupInfo;out PI:TProcessInformation;
 out Pipe:TPipes):LongWord;
{$ENDIF}
function WinExecWithPipe(const CmdLine:String;const Show:Word;out Pipe:TPipes;out PI:TProcessInformation):LongWord;
function CreateEmptyPipe(out Pipe:TPipes):LongWord;
function DuplicatePipe(const InPipe:TPipes;out OutPipe:TPipes;const Proc:THandle):LongWord;
function OpenPipe(var Inp, Outp:TextFile;const Pipe:TPipes):Integer;
procedure ClosePipe(var Pipe:TPipes);

implementation

{$IFDEF MSWINDOWS}
function PipeFileIn(var F:TTextRec):Integer;
var
 todo:LongWord;
begin
 F.BufEnd:=0;
 F.BufPos:=0;
 if not PeekNamedPipe(F.Handle, F.BufPtr, F.BufSize, nil, @todo, nil) then
  begin
   PipeFileIn:=GetLastError;
   Exit;
  end;
 if todo=0 then
  inc(todo);
 if not (ReadFile(F.Handle, F.BufPtr^, todo, LongWord(F.BufEnd), nil) or (GetLastError=ERROR_BROKEN_PIPE)) then
  PipeFileIn:=GetLastError
 else
  PipeFileIn:=0;
end;

function PipeFileOut(var F:TTextRec):Integer;
var
 Dummy:LongWord;
begin
 if F.BufPos=0 then
   PipeFileOut:=0
 else
  begin
   if not WriteFile(F.Handle, F.BufPtr^, F.BufPos, Dummy, nil) then
    PipeFileOut:=GetLastError
   else
    PipeFileOut:=0;
   F.BufPos:=0;
  end;
end;

function PipeFileClose(var F:TTextRec):Integer;
var
 state:Boolean;
begin
 if F.Mode=fmInput then
  begin
   state:=CloseHandle(PHandle(@F.UserData)^);
   state:=CloseHandle(F.Handle) and state;
  end
 else
  begin
   state:=CloseHandle(F.Handle);
   state:=CloseHandle(PHandle(@F.UserData)^) and state;
  end;
 FreeMem(F.BufPtr);
 F.Mode:=fmClosed;
 if state then
  PipeFileClose:=0
 else
  PipeFileClose:=GetLastError;
end;

function PipeFileOpen(var F:TTextRec):Integer;
var
 P:Pointer;
begin
 PipeFileOpen:=-1;
 F.BufEnd:=0;
 case F.Mode of
  fmInput:P:=@PipeFileIn;
  fmOutput:P:=@PipeFileOut;
 else
  Exit;
 end;
 F.InOutFunc:=P;
 F.FlushFunc:=P;
 F.BufSize:=BufS;
 GetMem(F.BufPtr, F.BufSize);
{$IFDEF FPC}
 F.LineEnd:=TTextRec(Output).LineEnd;
{$ELSE}
 F.Flags:=tfCRLF;
{$ENDIF}
 PipeFileOpen:=0;
end;

procedure AssignPipe(var F:TextFile;const PipeM:THandle;const PipeO:THandle);
begin
 FillChar(F, sizeof(TTextRec), 0);
 with TTextRec(F) do
  begin
   Mode:=fmClosed;
   OpenFunc:=@PipeFileOpen;
   CloseFunc:=@PipeFileClose;
   Handle:=PipeM;
   Name:='';
   PHandle(@UserData)^:=PipeO;
  end;
end;

function OpenPipe(var Inp, Outp:TextFile;const Pipe:TPipes):Integer;
var fm:Byte;
    r:Integer;
begin
 AssignPipe(Inp, Pipe.stdout_r, Pipe.stdout_w);
 AssignPipe(Outp, Pipe.stdinp_w, Pipe.stdinp_r);
{$I-}
 Rewrite(Outp);
{$I+}
 r:=IOResult;
 if r=0 then
  begin
   fm:=FileMode;
   FileMode:=0;
{$I-}
   Reset(Inp);
{$I+}
   FileMode:=fm;
   r:=IOResult;
  end;
 OpenPipe:=r;
end;

function CreateProcessWithPipe(const lpApplicationName:PChar;const lpCommandLine:PChar;const dwCreationFlags:LongWord;
 const lpEnvironment:Pointer;const lpCurrentDirectory:PChar;const StIn:TStartupInfo;out PI:TProcessInformation;
 out Pipe:TPipes):LongWord;
var
 SI:TStartupInfo;
 OK:Boolean;
begin
 FillChar(PI, sizeof(PI), 0);
 Result:=CreateEmptyPipe(Pipe);
 if Result<>0 then
  Exit;
 SI:=StIn;
 with SI, Pipe do
  begin
   hStdInput:=stdinp_r;
   hStdOutput:=stdout_w;
   hStdError:=stdout_w;
   dwFlags:=dwFlags or STARTF_USESTDHANDLES;
  end;
 OK:=CreateProcess(lpApplicationName, lpCommandLine, nil, nil, true, dwCreationFlags, lpEnvironment, lpCurrentDirectory, SI, PI);
 if OK and (WaitForInputIdle(PI.hProcess, 0)=WAIT_TIMEOUT) then
  begin
   TerminateProcess(PI.hProcess, 0);
   OK:=false;
   SetLastError(ERROR_INVALID_PARAMETER);
  end;
 if not OK then
  begin            
   Result:=GetLastError;
   ClosePipe(Pipe);
  end;
end;

function WinExecWithPipe(const CmdLine:String;const Show:Word;out Pipe:TPipes;out PI:TProcessInformation):LongWord;
var
 SI:TStartupInfo;
begin
 FillChar(SI, sizeof(SI), 0);
 SI.cb:=sizeof(SI);
 GetStartupInfo(SI);
 SI.wShowWindow:=Show;
 SI.dwFlags:=SI.dwFlags or STARTF_USESHOWWINDOW;
 WinExecWithPipe:=CreateProcessWithPipe(nil, PChar(CmdLine), CREATE_NEW_CONSOLE, nil, nil, SI, PI, Pipe);
end;

function CreateEmptyPipe(out Pipe:TPipes):LongWord;
var OK:Boolean;
    SA:TSecurityAttributes;
begin
 FillChar(SA, sizeof(SA), 0);
 with SA do
  begin
   nLength:=sizeof(SA);
   bInheritHandle:=true;
   lpSecurityDescriptor:=nil;
  end;
 FillChar(Pipe, sizeof(Pipe), 0);
 with Pipe do
  begin
   OK:=CreatePipe(stdinp_r, stdinp_w, @SA, 0);
   if OK then
    OK:=CreatePipe(stdout_r, stdout_w, @SA, 0);
  end;
 if not OK then
  CreateEmptyPipe:=GetLastError
 else
  CreateEmptyPipe:=0;
end;

function DuplicatePipe(const InPipe:TPipes;out OutPipe:TPipes;const Proc:THandle):LongWord;
var OK:Boolean;
begin
 OK:=DuplicateHandle(GetCurrentProcess, InPipe.stdinp_r, Proc, @OutPipe.stdinp_r, 0, true, DUPLICATE_SAME_ACCESS);
 if OK then
  OK:=DuplicateHandle(GetCurrentProcess, InPipe.stdinp_w, Proc, @OutPipe.stdinp_w, 0, true, DUPLICATE_SAME_ACCESS);
 if OK then
  OK:=DuplicateHandle(GetCurrentProcess, InPipe.stdout_r, Proc, @OutPipe.stdout_r, 0, true, DUPLICATE_SAME_ACCESS);
 if OK then
  OK:=DuplicateHandle(GetCurrentProcess, InPipe.stdout_w, Proc, @OutPipe.stdout_w, 0, true, DUPLICATE_SAME_ACCESS);
 if OK then
  DuplicatePipe:=0
 else
  DuplicatePipe:=GetLastError;
end;

procedure ClosePipe(var Pipe:TPipes);
begin
 if Pipe.stdinp_r<>INVALID_HANDLE_VALUE then
  CloseHandle(Pipe.stdinp_r);
 if Pipe.stdinp_w<>INVALID_HANDLE_VALUE then
  CloseHandle(Pipe.stdinp_w);
 if Pipe.stdout_w<>INVALID_HANDLE_VALUE then
  CloseHandle(Pipe.stdout_w);
 if Pipe.stdout_r<>INVALID_HANDLE_VALUE then
  CloseHandle(Pipe.stdout_r);
end;
{$ENDIF}

end.
