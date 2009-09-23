unit PipeUtils;

interface

uses {$IFDEF MSWINDOWS}Windows{$ELSE}Process, Pipes{$ENDIF}, STypes;

{$IFDEF MSWINDOWS}
function CreateProcessWithPipe(const lpApplicationName:PChar;const lpCommandLine:PChar;const dwCreationFlags:LongWord;
 const lpEnvironment:Pointer;const lpCurrentDirectory:PChar;const StIn:TStartupInfo;out PI:TProcessInformation;
 out Pipe:TPipes):LongWord;
{$ENDIF}
function WinExecWithPipe(const CmdLine:String;const Show:Word;out Pipe:TPipes;out PI:TProcessInformation):LongWord;
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
 SA:TSecurityAttributes;
 OK:Boolean;
begin
 FillChar(PI, sizeof(PI), 0);
 with SA do
  begin
   nLength:=sizeof(SA);
   bInheritHandle:=true;
   lpSecurityDescriptor:=nil;
  end;
 FillChar(Pipe, sizeof(Pipe), 0);
 with Pipe, SI do
  begin
   OK:=CreatePipe(stdinp_r, stdinp_w, @SA, 0);
   if OK then
    OK:=CreatePipe(stdout_r, stdout_w, @SA, 0);
   if OK then
    begin
     SI:=StIn;
     hStdInput:=stdinp_r;
     hStdOutput:=stdout_w;
     hStdOutput:=stdout_w;
     dwFlags:=dwFlags or STARTF_USESTDHANDLES;
     OK:=CreateProcess(lpApplicationName, lpCommandLine, @SA, @SA, true, dwCreationFlags, lpEnvironment, lpCurrentDirectory, SI, PI);
    end;
   if WaitForInputIdle(PI.hProcess, 0)=WAIT_TIMEOUT then
    begin
     TerminateProcess(PI.hProcess, 0);
     OK:=false;
     SetLastError(ERROR_INVALID_PARAMETER);
    end;
   if not OK then
    begin
     CreateProcessWithPipe:=GetLastError;
     CloseHandle(stdinp_r);
     CloseHandle(stdinp_w);
     CloseHandle(stdout_r);
     CloseHandle(stdout_w);
    end
   else
    CreateProcessWithPipe:=0;
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

procedure ClosePipe(var Pipe:TPipes);
begin
 CloseHandle(Pipe.stdinp_r);
 CloseHandle(Pipe.stdinp_w);
 CloseHandle(Pipe.stdout_w);
 CloseHandle(Pipe.stdout_r);
end;

{$ELSE}
function WinExecWithPipe(const CmdLine:String;const Show:Word;out Pipe:TPipes;out PI:TProcessInformation):LongWord;
begin
 PI:=TProcess.Create(nil);
 PI.Options:=[poUsePipes, poStderrToOutPut];
 PI.CommandLine:=CmdLine;
 try
  PI.Execute;
  Pipe.OutP:=PI.Output;
  Pipe.InP:=PI.Input;
  Result:=0;
 except on EProcess
  Result:=INFINITE;
 end;
end;

procedure ClosePipe(var Pipe:TPipes);
begin
 Pipe.OutP.Destroy;
 Pipe.InP.Destroy;
end;
{$ENDIF}

end.
