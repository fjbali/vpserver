unit SLog;

interface

uses STypes;

procedure ConsoleLog(const Msg:String);
procedure StartDialog;
procedure StopDialog;
procedure SetLogLevel(const Lev:Byte);
function GetInputLine:String;
procedure WriteInputLine(const S:String);

implementation

uses SUtils{$IFNDEF FPC}, Windows{$ENDIF};

var Ride:TRide;
    cons:Integer=0;

procedure ConsoleLog(const Msg:String);
var Sh:String;
begin
 StartRide(Ride);
 if InterlockedIncrement(cons)<>1 then
  Sh:=#13+Msg+#13#10+PROMPT
 else
  Sh:=Msg+#13#10;
 write(Sh);
 InterlockedDecrement(cons);
 StopRide(Ride);
end;

procedure StartDialog;
begin
end;

procedure StopDialog;
begin
 ConsoleLog('');
end;

procedure SetLogLevel(const Lev:Byte); 
begin
end;

function GetInputLine:String;
begin
 if InterlockedIncrement(cons)=1 then
  write(#13#10+PROMPT);
 readln(Result);
 InterlockedDecrement(cons);
end;

procedure WriteInputLine(const S:String);
begin
 if InterlockedIncrement(cons)=1 then
  write(#13#10+PROMPT);
 StartRide(Ride);
 writeln(S);
 StopRide(Ride);
 InterlockedDecrement(cons);
end;

initialization
 Ride:=RegisterRide;
finalization
 UnregisterRide(Ride);
end.
