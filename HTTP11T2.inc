procedure DeleteHeaders(var Headers:THeaders);
var
 p:LongWord;
 T:PHeader;
begin
 for p:=1 to Headers.Count do
  begin
   T:=GetHeader(Headers, p);
   if T=nil then
    continue;
   HeaderDelete[T^.Header](T^.Data);
   Dispose(T);
  end;
 FreeMem(Headers.Headers);
end;