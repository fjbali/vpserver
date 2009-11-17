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