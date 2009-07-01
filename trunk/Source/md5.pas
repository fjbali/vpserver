unit md5;

interface

{
 Version of MD5 algorithm for Pascal
 Copyright (c) Ivanov Viktor 2009

 Special for VPSERVER
}

{
  Copyright (C) 1999, 2000, 2002 Aladdin Enterprises.  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  L. Peter Deutsch
  ghost@aladdin.com

}
{
  Independent implementation of MD5 (RFC 1321).

  This code implements the MD5 Algorithm defined in RFC 1321, whose
  text is available at
	http://www.ietf.org/rfc/rfc1321.txt
  The code is derived from the text of the RFC, including the test suite
  (section A.5) but excluding the rest of Appendix A.  It does not include
  any code or documentation that is identified in the RFC as being
  copyrighted.

  The original and principal author of md5.c is L. Peter Deutsch
  <ghost@aladdin.com>.  Other authors are noted in the change history
  that follows (in reverse chronological order):

  2002-04-13 lpd Clarified derivation from RFC 1321; now handles byte order
	either statically or dynamically; added missing #include <string.h>
	in library.
  2002-03-11 lpd Corrected argument list for main(), and added int return
	type, in test program and T value program.
  2002-02-21 lpd Added missing #include <stdio.h> in test program.
  2000-07-03 lpd Patched to eliminate warnings about "constant is
	unsigned in ANSI C, signed in traditional"; made test program
	self-checking.
  1999-11-04 lpd Edited comments slightly for automatic TOC extraction.
  1999-10-18 lpd Fixed typo in header comment (ansi2knr rather than md5).
  1999-05-03 lpd Original version.
}

type md5_state=record
  count:array[0..1] of LongWord;
  abcd:array[0..3] of LongWord;
  buf:array[0..63] of Byte;
 end;

procedure md5_init(var pms:md5_state);
procedure md5_append(var pms:md5_state;var Buf;Size:LongWord);
function md5_finish(var pms:md5_state):String;

implementation

const
 T1=$d76aa478;
 T2=$e8c7b756;
 T3=$242070db;
 T4=$c1bdceee;
 T5=$f57c0faf;
 T6=$4787c62a;
 T7=$a8304613;
 T8=$fd469501;
 T9=$698098d8;
 T10=$8b44f7af;
 T11=$ffff5bb1;
 T12=$895cd7be;
 T13=$6b901122;
 T14=$fd987193;
 T15=$a679438e;
 T16=$49b40821;
 T17=$f61e2562;
 T18=$c040b340;
 T19=$265e5a51;
 T20=$e9b6c7aa;
 T21=$d62f105d;
 T22=$02441453;
 T23=$d8a1e681;
 T24=$e7d3fbc8;
 T25=$21e1cde6;
 T26=$c33707d6;
 T27=$f4d50d87;
 T28=$455a14ed;
 T29=$a9e3e905;
 T30=$fcefa3f8;
 T31=$676f02d9;
 T32=$8d2a4c8a;
 T33=$fffa3942;
 T34=$8771f681;
 T35=$6d9d6122;
 T36=$fde5380c;
 T37=$a4beea44;
 T38=$4bdecfa9;
 T39=$f6bb4b60;
 T40=$bebfbc70;
 T41=$289b7ec6;
 T42=$eaa127fa;
 T43=$d4ef3085;
 T44=$04881d05;
 T45=$d9d4d039;
 T46=$e6db99e5;
 T47=$1fa27cf8;
 T48=$c4ac5665;
 T49=$f4292244;
 T50=$432aff97;
 T51=$ab9423a7;
 T52=$fc93a039;
 T53=$655b59c3;
 T54=$8f0ccc92;
 T55=$ffeff47d;
 T56=$85845dd1;
 T57=$6fa87e4f;
 T58=$fe2ce6e0;
 T59=$a3014314;
 T60=$4e0811a1;
 T61=$f7537e82;
 T62=$bd3af235;
 T63=$2ad7d2bb;
 T64=$eb86d391;

procedure md5_process(var pms:md5_state;var Buf);
var x_:array[0..15] of LongWord absolute Buf;
function r_left(x, n:LongWord):LongWord;
begin
 r_left:=(x shl n) or (x shr (32 - n));
end;
function f(x, y, z:LongWord):LongWord;
begin
 f:=(x and y) or ((not x) and z);
end;
function g(x, y, z:LongWord):LongWord;
begin
 g:=(x and z) or (y and (not z));
end;
function h(x, y, z:LongWord):LongWord;
begin
 h:=x xor y xor z;
end;
function i(x, y, z:LongWord):LongWord;
begin
 i:=y xor (x or (not z));
end;
procedure SET1(var a:LongWord;b, c, d, k, s, t:LongWord);
var m:LongWord;
begin
 m:=a+f(b, c, d)+x_[k]+t;
 a:=r_left(m, s)+b;
end;
procedure SET2(var a:LongWord;b, c, d, k, s, t:LongWord);
var m:LongWord;
begin        
 m:=a+g(b, c, d)+x_[k]+t;
 a:=r_left(m, s)+b;
end;
procedure SET3(var a:LongWord;b, c, d, k, s, t:LongWord);
var m:LongWord;
begin         
 m:=a+h(b, c, d)+x_[k]+t;
 a:=r_left(m, s)+b;
end;
procedure SET4(var a:LongWord;b, c, d, k, s, t:LongWord);
var m:LongWord;
begin
 m:=a+i(b, c, d)+x_[k]+t;
 a:=r_left(m, s)+b;
end;
var a, b, c, d:LongWord;
begin
 a:=pms.abcd[0];
 b:=pms.abcd[1];
 c:=pms.abcd[2];
 d:=pms.abcd[3];
 SET1(a, b, c, d,  0,  7,  T1);
 SET1(d, a, b, c,  1, 12,  T2);
 SET1(c, d, a, b,  2, 17,  T3);
 SET1(b, c, d, a,  3, 22,  T4);
 SET1(a, b, c, d,  4,  7,  T5);
 SET1(d, a, b, c,  5, 12,  T6);
 SET1(c, d, a, b,  6, 17,  T7);
 SET1(b, c, d, a,  7, 22,  T8);
 SET1(a, b, c, d,  8,  7,  T9);
 SET1(d, a, b, c,  9, 12, T10);
 SET1(c, d, a, b, 10, 17, T11);
 SET1(b, c, d, a, 11, 22, T12);
 SET1(a, b, c, d, 12,  7, T13);
 SET1(d, a, b, c, 13, 12, T14);
 SET1(c, d, a, b, 14, 17, T15);
 SET1(b, c, d, a, 15, 22, T16);  
 SET2(a, b, c, d,  1,  5, T17);
 SET2(d, a, b, c,  6,  9, T18);
 SET2(c, d, a, b, 11, 14, T19);
 SET2(b, c, d, a,  0, 20, T20);
 SET2(a, b, c, d,  5,  5, T21);
 SET2(d, a, b, c, 10,  9, T22);
 SET2(c, d, a, b, 15, 14, T23);
 SET2(b, c, d, a,  4, 20, T24);
 SET2(a, b, c, d,  9,  5, T25);
 SET2(d, a, b, c, 14,  9, T26);
 SET2(c, d, a, b,  3, 14, T27);
 SET2(b, c, d, a,  8, 20, T28);
 SET2(a, b, c, d, 13,  5, T29);
 SET2(d, a, b, c,  2,  9, T30);
 SET2(c, d, a, b,  7, 14, T31);
 SET2(b, c, d, a, 12, 20, T32);
 SET3(a, b, c, d,  5,  4, T33);
 SET3(d, a, b, c,  8, 11, T34);
 SET3(c, d, a, b, 11, 16, T35);
 SET3(b, c, d, a, 14, 23, T36);
 SET3(a, b, c, d,  1,  4, T37);
 SET3(d, a, b, c,  4, 11, T38);
 SET3(c, d, a, b,  7, 16, T39);
 SET3(b, c, d, a, 10, 23, T40);
 SET3(a, b, c, d, 13,  4, T41);
 SET3(d, a, b, c,  0, 11, T42);
 SET3(c, d, a, b,  3, 16, T43);
 SET3(b, c, d, a,  6, 23, T44);
 SET3(a, b, c, d,  9,  4, T45);
 SET3(d, a, b, c, 12, 11, T46);
 SET3(c, d, a, b, 15, 16, T47);
 SET3(b, c, d, a,  2, 23, T48);
 SET4(a, b, c, d,  0,  6, T49);
 SET4(d, a, b, c,  7, 10, T50);
 SET4(c, d, a, b, 14, 15, T51);
 SET4(b, c, d, a,  5, 21, T52);
 SET4(a, b, c, d, 12,  6, T53);
 SET4(d, a, b, c,  3, 10, T54);
 SET4(c, d, a, b, 10, 15, T55);
 SET4(b, c, d, a,  1, 21, T56);
 SET4(a, b, c, d,  8,  6, T57);
 SET4(d, a, b, c, 15, 10, T58);
 SET4(c, d, a, b,  6, 15, T59);
 SET4(b, c, d, a, 13, 21, T60);
 SET4(a, b, c, d,  4,  6, T61);
 SET4(d, a, b, c, 11, 10, T62);
 SET4(c, d, a, b,  2, 15, T63);
 SET4(b, c, d, a,  9, 21, T64);
 inc(pms.abcd[0], a);
 inc(pms.abcd[1], b);
 inc(pms.abcd[2], c);
 inc(pms.abcd[3], d);
end;

procedure md5_init(var pms:md5_state);
begin
 pms.count[0]:=0;
 pms.count[1]:=0;
 pms.abcd[0]:=$67452301;     
 pms.abcd[1]:=$efcdab89;
 pms.abcd[2]:=$98badcfe;
 pms.abcd[3]:=$10325476;
end;

procedure md5_append(var pms:md5_state;var Buf;Size:LongWord);
var left, offset, nbits, copy_, p:LongWord;
    data:array[0..MaxInt-1] of Byte absolute Buf;
begin
 if Size=0 then
  Exit;
 left:=Size;
 offset:=(pms.count[0] shr 3) and 63;
 nbits:=Size shl 3;
 inc(pms.count[1], Size shr 29);
 inc(pms.count[0], nbits);
 if pms.count[0]<nbits then
  inc(pms.count[1]);
 p:=0;
 if offset>0 then
  begin
   if (offset+Size)>64 then
    copy_:=64-offset
   else
    copy_:=Size;
   move(Buf, pms.buf[offset], copy_);
   if (offset+copy_)<64 then
    Exit;
   inc(p, copy_);
   dec(left, copy_);
   md5_process(pms, pms.buf);
  end;
 while left>=64 do
  begin
   md5_process(pms, data[p]);
   inc(p, 64);
   dec(left, 64);
  end;
 if left>0 then
  move(data[p], pms.buf, left);
end;

function md5_finish(var pms:md5_state):String;
type padt=array[0..63] of Byte;
const pad:padt=($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
function Hex(t:Byte):String;
function ICH(a:Byte):Char;
begin
 if a>9 then
  ICH:=chr(ord('a')+a-10)
 else
  ICH:=chr(ord('0')+a);
end;
begin
 Hex:=ICH(t div 16)+ICH(t mod 16);
end;
var data:array[0..7] of Byte;
    i:LongWord;
    r:String;
    pad2:padt;
begin
 for i:=0 to 7 do
  data[i]:=pms.count[i shr 2] shr ((i and 3) shl 3);
 pad2:=pad;
 md5_append(pms, pad2, ((55-(pms.count[0] shr 3)) and 63)+1);
 md5_append(pms, data, 8);
 r:='';
 for i:=0 to 15 do
  r:=r+Hex((pms.abcd[i shr 2] shr ((i and 3) shl 3)));
 md5_finish:=r;
end;

end.
