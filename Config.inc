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

{$DEFINE DECLARE_GPL}

const
{$IF NOT DECLARED(GPL)}
 GPL=true;
{$IFEND}
 VER=3.0;
 SNAME='VPSERVER';
 BUILDVER=1.2;
 TermTimeout=1000;
 BufS=4096;
 SSTATUS=psAlpha;
 PROMPT='>';
 LogoText='-------------------------------------------'#13#10+
          'Авторские права (С) Иванов Виктор, 2009 год'#13#10+
          '-------------------------------------------'#13#10+
{$IF DECLARED(GPL)}
    #13#10'Программа распространяется БЕЗ ВСЯКИХ ГАРАНТИЙ;'#13#10+
          'является свободным программным обеспечением и Вы можете'#13#10+
          'распространять ее в соответствии с условиями Стандартной'#13#10+
          'Общественной Лицензии GNU (GNU GPL). Более подробная'#13#10+
          'информация находится в файле "License.txt"'#13#10+
{$IFEND}
    #13#10'Загрузка...'#13#10;
