
{$DEFINE DECLARE_GPL}

const
{$IF NOT DECLARED(GPL)}
 GPL=true;
{$IFEND}
 VER=3.0;
 SNAME='VPSERVER';
 BUILDVER=0.9;
 TermTimeout=1000;
 BufS=4096;
 SSTATUS=psPreAlpha;
 PROMPT='>';
 LogoText='-------------------------------------------'#13#10+
          'Авторские права (С) Иванов Виктор, 2009 год'#13#10+
          '-------------------------------------------'#13#10+
{$IF DECLARED(GPL)}
    #13#10'Программа рапростроняется на условиях GNU GPL'#13#10+
{$IFEND}
    #13#10'Загрузка...'#13#10;
