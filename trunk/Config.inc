
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
          '��������� ����� (�) ������ ������, 2009 ���'#13#10+
          '-------------------------------------------'#13#10+
{$IF DECLARED(GPL)}
    #13#10'��������� ��������������� �� �������� GNU GPL'#13#10+
{$IFEND}
    #13#10'��������...'#13#10;