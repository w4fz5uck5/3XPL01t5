# Boofuzz FTP Fuzzer
# By w4fz5uck5
from boofuzz import * 
import time

session = Session(
    target=Target(
        connection=SocketConnection("192.168.0.111", 21, proto='tcp', send_timeout=10.0, recv_timeout=10.0)))

s_initialize("user")
s_static("USER ")
s_string("anonymous")
s_static("\r\n")
s_static("PASS \r\n")

s_initialize("pass")
s_static("USER anonymous\r\n")
s_static("PASS ")
s_string("BBBB")
s_static("\r\n")

s_initialize('ABOR')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('ABOR ')
s_string('AAAA')
s_static('\r\n')

s_initialize('ACCT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('ACCT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('ADAT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('ADAT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('ALLO')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('ALLO ')
s_string('AAAA')
s_static('\r\n')

s_initialize('APPE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('APPE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('AUTH')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('AUTH ')
s_string('AAAA')
s_static('\r\n')

s_initialize('AVBL')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('AVBL ')
s_string('AAAA')
s_static('\r\n')

s_initialize('CCC')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('CCC ')
s_string('AAAA')
s_static('\r\n')

s_initialize('CDUP')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('CDUP ')
s_string('AAAA')
s_static('\r\n')

s_initialize('CONF')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('CONF ')
s_string('AAAA')
s_static('\r\n')

s_initialize('CSID')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('CSID ')
s_string('AAAA')
s_static('\r\n')

s_initialize('CWD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('CWD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('DELE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('DELE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('DSIZ')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('DSIZ ')
s_string('AAAA')
s_static('\r\n')

s_initialize('ENC')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('ENC ')
s_string('AAAA')
s_static('\r\n')

s_initialize('EPRT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('EPRT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('EPSV')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('EPSV ')
s_string('AAAA')
s_static('\r\n')

s_initialize('FEAT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('FEAT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('HELP')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('HELP ')
s_string('AAAA')
s_static('\r\n')

s_initialize('HOST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('HOST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('LANG')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('LANG ')
s_string('AAAA')
s_static('\r\n')

s_initialize('LIST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('LIST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('LPRT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('LPRT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('LPSV')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('LPSV ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MDTM')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MDTM ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MFCT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MFCT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MFF')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MFF ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MFMT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MFMT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MIC')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MIC ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MKD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MKD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MLSD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MLSD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MLST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MLST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('MODE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('MODE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('NLST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('NLST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('NOOP')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('NOOP ')
s_string('AAAA')
s_static('\r\n')

s_initialize('OPTS')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('OPTS ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PASS')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PASS ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PASV')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PASV ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PBSZ')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PBSZ ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PORT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PORT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PROT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PROT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('PWD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('PWD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('QUIT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('QUIT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('REIN')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('REIN ')
s_string('AAAA')
s_static('\r\n')

s_initialize('REST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('REST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('RETR')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('RETR ')
s_string('AAAA')
s_static('\r\n')

s_initialize('RMD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('RMD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('RMDA')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('RMDA ')
s_string('AAAA')
s_static('\r\n')

s_initialize('RNFR')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('RNFR ')
s_string('AAAA')
s_static('\r\n')

s_initialize('RNTO')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('RNTO ')
s_string('AAAA')
s_static('\r\n')

s_initialize('SITE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('SITE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('SIZE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('SIZE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('SMNT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('SMNT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('SPSV')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('SPSV ')
s_string('AAAA')
s_static('\r\n')

s_initialize('STAT')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('STAT ')
s_string('AAAA')
s_static('\r\n')

s_initialize('STOR')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('STOR ')
s_string('AAAA')
s_static('\r\n')

s_initialize('STOU')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('STOU ')
s_string('AAAA')
s_static('\r\n')

s_initialize('STRU')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('STRU ')
s_string('AAAA')
s_static('\r\n')

s_initialize('SYST')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('SYST ')
s_string('AAAA')
s_static('\r\n')

s_initialize('THMB')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('THMB ')
s_string('AAAA')
s_static('\r\n')

s_initialize('TYPE')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('TYPE ')
s_string('AAAA')
s_static('\r\n')

s_initialize('USER')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('USER ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XCUP')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XCUP ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XMKD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XMKD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XPWD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XPWD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XRCP')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XRCP ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XRMD')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XRMD ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XRSQ')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XRSQ ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XSEM')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XSEM ')
s_string('AAAA')
s_static('\r\n')

s_initialize('XSEN')
s_static('USER anonymous\r\n')
s_static('PASS \r\n')
s_static('XSEN ')
s_string('AAAA')
s_static('\r\n')

session.connect(s_get("user"))

session.connect(s_get("pass"))

session.connect(s_get('ABOR'))

session.connect(s_get('ACCT'))

session.connect(s_get('ADAT'))

session.connect(s_get('ALLO'))

session.connect(s_get('APPE'))

session.connect(s_get('AUTH'))

session.connect(s_get('AVBL'))

session.connect(s_get('CCC'))

session.connect(s_get('CDUP'))

session.connect(s_get('CONF'))

session.connect(s_get('CSID'))

session.connect(s_get('CWD'))

session.connect(s_get('DELE'))

session.connect(s_get('DSIZ'))

session.connect(s_get('ENC'))

session.connect(s_get('EPRT'))

session.connect(s_get('EPSV'))

session.connect(s_get('FEAT'))

session.connect(s_get('HELP'))

session.connect(s_get('HOST'))

session.connect(s_get('LANG'))

session.connect(s_get('LIST'))

session.connect(s_get('LPRT'))

session.connect(s_get('LPSV'))

session.connect(s_get('MDTM'))

session.connect(s_get('MFCT'))

session.connect(s_get('MFF'))

session.connect(s_get('MFMT'))

session.connect(s_get('MIC'))

session.connect(s_get('MKD'))

session.connect(s_get('MLSD'))

session.connect(s_get('MLST'))

session.connect(s_get('MODE'))

session.connect(s_get('NLST'))

session.connect(s_get('NOOP'))

session.connect(s_get('OPTS'))

session.connect(s_get('PASS'))

session.connect(s_get('PASV'))

session.connect(s_get('PBSZ'))

session.connect(s_get('PORT'))

session.connect(s_get('PROT'))

session.connect(s_get('PWD'))

session.connect(s_get('QUIT'))

session.connect(s_get('REIN'))

session.connect(s_get('REST'))

session.connect(s_get('RETR'))

session.connect(s_get('RMD'))

session.connect(s_get('RMDA'))

session.connect(s_get('RNFR'))

session.connect(s_get('RNTO'))

session.connect(s_get('SITE'))

session.connect(s_get('SIZE'))

session.connect(s_get('SMNT'))

session.connect(s_get('SPSV'))

session.connect(s_get('STAT'))

session.connect(s_get('STOR'))

session.connect(s_get('STOU'))

session.connect(s_get('STRU'))

session.connect(s_get('SYST'))

session.connect(s_get('THMB'))

session.connect(s_get('TYPE'))

session.connect(s_get('USER'))

session.connect(s_get('XCUP'))

session.connect(s_get('XMKD'))

session.connect(s_get('XPWD'))

session.connect(s_get('XRCP'))

session.connect(s_get('XRMD'))

session.connect(s_get('XRSQ'))

session.connect(s_get('XSEM'))

session.connect(s_get('XSEN'))

session.fuzz()
                 
