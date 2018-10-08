#!/usr/bin/perl
# Perl script written by Peter Van Eeckhoutte
# http://www.corelan.be
# This script takes a string as argument
# and will produce the opcodes 
# to push this string onto the stack
#
#
#C:\shellcode>perl pvePushString.pl
#  usage: pvePushString.pl "String to put on stack"
#
#C:\shellcode>perl pvePushString.pl "Corelan"
#String length : 7
#Opcodes to push this string onto the stack :
#
#"\x68\x6c\x61\x6e\x00"    //PUSH 0x006e616c
#"\x68\x43\x6f\x72\x65"    //PUSH 0x65726f43
#
#C:\shellcode>perl pvePushString.pl "You have been pwned by Corelan"
#String length : 30
#Opcodes to push this string onto the stack :
#
#"\x68\x61\x6e\x20\x00"    //PUSH 0x00206e61
#"\x68\x6f\x72\x65\x6c"    //PUSH 0x6c65726f
#"\x68\x62\x79\x20\x43"    //PUSH 0x43207962
#"\x68\x6e\x65\x64\x20"    //PUSH 0x2064656e
#"\x68\x6e\x20\x70\x77"    //PUSH 0x7770206e
#"\x68\x20\x62\x65\x65"    //PUSH 0x65656220
#"\x68\x68\x61\x76\x65"    //PUSH 0x65766168
#"\x68\x59\x6f\x75\x20"    //PUSH 0x20756f59

if ($#ARGV ne 0) { 
print "  usage: $0 ".chr(34)."String to put on stack".chr(34)."\n"; 
exit(0); 
} 
#convert string to bytes
my $strToPush=$ARGV[0];
my $strThisChar="";
my $strThisHex="";
my $cnt=0;
my $bytecnt=0;
my $strHex="";
my $strOpcodes="";
my $strPush="";
print "String length : " . length($strToPush)."\n";
print "Opcodes to push this string onto the stack :\n\n";
while ($cnt < length($strToPush))
{
  $strThisChar=substr($strToPush,$cnt,1);
  $strThisHex="\\x".ascii_to_hex($strThisChar);
  if ($bytecnt < 3)
  {
     $strHex=$strHex.$strThisHex;
    $bytecnt=$bytecnt+1;
  }
  else
  {
    $strPush = $strHex.$strThisHex;
    $strPush =~ tr/\\x//d;
    $strHex=chr(34)."\\x68".$strHex.$strThisHex.chr(34).
   "    //PUSH 0x".substr($strPush,6,2).substr($strPush,4,2).
   substr($strPush,2,2).substr($strPush,0,2);
   
    $strOpcodes=$strHex."\n".$strOpcodes;
    $strHex="";
   $bytecnt=0;
  }
  $cnt=$cnt+1;
}
#last line
if (length($strHex) > 0)
{
  while(length($strHex) < 12)
  {
    $strHex=$strHex."\\x20";
  }
  $strPush = $strHex;
  $strPush =~ tr/\\x//d;  
  $strHex=chr(34)."\\x68".$strHex."\\x00".chr(34)."    //PUSH 0x00".
  substr($strPush,4,2).substr($strPush,2,2).substr($strPush,0,2);
  $strOpcodes=$strHex."\n".$strOpcodes;
}
else
{
  #add line with spaces + null byte (string terminator)
  $strOpcodes=chr(34)."\\x68\\x20\\x20\\x20\\x00".chr(34).
              "    //PUSH 0x00202020"."\n".$strOpcodes;
}
print $strOpcodes;


sub ascii_to_hex ($)    
{       
   (my $str = shift) =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;       
   return $str;    
}


