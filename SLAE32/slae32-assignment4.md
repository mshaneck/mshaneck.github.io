---
layout: page
title: SLAE32 Assignment 4
comments: true
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 4: Custom Encoder</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

Assignment 4 calls for a custom encoder. The encoder is simply a mechanism to transform the bytes into a less recognizable form, and couple onto it a decoding stub, that will perform the inverse transformation. In the class, a simple XOR encoder was covered where a single byte was used to xor each individual byte of the shellcode. In a subsequent video, the same technique was shown using xmm registers. I liked the idea of using obscure registers and I also like the simplicity of the xor operation.

However, I wanted to implement something above and beyond what was covered in the course, so I decided to extend the xmm xor technique. In the video, he used a single byte repeated over and over. My idea was to use a 128 bit random value and xor the entire thing with 128 bits of shellcode. Then, in order to prevent exact reuse of the key for each 128 bit block, I decided to rotate the key after each block, so that if there happened to be a repeated shellcode block, it wouldn't be repeated in the encoded version. Since this isn't crypto, it's not that critical, but I thought it might add a bit of difficulty to analysis.

Another thing that I wanted to do was create a random key each time the encoder was run and also a random shift value. I also wanted the random 128 bit key to be physically located in the middle of the decoder stub so that it broke up the static decoder stub with a little bit of randomness, so that each static piece was a little shorter.

In order to do all this without going insane cutting and pasting byte strings between different files, I made the encoder not only encode the shellcode, but output the decoder stub as well, so I can just pipe the encoded shellcode into the excecution stub, which I made read the shellcode to execute from STDIN.

I wrote the encoder in Python 3 and I wrote the decoder in assembly, and pasted the bytes the I needed into the Python encoder script.

Both scripts were a bit tricky to implement - particularly using the xmm instructions properly. But all in all, my main issues were lack of familiarity with the necessary commands, both in Python and asm. In the end, I was able to get everything working, and I will demonstrate its functionality after I present the code.

I'll present the Python script first, but I'll omit the objdump output that I include as a comment at the bottom in the code on [github](http://www.github.com/mshaneck/SLAE32), as well as the print statements that I commented out, but left in case someone wants to investigate it further. There are lots of comments in the code to explain what it is doing, but I'll add explanation as needed.

```python
#!/usr/bin/python3

import sys
import random
import struct
import os

# for this function we are operating on 128 bit integers
# We want to shift in multiples of bytes since the xmm instructions
# shift in multiples of bytes, not bits
def rotate128Left(value, bytes):
    mask=0xffffffffffffffffffffffffffffffff
    return (((value << (bytes*8)) & mask) | (value >> (128-(bytes*8))))
```
I wanted to shift a random amount of bytes, but the xmm shift instruction shifts in multiples of bytes, so I was limited by the underlying instructions.

```python
# Shellcode payload to encode
with os.fdopen(sys.stdin.fileno(), 'rb') as shellcode_input:
    mainPayload = shellcode_input.read()

# Get random key
xorKey = random.getrandbits(128)
# We need to shift an odd amount to avoid short cycles
shiftKey = random.randint(1,15)
if shiftKey % 2 == 0:
   shiftKey = shiftKey+1

shiftString = '\\x'+'{:02x}'.format(shiftKey)
remainderString = '\\x' + '{:02x}'.format(16-shiftKey)

xorKeyString = ""
for s in xorKey.to_bytes(16,"little"):
    xorKeyString += "\\x" + '{:02x}'.format(s)
```
I am going to paste these values into the code directly, so I format them so that I can just concatenate them later. I was going to put the shift value right next to the xor key, but the shift instruction for xmm registers takes an immediate value as the amount of bytes to shift, so I have to paste them into the code in the appropriate position, building the instructions on the fly.

```python
# break up input into chunks of 16 bytes
payloadParts = []
while(mainPayload):
    payloadParts.append(xorKey ^ nextPart)
    xorKey = rotate128Left(xorKey, shiftKey)
    mainPayload = mainPayload[16:]
```
This was the main encoding function. I xor the key with the next block, and the rotate the bytes in the key left by whatever amount is needed.
```python

encodedPayload = ""
for p in payloadParts:
    for s in p.to_bytes(16,"little"):
        encodedPayload += "\\x" + '{:02x}'.format(s)

currentKey=""
for s in xorKey.to_bytes(16,"little"):
    currentKey += "\\x" + '{:02x}'.format(s)

```
The following part is the construction of the decoder stub plus the encoded shellcode. The byte codes are from the objdump that comes from the assembly code that will be described next.
```python
#So now we have all the important parts
#So lets construct the entire shellcode, including the decoder and the encoded shellcode
# I wanted to break up the lines so I did it by labeled section...
mainPayload="\\xeb\\x0d"  \
            +"\\x5e\\x31\\xc9\\xf3\\x0f\\x6f\\x0e\\x66\\x0f\\xef\\xdb\\xeb\\x15"\
            +"\\xe8\\xee\\xff\\xff\\xff"\
            +xorKeyString \
            +"\\xeb\\x2f"\
            +"\\x5e\\x89\\xf2"\
            +"\\xf3\\x0f\\x6f\\x06\\x66\\x0f\\xef\\xc1\\xf3\\x0f\\x7f\\x06\\xc4\\xe2\\x79\\x17\\xd8\\x73\\x02\\xff\\xe2"\
            +"\\xf3\\x0f\\x6f\\xd1\\x66\\x0f\\x73\\xf9"\
            + shiftString\
            +"\\x66\\x0f\\x73\\xda"\
            + remainderString\
            +"\\x66\\x0f\\xeb\\xca\\x83\\xc6\\x10\\xeb\\xd4"\
            +"\\xe8\\xcc\\xff\\xff\\xff"\
            +encodedPayload+currentKey

# Would be better to automatically select another key, but I didn't do that.
if "00" in mainPayload:
   print("It contains a null! Try again...")
   exit()

print(mainPayload)

```

That's it for the encoder script. I will show proper usage of it below after we describe the xmm xor decoder.

```nasm
; Title: XMM decoder shellcode
; Filename: xmm_xor_decoder.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
; A more detailed description of this code can be found at
; http://markshaneck.com/SLAE32/slae32-assignment4
;
; Purpose: Decode shellcode that has been encoded through
; an xor with a 128 bit value that gets rotated left by
; a particular amount. This code is not intended to be
; used directly but as a way to create a template for
; the associated python script to autogenerate it, since
; the xor key and the shift amount will be randomized for
; each run

global _start

section .text
_start:
    jmp get_keys

got_keys:
    pop esi            ; esi contains the address of the xor key
    xor ecx,ecx
    movdqu xmm1, [esi] ; put the xor key into xmm1
    pxor xmm3,xmm3     ; put a zero in xmm3 for end point check
    jmp short move_on

; put the data in the middle to break up the signature somewhat, since
; the 128 bit xorkey will be random each time
get_keys:
    call got_keys

    ; the xorkey will be a random value, and will be replaced in the python script
    xorKey: db 0x71,0x6a,0xc9,0xfc,0xfe,0x1a,0xd1,0x09,0xb4,0x9c,0x2b,0x7f,0xce,0x75,0x8f,0xc4

move_on:
    jmp short get_shellcode

got_shellcode:    
    pop esi      ; now the shellcode address is loaded into esi
    mov edx,esi  ; we will update esi, so edx will save the start point

decode_loop:
    movdqu xmm0, [esi]  ; put the first block of encoded shellcode into xmm0

    pxor xmm0,xmm1  ; decode that next block
    movdqu [esi],xmm0

    ; check to see if that value in xmm0 is 0
    ; xmm3 contains all zeros
    ; so we can use vptest and jc
    ; vptest xmm3,xmm0 sets the CF if xmm0 AND NOT xmm3 is all zeros
    ; that is, since xmm3 is zero, not xmm3 is all 1s
    ; so xmm0 and not xmm3 will be all zeros if xmm0 is all zeros
    vptest xmm3,xmm0
    jnc rotate_key
    jmp edx

rotate_key:
    ; before we increment esi and loop, rol the key by shiftvalue bytes
    ; these shift values will be dynamically generated by the encoder script
    ; hard code for now
    movdqu xmm2,xmm1 ; copy so we can rotate the key
    pslldq xmm1, 0x9 ; rotate left by shift key  --> this will be replaced with the random value
    psrldq xmm2, 0x7 ; rotate right by remainder --> this will be replaced with the random value
    por xmm1,xmm2   ; OR together to get rotate left

    ; skip to the next block of encoded shellcode
    add esi, 0x10

    jmp short decode_loop

get_shellcode:
    call got_shellcode
    ; The following shellcode will be dynamically replaced in the python script
    shellcode: db 0x40,0xa3,0x3e,0x1d,0xcf,0xc1,0x61,0x0d,0x07,0x9d,0xc0,0x74,0x97,0xc7,0x82,0x09,0x89,0x04,0x9d,0x1a,0xa4,0x03,0xf5,0x67,0x34,0x8e,0x95,0x36,0xb4,0x9b,0x76,0xbd,0xe0,0xe4,0x06,0x05,0xbb,0x90,0x9a,0x3b,0xdb,0x09,0xb4,0x9c,0x2b,0x7f,0xce,0x75,0x1a,0xd1,0x09,0xb4,0x9c,0x2b,0x7f,0xce,0x75,0x8f,0xc4,0x71,0x6a,0xc9,0xfc,0xfe
```
And that's it. It took a surprisingly long time to implement given how relatively simple it is. However, I was quite happy with the end result. Now, I'll show how it works with a few different shellcodes, include the execve stack method that the assignment asks for. However, due to the way it is setup, it is easy to put any shellcode in it.

First, let's try the standard Hello World. The assembly is the same as in the class, so I won't go over it again. But as you can see in the image, I compile the helloworld.nasm file to get its shellcode, pipe that into the encoder, and pipe the result of that into the shellcode stub, which just reads from stdin and executes. You can also see from the image that it adds about 113 bytes to the original shellcode.

{% include image name="hello_world.png" width="100%" %}

Next up is the execve stack shellcode. This also was covered in the videos, so I'll not describe it either. I did however run into a very strange problem. If anyone has any insight on this, please drop me a note on [Keybase chat](https://keybase.io/shaneck) (unless I get comments working on these posts first). I could not get the code to execute properly when reading the shellcode from stdin. I had to use the technique of declaring a global unsigned char array and pasting the shellcode into there. It seemed from my debugging that the shell was indeed executing but then crashing once it was run. I could not figure out what was different between the two methods of execution. I verified that the code was being read in correctly and did not have any errors in memory. But still, it would not execute.

However, it worked fine when put in the global variable, as seen in the shellcode.c in my github repo for this assignment.

{% include image name="execve-encoded.png" width="100%" %}

The encoded code also worked for my bind and reverse TCP shells from previous assignments.

{% include image name="shell-bind-part1.png" width="100%" %}

{% include image name="shell-bind-part2.png" width="100%" %}

I really enjoyed working on this encoder and I think I got a lot out of the process.
