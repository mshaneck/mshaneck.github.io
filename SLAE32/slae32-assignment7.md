---
layout: page
title: SLAE32 Assignment 7
---

<div class="well" markdown="1">
<h2>SLAE32 Assignment 7: Custom Crypter</h2>

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1009

The challenge for this assignment is to create a custom crypter. You are allowed to use any programming language and any encryption scheme.

I took a look at some of the other Assignment 7s out there, since they are required to be public for the exam. Most solutions used symmetric block ciphers, and so I wanted to be different, so I decided to use a stream cipher. I also wanted to implement the code instead of use a library. I have done enough crypto programming that it seemed that it wouldn't be much fun to just use an existing implementation to encrypt and decrypt. I also wanted to get the most out of this experience in terms of learning assembly code, so I opted to implement the encrypter in Python and the decrypter in assembly and attach the decryption shellcode to the encrypted shellcode, so it could decrypt itself. That is another reason why I had to implement the decryption myself - it was too specific of a use case to be able to use existing code.

Disclaimer: I implemented the encryption code myself, which means that you should never take this code and use it in anything remotely close to something even resembling a production environment. This was for my own education. Feel free to play with the code, but if you want real code to use, just use the libraries. Of course, if you are using it to encrypt shellcode, the lack of rigorous cryptographic security proofs is probably not all that big of a deal.

Also note that the key will be included in the decryption shellcode. You could change that to read the key in from a file that was planted through some other means or by constructing the key some other way to slow down or possibly thwart analysis. Since this code includes it in the decryption stub, it may possibly delay analysis, but it will definitely not prevent it...

So the stream cipher that I chose was Salsa20. It seemed like a fairly simple algorithm, and since I was going to implement it in assembly, I wanted to use a simple algorithm.  I used the main author's (Daniel Bernstein) [implementation](https://cr.yp.to/snuffle.html) as reference, and for the Python version, simply ported his C code into Python, then adapted it to my particular use case.

For the assembly version, I took the Python version and reimplemented each function in assembly. It was definitely the hardest and most intricate assembly that I have written for this certification, and therefore it was the right choice to implement Salsa20 in assembly. It took a while to get it functioning properly. I also gave up pretty early trying to keep out nulls, so to use this in a string based exploit, you would want to reencode it with the xor encoder from A4 or something similar.

In any case, here is the Python code that both encrypts the original shellcode and then outputs the decyption stub along with the encrypted shellcode, ready for independent execution.







<h2>Bonus Learning Experience</h2>

Fun story. I got the code working to decrypt the shellcode finally. Took a very long time, but it was working.
However, I was storing the length of the message just in front of the encrypted shellcode itself in a byte. When it was all working, it occurred to me that one byte was not sufficient to store the length of the shellcode, as that allows a maximum of 256 bytes. 2 bytes would be better as that would allow for 64k. So I changed it from db 0x65 to db 0x65,0x0. It then stopped working correctly. It would decrypt the first five or so bytes and the rest was gibberish.

This turned out to be a very hard bug for me to figure out. Everything seemed to be fine, it just wasn't decrypting. I was checking the round key before and after each round and it matched up exactly with what the python code was printing. I finally dug into where it xor'd all the bytes together and examined the ciphertext and the key. It was then that I finally realized that the ciphertext had the first few bytes correct, and then it started over. That is, about 6 bytes in, it repeated the ciphertext from the beginning. I checked it out in objdump and sure enough, it was repeated. But it was not that way in the source asm file. The only thing I could figure was that the byte 0x65 was a full instruction, so it was happy with that. However 0x65,0x00 was not a full instruction, so it repeated bytes over in order to complete instructions.

Does anyone know why it does that? Is there anyway to turn it off? I realize that what we are doing here is an obscure use and not really the supported way that it is supposed to work. You really aren't supposed to store data in and among instructions in the text section. In fact, the regular executable doesn't even run, since we are editing (or attempting to write to) data in the .text section. I suppose it is an unsupported way of coding in assembly and thus is has unpredictable behavior. If anyone has any insight, please let me know and I will post an update.

My solution to this problem was to hardcode the length, as I am dynamically generating the code anyway, so I can just paste it in. Also, I didn't realize that this was going on, but I had noticed some symptoms of this issue with the other code, as I had to put nops after the data, as I had noticed that it was jumping into garbage instructions in and around the data. By adding nops, even if the offsets were wrong by a few bytes, it would jump into the nop sled instead of the data. Kind of a hackish way of dealing with it, but hey, that seems appropriate for shellcode, right?



</div>
