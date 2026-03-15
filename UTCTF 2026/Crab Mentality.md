# UTCTF Web Writeup — Crab Mentality

**Challenge:** Crab Mentality  
**Category:** Web  
**URL:** http://challenge.utctf.live:5888  
**Event:** UTCTF  
**Author:** Elie / Razboy20  
![](images/Screenshot%202026-03-14%20032501.png)
---

The challenge pretends to be a global queue / patience challenge, but the real vulnerability is an **arbitrary file read via path traversal** in:


/getFlag?f=


Using `../` allows reading files outside the web directory.  
We read a backup file:


/getFlag?f=../main.py.bak


The backup server code contains the flag (lightly obfuscated).

**Flag**


utflag{y0u_e1th3r_w@1t_yr_turn_0r_cut_1n_l1ne}


---

## 1. Recon — Understanding the page

Opening the challenge shows a **Flag Dispenser UI** with rules saying:

- You must wait 5 minutes
- If another team requests during your window, your turn is canceled
- Everyone keeps canceling each other

This suggests the challenge is about **patience / queue logic**, but this is actually misdirection.

![Flag Dispenser UI](IMAGE_URL_HERE)

---

## 2. Client-side analysis

Viewing page source shows the front-end makes requests to:


/getFlag?f=flag.txt
/status


JavaScript flow:


GET /getFlag?f=flag.txt

-> JSON if waiting
-> plain text if success

while waiting:
GET /status every 5s


This reveals something suspicious:


f=flag.txt


The server is reading a file path provided by the client.

![Source Code](IMAGE_URL_HERE)

---

## 3. Testing for path traversal

Try changing the filename:


/getFlag?f=../index.html


Result: works

Try deeper:


/getFlag?f=../../../../etc/passwd


Result: blocked (403)

So the server allows **one-level traversal**, meaning files next to the web root may be readable.

This suggests:

- insecure path join
- weak validation
- possible backup file exposure

![Traversal Test](IMAGE_URL_HERE)

---

## 4. Finding the backup hint

Looking at the HTML comments reveals a hint about backups / rollback.

Example comment:


rollback old style of site + server code from backup files


So we try:


/getFlag?f=../main.py.bak


Success — returns Python source code.

![Backup File](IMAGE_URL_HERE)

---

## 5. Reading main.py.bak

The file contains obfuscated flag data.

```python
import base64

_d = [
    0x75, 0x74, 0x66, 0x6c, 0x61, 0x67, 0x7b, 0x79,
    0x30, 0x75, 0x5f, 0x65, 0x31, 0x74, 0x68, 0x33,
    0x72, 0x5f, 0x77, 0x40, 0x31, 0x74, 0x5f, 0x79,
    0x72, 0x5f, 0x74, 0x75, 0x72, 0x6e, 0x5f, 0x30,
    0x72, 0x5f, 0x63, 0x75, 0x74, 0x5f, 0x31, 0x6e,
    0x5f, 0x6c, 0x31, 0x6e, 0x65, 0x7d
]

_k = base64.b64decode("U2VjcmV0S2V5MTIz").decode()

_x = bytes([
    c ^ ord(_k[i % len(_k)])
    for i, c in enumerate(_d)
]).hex()

if __name__ == "__main__":
    raw = bytes(
        int(_x[i:i+2], 16) ^ ord(_k[i // 2 % len(_k)])
        for i in range(0, len(_x), 2)
    )
    print(raw.decode())

```

The script uses:

XOR

base64 key

hex conversion

So easiest solution:

python3 main.py.bak
6. Flag recovery

Running the script prints:


Final Flag
utflag{y0u_e1th3r_w@1t_yr_turn_0r_cut_1n_l1ne}
