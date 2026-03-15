# **UTCTF Web — Time to Pretend**

**Category:** Web  
**Challenge Name:** Time to Pretend  
**Target URL:** [http://challenge.utctf.live:9382/](http://challenge.utctf.live:9382/)

![](images/Screenshot%202026-03-13%20231711.png)

---

## **1\. Challenge Information**

We are given a web challenge that contains a login portal.  
Additionally, a leaked PCAP file named:

``` aftechLEAK.pcap ```

is provided, which contains internal AffiniTECH traffic.  
The challenge description suggests that the PCAP contains enough information to reproduce the exploit.

---

## **2\. Initial Recon**

Opening the main page:

[http://challenge.utctf.live:9382/](http://challenge.utctf.live:9382/)

![](images/Screenshot%202026-03-14%20030318.png)

We see a terminal-style login interface.

Inspecting the JavaScript shows that:

* Login request → POST /auth  
* After login → redirect to /portal

This confirms the authentication flow.

---

## **3\. Important Hint — urgent.txt**

There is an exposed internal file:

[http://challenge.utctf.live:9382/urgent.txt](http://challenge.utctf.live:9382/urgent.txt)

![](images/Screenshot%202026-03-14%20030343.png)

The memo states that:

* All accounts were locked  
* Only account still active: ``` timothy ```

This means we must log in as:

*timothy*

Brute forcing random usernames will not work.

---

## **4\. PCAP Analysis**

Opening the PCAP in Wireshark and filtering HTTP traffic shows repeated requests to:

POST /debug/getOTP

![](images/Screenshot%202026-03-14%20030507.png)

Example request:

```
{  
"username": "carrasco",  
"epoch": 1773290571  
}
```
Example response:
```
{  
"add": 13,  
"mult": 7,  
"otp": "bnccnjbh"  
}
```

![](images/Screenshot%202026-03-14%20030549.png)

Observation:

The OTP is not random.  
If we reverse the transformation using add and mult, the result becomes the original username.

This means the OTP is just an encoded username.

---

## **5\. Reverse Engineering the OTP**

The pattern matches an affine cipher.

Alphabet mapping:

a \= 0  
b \= 1  
c \= 2  
...  
z \= 25

Formula:

c \= (mult × p \+ add) mod 26

Where

p \= plaintext letter index  
c \= ciphertext letter index

From PCAP samples:

add \= epoch % 26

mult depends on epoch % 12

Lookup table:

epoch % 12 → mult

0 → 1  
1 → 3  
2 → 5  
3 → 7  
4 → 9  
5 → 11  
6 → 15  
7 → 17  
8 → 19  
9 → 21  
10 → 23  
11 → 25

All values are coprime with 26, so the cipher is reversible.

---

## **6\. The Trick — "Time to Pretend"**

Using real epoch time does NOT work.

The service pretends to use epoch time,  
but actually uses a time step counter.

Real formula:

t \= floor(unix\_time / 15\)

Then

add \= t % 26  
mult \= table\[t % 12\]

This means the OTP changes every 15 seconds.

Because of drift, we must try a small window around current time.

---

## **7\. Exploit Script**

Python solve script:

```
import time
import string
import requests
ALPHA = string.ascii_lowercase
MULT_TABLE = [1,3,5,7,9,11,15,17,19,21,23,25]
def otp_for(username, counter):
add = counter % 26
mult = MULT_TABLE[counter % 12]
out = [] 

for ch in username: 
   if ch in ALPHA: 
       out.append(ALPHA[(mult * ALPHA.index(ch) + add) % 26]) 
   else: 
       out.append(ch) 

return "".join(out) 
BASE = "http://challenge.utctf.live:9382"
USER = "timothy"
sess = requests.Session()
period = 15
ctr0 = int(time.time()) // period
for dc in range(-30, 31):
ctr = ctr0 + dc
otp = otp_for(USER, ctr) 

r = sess.post(
   f"{BASE}/auth",
   json={"username": USER, "otp": otp}
)

if r.status_code == 200:
   print("Auth success")

   portal = sess.get(f"{BASE}/portal")
   print(portal.text)


 ```  
---

## **8\. Flag**

![](images/Screenshot%202026-03-14%20030707.png)
![](images/Screenshot%202026-03-14%20030746.png)

utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}

---

## **9\. Lessons Learned**

* OTP must never be reversible  
* Time-based auth should use secure TOTP, not custom math  
* Debug endpoints must never be exposed  
* PCAP leaks can reveal full authentication logic

