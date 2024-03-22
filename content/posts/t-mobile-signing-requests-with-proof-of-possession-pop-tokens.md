+++
title = 'T-Mobile: Signing Requests With Proof of Possession (PoP) Tokens'
date = 2024-03-22T14:11:45-04:00
draft = false
+++
## Introduction

In a typical authenticated API, leaked credentials allow an attacker to make API requests as the associated user for as long as the credentials are valid. With many REST APIs, these credentials come in the form of a bearer token, typically using JSON Web Tokens (JWTs).

The OAuth 2.0 bearer token specification, as defined in RFC6750, allows any party in possession of a bearer token to get access to the associated resources without demonstrating possession of a cryptographic key. Given the risk of exposure of these tokens, some organizations require additional security measures, such as request signing with a known keypair.

T-Mobile uses a method called proof of possession (PoP) which provides a mechanism to bind key material to OAuth tokens. The client can use a keypair to add a signature to the outgoing HTTP requests to the resource server. The resource server in turn can validate the signature and ensure that the key material provided by the sender is the same entity that requested the token in the first place (as opposed to someone who stole the token in transit or at rest). Further, each request is signed with its own PoP token, minimizing the risk of leaked access tokens being used across endpoints.

## PoP Token Structure

The structure of the PoP token used by T-Mobile is:

```
Header: {alg, type}
Body: {
    iat: <epoch time>
    exp: <epoch time + 2 minutes>
    ehts: <authorization; content_type; uri; http-method; body> => All request headers, URI, HTTP method and body fields used to create hash
    edts: <Base64UrlSafeEncoding[SHA256(all ehts claim values as a concatenated string)]>
    jti: <unique identifier>
    v: "1"
}
Signature: <digitalSignature>
```

This token is then passed to T-Mobile API endpoints via the `X-Authentication` header, along with the access token in the `Authorization` header.

This is an example PoP token:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MTExMTkwNTEsImV4cCI6MTcxMTExOTE3MSwiZWh0cyI6IkNvbnRlbnQtVHlwZTt1cmk7aHR0cC1tZXRob2QiLCJlZHRzIjoidHBBZG1QTWwyUV8yZlJVUjRPRWZsa25aUXR5VFloX3JLcVYzeXFiRFpBMCIsImp0aSI6ImZiMjc3ZGVmLTFkMDEtNDdiMy1hM2Q4LTk1NGJmY2MxNGY1OSIsInYiOjF9.HNfcPqaKufuj64eKDVgx-TahcM15PoCBJIE9RDJVirUMb4xOE0GhfxcXTmDyRVry-mlWp2czhS_cHQawXwvzdJ3SaJBQngWdQR8sApnaWcZcpjCjvysy5jxHEo3CSdKJdUNjA5Rzd7AboQaYpVvidwRUvhFdoUsOoXC3qVWiL1krqlwzHe-dvdKyRzdOSjmwuTHEGXmUS0WTm73449yzFoajgUJi4fh_Yi7Oz0Ac8o1jMh63GmtObA-D0uzQDMi-VVbrCsVhxDORL82xmuOoI1HyQZtZkjl69u1Ykgi-q5HjFNqm3YJC70QMfxcXNm9GFiC7X8X3T4tLr981_pDl5Q
```

When decoded, it contains the following data:

```
{
    "alg": "RS256",
    "typ": "JWT"
}
{
    "iat": 1711119051,
    "exp": 1711119171,
    "ehts": "Content-Type;uri;http-method",
    "edts": "tpAdmPMl2Q_2fRUR4OEflknZQtyTYh_rKqV3yqbDZA0",
    "jti": "fb277def-1d01-47b3-a3d8-954bfcc14f59",
    "v": 1
}
<signature>
```

## Generating a PoP Token

The `edts` hash can be generated with the following data:

```
POST /oauth2/v2/tokens
Host core.saas.api.t-mobile.com
Content-Type: application/json
{"cnf":"-----BEGIN PUBLIC KEY-----...","client_id":"SIDWeb"}
```

Resulting in the following payload:

```
edtsString = "application/json/oauth2/v2/tokensPOST"
edts = base64.b64encode(SHA256.new(bytes(edtsString, "utf-8")).digest()).decode('utf-8').replace("=", "").replace("+", "-").replace("/", "_")
# tpAdmPMl2Q_2fRUR4OEflknZQtyTYh_rKqV3yqbDZA0
```

The backend API server can then take the public key provided in the POST body and validate the headers specified in the `ehts` claim.

Here is some sample Python code to generate the PoP token for a given request:

```
import base64
from datetime import datetime, timedelta, timezone
import uuid
from Crypto.Hash import SHA256
import jwt


def get_pop_token(priv_key, method, uri, headers=None, body=None):
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=120)).timestamp()),
    }

    data = {
        **headers,
        "uri": uri,
        "http-method": method
    }
    if body:
        data['body'] = body

    # Creating ehts string...
    ehts = []
    edtsString = ""
    for k, v in data.items():
        ehts.append(k)
        edtsString += str(v)
    payload['ehts'] = ';'.join(ehts)

    # Creating edts hash...
    hash = SHA256.new(bytes(edtsString, "utf-8"))
    edts = base64.b64encode(hash.digest()).decode('utf-8').replace("=", "").replace("+", "-").replace("/", "_")
    payload['edts'] = edts

    payload.update({
        "jti": str(uuid.uuid4()),
        "v": 1
    })

    return jwt.encode(payload, priv_key, algorithm="RS256")
```

## Using PoP tokens

Once you have the ability to generate PoP tokens, you can request an access token:

```
def _access_token(self) -> str:
    endpoint = "/oauth2/v2/tokens"
    # These are the credentials associated with your T-Mobile app or user
    auth = HTTPBasicAuth(self.client_id, self.client_secret)
    headers = {"Content-Type": "application/json"}
    headers['X-Authorization'] = get_pop_token(self.priv_key, "POST", endpoint, headers=headers)
    r = requests.post(f"{self.base_url}{endpoint}", auth=auth, headers=headers)
    return r.json()['access_token']
```

And then finally you can put it all together to make an authenticated request to an API like this one for DevEdge:

```
def devices(self, iccid: str) -> Dict[Any, Any]:
    endpoint = f"/iot-connectivity/v1/devices/{iccid}"
    headers = {"Content-Type": "application/json"}
    headers['X-Authorization'] = get_pop_token(self.base.priv_key, "GET", endpoint, headers=headers)
    headers['Authorization'] = f'Bearer {self.base._access_token()}'
    r = requests.get(f"{self.base.base_url}{endpoint}", headers=headers)
    return r.json()
```
