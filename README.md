# URL Sign
With URL signing you can validate a REST operation without using additional
authentication means. Here's an example:

Let's assume that A wants to execute the REST operation ```x``` on the service
C.  B acts as an authentication gateway for the service C.


```
        +-------+      auth + x      +-------+               +-------+
        |       |------------------->|       |               |       |
        |   A   |                    |   B   |               |   C   |
        |       |<-------------------|       |               |       |
        +---+---+     y = signed(x)  +-------+               +-------+
            |                                                    ^
            |                                                    |
            |                        y                           |
            +----------------------------------------------------+
```

If the client A can successfully authenticate with B, then B generates a signed
version ```y``` of the operation ```x```. At this point, without the need of
additional authentication, C can verify the validity of the operation simply by
checking the signature attached to ```y``` and execute the operation for A.

This simple URL signing mechanism is based on asymmetric RSA keys. B signs the
URL with its private key and the signature can be verified by C by using B's
public key.

The only currently supported format for RSA keypairs is  PEM
[SSLeay](http://en.wikipedia.org/wiki/SSLeay) which is the default format used
by ```ssh-keygen```.

## Usage

### Sign an URL

Assume you want to sign ```https://www.mendix.com/``` with your private key, then this:

```java
String privateKeyFileName = "id_rsa";
URLSigner urlSigner = new URLSigner(new File(privateKeyFileName));
URI signedUri = urlSigner.sign(new URI("https://www.mendix.com"), 10);
```
will generate the following signed URI:
```
https://www.mendix.com/?expire=20150611150101&signature=<base64 encoded signature>
```

### Verify a signed URL

Given a signed URL, its validity can be verified using the public key with:
```java
String publicKeyFileName = "id_rsa.pub";
URLVerifier urlVerifier = new URLVerifier(new File(publicKeyFileName));
boolean valid = urlVerifier.verify(signedUri);
```
If the signature is valid and the expire date is not passed then ```valid``` will be ```true```.

## Testing
Some basic tests are provided:

```
mvn test
```

## Work in progress

This library is a work in progress, therefore it will probably change soon.

There still a lot that can be done:

- Implement proper error handling.
- Improve abstractions to support more signing algorithms.
- Improve support for keypair formats.
