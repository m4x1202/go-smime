# S/MIME

This is a partial implementation of S/MIME 4.0 in golang.

It consists of the following packages

- asn1<sup>[1]</sup> - ASN.1 marshalling and unmarshalling [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/asn1?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/asn1)
- b64 - Pretty base64 encoding for S/MIME (basically just the PEM body) [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/b64?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/b64)
- cms(cms/protocol)<sup>[2]</sup> - Cryptographic Message Syntax [rfc5652](https://tools.ietf.org/html/rfc5652)[![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/cms?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/cms) [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/cms/protocol?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/cms/protocol)
- mime - Parsing for mime/multipart messages needed for S/MIME [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/mime?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/mime)
- oid<sup>[3]</sup> - ASN.1 object identifiers and related crypto [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/oid?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/oid)
- openssl - Shelled-out openssl for testing [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/openssl?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/openssl)
- pki<sup>[4]</sup> - Creates x.509 pki for testing [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/pki?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/pki)
- smime Secure/Multipurpose Internet Mail Extensions (S/MIME) Version 4.0 [rfc5751-bis-12](https://tools.ietf.org/html/draft-ietf-lamps-rfc5751-bis-12) [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/smime?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/smime)
- timestamp<sup>[5]</sup> - Time-Stamp Protocol (TSP) [rfc3161](https://tools.ietf.org/html/rfc3161) [![GoDoc](https://godoc.org/github.com/m4x1202/go-smime/timestamp?status.svg)](https://godoc.org/github.com/m4x1202/go-smime/timestamp)

It supports enveloped data with AES in CBC mode. Decryption also works with (3)DES.  Authenticated-Enveloped-Data Content Type is also supported with AES-GCM and ChaCha20-Poly1305. Also RSAES-OAEP and RSASSA-PSS is supported.

This is covered in
- Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type [rfc5083](https://tools.ietf.org/html/rfc5083)
- Using ChaCha20-Poly1305 Authenticated Encryption in the Cryptographic Message Syntax (CMS) [rfc8103](https://tools.ietf.org/html/rfc8103)
- Using AES-CCM and AES-GCM Authenticated Encryption in the Cryptographic Message Syntax (CMS) [rfc5084](https://tools.ietf.org/html/rfc5084)
- Use of the RSASSA-PSS Signature Algorithm in Cryptographic Message Syntax (CMS) [rfc4056](https://tools.ietf.org/html/rfc4056)
- Use of the RSAES-OAEP Key Transport Algorithm in the Cryptographic Message Syntax (CMS) [rfc3560](https://tools.ietf.org/html/rfc3560)

## Examples

### Encryption and decryption
```go
import "github.com/m4x1202/go-smime/smime"

// Alice
mail := "From: Alice\nTo: Bob\n\nHello World!"
SMIME, _ := smime.New()
ciphertext, _ := SMIME.Encrypt([]byte(mail), []*x509.Certificate{Bobcert})
// Bob
BobkeyPair, _ := tls.LoadX509KeyPair("BobCert", "BobKey")
SMIME, _ := smime.New(BobkeyPair)
plaintext, _ := SMIME.Decrypt(ciphertext)
```

### Signing and verfication
```go
import "github.com/m4x1202/go-smime/smime"

// Alice
AlicekeyPair, _ := tls.LoadX509KeyPair("AliceCert", "AliceKey")
mail := "From: Alice\nTo: Bob\n\nHello World!"
SMIME, _ := smime.New(AlicekeyPair)
signedMsg, _ := SMIME.Sign([]byte(mail), []*x509.Certificate{Bobcert})
// Bob
SMIME, _ := smime.New()
plaintext, _ := SMIME.Verify(signedMsg)
```

## Todo

- Testing


[1]: https://golang.org/pkg/encoding/asn1/
[2]: https://github.com/mastahyeti/cms
[3]: https://github.com/mastahyeti/cms
[4]: https://github.com/mastahyeti/fakeca
[5]: https://github.com/mastahyeti/cms
