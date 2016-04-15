# Generate SSL certificates with ease

## Generating ROOT CA certificate

```c#
private static X509Certificate GenerateCaCertificate() {
    var cert = new X509Certificate {
        Tbs = {
            SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
            Validity = new X509Validity {
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(5)
            },
            Subject = new X509Name {
                CommonName = "Sergey CA",
                Organization = "My Ca"
            }
        }
    }
    .GenerateRsaKey()
    .GenerateSerialNumber()
    .SetIssuerSelf()
    .SetBasicConstraint(new BasicConstraintData {
        Authority = true,
        PathLengthConstraint = 3
    })
    .SignSelf();

    return cert;
}
```

## Generating end certificate signed with CA certificate

```c#
private static X509Certificate GenerateEndCertificate(X509Certificate ca) {
    var cert = new X509Certificate {
        Tbs = {
            SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
            Validity = new X509Validity {
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(5)
            },
            Subject = new X509Name {
                CommonName = "test.vcap.me",
                Organization = "Home"
            }
        }
    }
    .SetIssuer(ca)
    .GenerateRsaKey()
    .GenerateSerialNumber()
    .AddSubjectAltNames("test2.vcap.me")
    .SignWith(ca);

    return cert;
}
```

## Generating self-signed certificate

```c#
private static X509Certificate GenerateSelfSignedCertificate(X509Certificate ca) {
    var cert = new X509Certificate {
        Tbs = {
            SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
            Validity = new X509Validity {
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(5)
            },
            Subject = new X509Name {
                CommonName = "test.vcap.me",
                Organization = "Home"
            }
        }
    }
    .SetIssuer(ca)
    .GenerateRsaKey()
    .GenerateSerialNumber()
    .AddSubjectAltNames("test2.vcap.me")
    .SignSelf(ca);

    return cert;
}
```

## Export certificate
 
 ```c#   
    new X509Certificate {
        Tbs = {
            SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
            Validity = new X509Validity {
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(5)
            },
            Subject = new X509Name {
                CommonName = "test.vcap.me",
                Organization = "Home"
            }
        }
    }
    .SetIssuer(ca)
    .GenerateRsaKey()
    .GenerateSerialNumber()
    .SignSelf()
    .Export(filePath, true);
```
