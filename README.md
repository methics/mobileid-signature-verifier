# mobileid-signature-verifier
A sample implementation how to verify a CMS/PKCS7 signature, i.e. from a Swisscom Mobile ID signature response.
For simplicity, only basic validation is done. You may use the code as a basis to further improve the signature validation.

More GitHub samples on Mobile ID can be found at https://github.com/SCS-CBU-CED-IAM
Futher information about the Swisscom Mobile ID Service can be found at http://swisscom.com/mid, i.e. you should read the Mobile ID Client Reference Guide.

##### Usage

Refer to the simplified examples used in the main method of the class `ch.swisscom.mid.verifier.MobileIdCmsVerifier`.

###### Code snippet from the main method example
```java
MobileIdCmsVerifier verifier = new MobileIdCmsVerifier(args[0]);

KeyStore keyStore = KeyStore.getInstance("JKS");
keyStore.load(new FileInputStream("jks/truststore.jks"), "secret".toCharArray());
			
// Validate certificate path against trust anchor
System.out.println("X509 Path Validated: " + verifier.isCertPathValid(keyStore));
			
// TODO: OCSP or CRL revocation check
System.out.println("X509 Revoked: " + verifier.isRevoked(
		(X509Certificate) keyStore.getCertificate("swisscom root ca 2"),
		(X509Certificate) keyStore.getCertificate("Swisscom_Rubin_CA_2"),
		(X509Certificate) keyStore.getCertificate("Swisscom_OCSP_Signer_Rubin_CA_2"),
		"http://ocsp.swissdigicert.ch/sdcs-rubin2")
		);

// Output X509 Certificate Details
System.out.println("X509 SerialNumber: " + verifier.getX509SerialNumber());
System.out.println("X509 Subject DN: " + verifier.getX509SubjectDN());
System.out.println("X509 Issuer: " + verifier.getX509IssuerDN());
System.out.println("X509 Validity Not Before: " + verifier.getX509NotBefore());
System.out.println("X509 Validity Not After: " + verifier.getX509NotAfter());

System.out.println("User's unqiue Mobile ID SerialNumber: " + verifier.getMIDSerialNumber());

// Get signed content (should be equal to the DTBS Message of the Signature Request)
System.out.println("Signed Data: " + verifier.getSignedData());

// Verify the signature on the SignerInformation object
System.out.println("Signature Verified: " + verifier.isVerified());
```

###### Example Usage
```
$ javac -d ./class -cp ".:./lib/*" ./src/ch/swisscom/mid/verifier/*.java

$ jar cfe ./jar/midverifier-v1.1.jar ch.swisscom.mid.verifier.MobileIdCmsVerifier -C ./class .

$ java -cp ".:./lib/*:./jar/*" ch.swisscom.mid.verifier.MobileIdCmsVerifier
  Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier <Base64Signature>
  
  Options:
    <Base64Signature> - Base 64 encoded CMS/PKCS7 signature string
  
  Example:
    java ch.swisscom.mid.verifier.MobileIdCmsVerifier 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
```

##### Example Output

```
X509 Path Validated: true
X509 Revoked: false
X509 SerialNumber: 181047290566811336462171535902987480739
X509 Subject DN: C=CH, CN=MIDCHE5HR8NAWUB3:PN, SERIALNUMBER=MIDCHE5HR8NAWUB3
X509 Issuer: CN=Swisscom Rubin CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 Validity Not Before: Wed Dec 24 10:29:59 CET 2014
X509 Validity Not After: Sun Dec 24 10:29:59 CET 2017
User's unqiue Mobile ID SerialNumber: MIDCHE5HR8NAWUB3
Signed Data: Test: Sign this Text? (ptp2cn)
Signature Verified: true
```
