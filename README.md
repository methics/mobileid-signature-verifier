# mobileid-signature-verifier
A sample implementation how to verify a CMS/PKCS7 signature, i.e. from a Swisscom Mobile ID signature response.
For simplicity, only basic validation is done. You may use the code as a basis to further improve the signature validation.

More GitHub samples on Mobile ID can be found at https://github.com/SCS-CBU-CED-IAM
Futher information about the Swisscom Mobile ID Service can be found at http://swisscom.com/mid, i.e. you should read the Mobile ID Client Reference Guide.

##### TrustStore

The Trust Anchor used by the verifier sample is based on the Swisscom Root CA 2 certificate. The TrustStore in the subfolder `jks` contains the root certificate plus intermediate CA certificates.
The TrustStore is protected with the password **secret** and contains the following public certificates (from swissdigicert.ch):

```
Alias name: swisscom root ca 2
Owner: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Issuer: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Certificate fingerprints (MD5): 5B:04:69:EC:A5:83:94:63:18:A7:86:D0:E4:F2:6E:19
```
```
Alias name: swisscom_rubin_ca_2
Owner: CN=Swisscom Rubin CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Issuer: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Serial number: 59cee707d35b3a863395b29b8e7fd290
Certificate fingerprints (MD5): 32:8F:87:8F:17:5B:46:C7:84:A0:47:3E:13:2E:02:1A
```
```
Alias name: swisscom_rubin_ca_3
Owner: C=ch, O=Swisscom, OU=Digital Certificate Services, CN=Swisscom Rubin CA 3
Issuer: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Certificate fingerprints (MD5): CD:8E:50:05:01:38:63:D5:88:04:C7:FD:E4:3F:B7:F5
```

##### Usage

Refer to the simplified examples used in the main method of the class `ch.swisscom.mid.verifier.MobileIdCmsVerifier`.
The verifier sample main method will ouput the following details:

* Print Issuer/SubjectDN/SerialNumber of all x509 certificates that can be found
* Print x509 certificate details (i.e. SerialNumber, SubjectDN, Issuer, Validity Date)
* Print the user's unique Mobile ID SerialNumber
* Print the Signed Data, which should be equal to the origin DTBS Message
* Print result of the signature verification on the SignerInformation object
* Print result of the certificate path validation against trust anchor (truststore) incl. an OCSP check

###### Code snippet from the main method example
```java
// Print Issuer/SubjectDN/SerialNumber of all x509 certificates that can be found in the CMSSignedData
verifier.printAllX509Certificates();

// Print Signer's X509 Certificate Details
System.out.println("X509 SignerCert SerialNumber: " + verifier.getX509SerialNumber());
System.out.println("X509 SignerCert Issuer: " + verifier.getX509IssuerDN());
System.out.println("X509 SignerCert Subject DN: " + verifier.getX509SubjectDN());
System.out.println("X509 SignerCert Validity Not Before: " + verifier.getX509NotBefore());
System.out.println("X509 SignerCert Validity Not After: " + verifier.getX509NotAfter());

System.out.println("User's unique Mobile ID SerialNumber: " + verifier.getMIDSerialNumber());
			
// Print signed content (should be equal to the DTBS Message of the Signature Request)
System.out.println("Signed Data: " + verifier.getSignedData());

// Verify the signature on the SignerInformation object
System.out.println("Signature Valid: " + verifier.isVerified());
			
// Validate certificate path against trust anchor incl. OCSP revocation check
System.out.println("X509 SignerCert Valid (Path+OCSP): " + verifier.isCertValid(keyStore));
```

###### Example Usage
```
$ javac -d ./class -cp ".:./lib/*" ./src/ch/swisscom/mid/verifier/*.java

$ jar cfe ./jar/midverifier-v1.3.jar ch.swisscom.mid.verifier.MobileIdCmsVerifier -C ./class .

$ java -cp ".:./lib/*:./jar/*" ch.swisscom.mid.verifier.MobileIdCmsVerifier
Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier [OPTIONS]

Options:
  -cms=VALUE        - Base 64 encoded CMS/PKCS7 signature string
  -jks=VALUE        - optional path to truststore file (default is 'jks/truststore.jks')
  -jkspwd=VALUE     - optional truststore password (default is 'secret')

Example:
  java ch.swisscom.mid.verifier.MobileIdCmsVerifier -cms=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
```

##### Example Output

```
X509 Certificate #1
X509 Issuer: CN=Swisscom Rubin CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 Subject DN: C=CH, CN=MIDCHE5HR8NAWUB3:PN, SERIALNUMBER=MIDCHE5HR8NAWUB3
X509 SerialNumber: 181047290566811336462171535902987480739
SignerCert: Yes

X509 SignerCert SerialNumber: 181047290566811336462171535902987480739
X509 SignerCert Issuer: CN=Swisscom Rubin CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 SignerCert Subject DN: C=CH, CN=MIDCHE5HR8NAWUB3:PN, SERIALNUMBER=MIDCHE5HR8NAWUB3
X509 SignerCert Validity Not Before: Wed Dec 24 10:29:59 CET 2014
X509 SignerCert Validity Not After: Sun Dec 24 10:29:59 CET 2017
User's unique Mobile ID SerialNumber: MIDCHE5HR8NAWUB3
Signed Data: Test: Sign this Text? (ptp2cn)
Signature Valid: true
X509 SignerCert Valid (Path+OCSP): true
```
