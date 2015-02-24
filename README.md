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
System.out.println("X509 SignerCert Validity currently valid: " + verifier.isCertCurrentlyValid());

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
  -cms=VALUE or -stdin   - base64 encoded CMS/PKCS7 signature string, either as VALUE or via standard input
  -jks=VALUE             - optional path to truststore file (default is 'jks/truststore.jks')
  -jkspwd=VALUE          - optional truststore password (default is 'secret')

Example:
  java ch.swisscom.mid.verifier.MobileIdCmsVerifier -cms=MIII...
  echo -n MIII... | java ch.swisscom.mid.verifier.MobileIdCmsVerifier -stdin
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
X509 SignerCert Validity currently valid: true
User's unique Mobile ID SerialNumber: MIDCHE5HR8NAWUB3
Signed Data: Test: Sign this Text? (ptp2cn)
Signature Valid: true
X509 SignerCert Valid (Path+OCSP): true
```
