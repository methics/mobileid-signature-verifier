/**
 * Copyright (C) 2014 - Swisscom (Schweiz) AG
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or (at your 
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see http://www.gnu.org/licenses/.
 * 
 * @author <a href="mailto:philipp.haupt@swisscom.com">Philipp Haupt</a>
 */

package ch.swisscom.mid.verifier;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.*;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class MobileIdCmsVerifier {

	private CMSSignedData cmsSignedData;
	private X509CertificateHolder x509CertHolder;
	private SignerInformation signerInfo;
	private X509Certificate signerCert;

	public static void main(String[] args) {
		
		if (args == null || args.length < 1) {
			System.out.println("Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier <Base64Signature>");
			System.out.println();
			System.out.println("Options:");
			System.out.println("  <Base64Signature> - Base 64 encoded CMS/PKCS7 signature string");
			System.out.println();
			System.out.println("Example:");
			System.out.println("  java ch.swisscom.mid.verifier.MobileIdCmsVerifier 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");
			System.exit(1);
		}
		
		try {
			MobileIdCmsVerifier verifier = new MobileIdCmsVerifier(args[0]);

			// Swisscom Root CA 2 Certificate (Production)
			// Alias name: swisscom root ca 2
			// Owner: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
			// Certificate fingerprints MD5: 5B:04:69:EC:A5:83:94:63:18:A7:86:D0:E4:F2:6E:19
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream("jks/truststore.jks"), "secret".toCharArray());
			X509Certificate rootCert = (X509Certificate) keyStore.getCertificate("swisscom root ca 2");

			// TODO: Validate Certificate against trust anchor (root certificate)
			System.out.println("X509 Trusted: " + verifier.isSignerCertTrusted(rootCert));
			
			// TODO: OCSP or CRL revocation check
			System.out.println("X509 Revoked: " + verifier.isRevoked());

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

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Will attempt to initialize the signer certificate
	 * 
	 * @param cmsSignatureBase64
	 *            Base 64 encoded CMS/PKCS7 String
	 * @throws CMSException
	 * @throws CertificateException
	 */
	public MobileIdCmsVerifier(String cmsSignatureBase64) throws CMSException, CertificateException {
		this.cmsSignedData = new CMSSignedData(Base64.decodeBase64(cmsSignatureBase64));
		// Find the signer certificate
		SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
		signerInfo = (SignerInformation) signerInfoStore.getSigners().iterator().next();
		x509CertHolder = (X509CertificateHolder) cmsSignedData.getCertificates().getMatches(signerInfo.getSID()).iterator().next();
		signerCert = new JcaX509CertificateConverter().getCertificate(x509CertHolder);
	}

	// TODO: code
	private boolean isSignerCertTrusted(X509Certificate rootCert) {
		return true;
	}
	
	// TODO: code
	private boolean isRevoked() {
		return false;
	}

	/**
	 * Gets the serialNumber value from the certificate. The serial number is an integer assigned by the certification authority to each certificate. It must be
	 * unique for each certificate issued by a given CA (i.e., the issuer name and serial number identify a unique certificate).
	 * 
	 * @return the serial number.
	 */
	private BigInteger getX509SerialNumber() {
		return signerCert.getSerialNumber();
	}

	/**
	 * Gets the subject (subject distinguished name) value from the certificate.
	 * 
	 * @return a Principal whose name is the subject name.
	 */
	private Principal getX509SubjectDN() {
		return signerCert.getSubjectDN();
	}

	/**
	 * Gets the issuer (issuer distinguished name) value from the certificate.
	 * 
	 * @return a Principal whose name is the issuer distinguished name.
	 */
	private Principal getX509IssuerDN() {
		return signerCert.getIssuerDN();
	}

	/**
	 * Gets the notBefore date from the validity period of the certificate.
	 * 
	 * @return the start date of the validity period.
	 */
	private Date getX509NotBefore() {
		return signerCert.getNotBefore();
	}

	/**
	 * Gets the notAfter date from the validity period of the certificate.
	 * 
	 * @return the end date of the validity period.
	 */
	private Date getX509NotAfter() {
		return signerCert.getNotAfter();
	}

	/**
	 * Get the user's unique Mobile ID SerialNumber from the signer certificate's SubjectDN
	 * 
	 * @return the user's unique Mobile ID serial number.
	 */
	private String getMIDSerialNumber() {
		Pattern pattern = Pattern.compile(".*SERIALNUMBER=(.{16}).*");
		Matcher matcher = pattern.matcher(signerCert.getSubjectDN().getName().toUpperCase());
		matcher.find();
		return matcher.group(1);
	}

	/**
	 * Get signed content - should be equal to the DTBS Message of the origin Signature Request
	 * 
	 * @return the signed data.
	 */
	private String getSignedData() {
		return new String((byte[]) cmsSignedData.getSignedContent().getContent()).toString();
	}

	/**
	 * Verify the signature on the SignerInformation object
	 * 
	 * @return true if the signer information is verified, false otherwise.
	 * @throws OperatorCreationException
	 * @throws CMSException
	 */
	private boolean isVerified() throws OperatorCreationException, CMSException {
		// Verify that the given verifier can successfully verify the signature on this SignerInformation object
		SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(),
				new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider())
				.build(x509CertHolder);
		return signerInfo.verify(verifier);
	}

}
