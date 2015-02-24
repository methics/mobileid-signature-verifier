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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
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
			System.out.println("Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier [OPTIONS]");
			System.out.println();
			System.out.println("Options:");
			System.out.println("  -cms=VALUE or -stdin   - base64 encoded CMS/PKCS7 signature string, either as VALUE or via standard input");
			System.out.println("  -jks=VALUE             - optional path to truststore file (default is 'jks/truststore.jks')");
			System.out.println("  -jkspwd=VALUE          - optional truststore password (default is 'secret')");
			System.out.println();
			System.out.println("Example:");
			System.out.println("  java ch.swisscom.mid.verifier.MobileIdCmsVerifier -cms=MIII...");
			System.out.println("  echo -n MIII... | java ch.swisscom.mid.verifier.MobileIdCmsVerifier -stdin");
			System.exit(1);
		}
		
		try {
			
			MobileIdCmsVerifier verifier = null;
			
			String jks = "jks/truststore.jks";
			String jkspwd = "secret";
			
			String param;
			for (int i = 0; i < args.length; i++) {	
				param = args[i].toLowerCase();
				if (param.contains("-jks=")) {
					jks = args[i].substring(args[i].indexOf("=") + 1).trim();
				} 
				else if (param.contains("-jkspwd=")) {
					jkspwd = args[i].substring(args[i].indexOf("=") + 1).trim();
				} 
				else if (param.contains("-cms=")) {
					verifier = new MobileIdCmsVerifier(args[i].substring(args[i].indexOf("=") + 1).trim());
				} 
				else if (param.contains("-stdin")) {
					BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
				    String stdin;
				    if ((stdin = in.readLine()) != null && stdin.length() != 0)
				    	verifier = new MobileIdCmsVerifier(stdin.trim());
				}
			}
			
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(jks), jkspwd.toCharArray());
			
			// If you are behind a Proxy..
			// System.setProperty("proxyHost", "10.185.32.54");
			// System.setProperty("proxyPort", "8079");
			// or set it via VM arguments: -DproxySet=true -DproxyHost=10.185.32.54 -DproxyPort=8079
			
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
	
	/**
	 * Prints Issuer/SubjectDN/SerialNumber of all x509 certificates that can be found in the CMSSignedData
	 * 
	 * @throws CertificateException
	 */
	private void printAllX509Certificates() throws CertificateException {
		
		// Find all available certificates with getMatches(null)
		Iterator<?> certIt = cmsSignedData.getCertificates().getMatches(null).iterator();
		int i = 0;
		
		while (certIt.hasNext()){
			X509CertificateHolder certHolder =  (X509CertificateHolder)certIt.next();
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
			System.out.println("X509 Certificate #" + ++i);
			System.out.println("X509 Issuer: " + cert.getIssuerDN());
			System.out.println("X509 Subject DN: " + cert.getSubjectDN());
			System.out.println("X509 SerialNumber: " + cert.getSerialNumber());
			System.out.println("SignerCert: " +  (cert.getBasicConstraints() == -1 ? "Yes" : "No"));
			System.out.println();
		}
	}

	/**
	 * Validates the specified certificate path incl. OCSP revocation check
	 * 
	 * @param truststore
	 * @return true if all certificate is valid
	 * @throws Exception 
	 */
	private boolean isCertValid(KeyStore truststore) throws Exception {
		List<X509Certificate> certlist = new ArrayList<X509Certificate>();
		certlist.add(signerCert);

		PKIXParameters params = new PKIXParameters(truststore);
		
		// Activate certificate revocation checking
        params.setRevocationEnabled(true);

        // Activate OCSP
        Security.setProperty("ocsp.enable", "true");

        // Activate CRLDP
        System.setProperty("com.sun.security.enableCRLDP", "true");

        // Ensure that the ocsp.responderURL property is not set.
		if (Security.getProperty("ocsp.responderURL") != null) {
			throw new Exception("The ocsp.responderURL property must not be set");
		}

		CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());

		cpv.validate(CertificateFactory.getInstance("X.509").generateCertPath(certlist), params);

		return true; // No Exception, all fine..
	}
	
	/**
	 * Checks that the certificate is currently valid. It is if the current date and time are within the validity period given in the certificate.
	 * 
	 * @return true if certificate is currently valid, false otherwise.
	 */
	private boolean isCertCurrentlyValid() {
		try {
			signerCert.checkValidity();
			return true;
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
		}
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
