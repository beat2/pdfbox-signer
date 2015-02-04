package com.github.beat.signer.pdf_signer;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class SigningTest {

	@Test
	public void test() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		File theFile = new File(SigningTest.class.getResource("/dummy.pdf")
				.toURI());
		SignatureInformation signatureInfo = createSignatureInfo();
		Signing signing = new Signing(signatureInfo);
		File outputFile = new File("src/test/resources/output.pdf");
		signing.signPDF(outputFile, theFile);
	}

	@Test
	public void testNotVis() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		File theFile = new File(SigningTest.class.getResource("/dummy.pdf")
				.toURI());
		SignatureInformation signatureInfo = createSignatureInfo();
		signatureInfo.getSignatureAppearance().setVisibleSignature(false);
		Signing signing = new Signing(signatureInfo);
		File outputFile = new File("src/test/resources/output_not_vis.pdf");
		signing.signPDF(outputFile, theFile);
	}

	private SignatureInformation createSignatureInfo() {
		SignatureInformation sigInfo = new SignatureInformation();
		sigInfo.setSignatureCryptoInfo(createSigCryptoInfo());
		sigInfo.setTimestamper(createTsaInformation());
		sigInfo.setSignatureAppearance(createSigAppearance());
		return sigInfo;
	}

	private SignatureAppearance createSigAppearance() {
		SignatureAppearance sigApp = new SignatureAppearance();
		sigApp.setContact("meier");
		sigApp.setLocation("sss");
		sigApp.setReason("egal");
		sigApp.setVisibleSignature(true);
		return sigApp;
	}

	private TSAInformation createTsaInformation() {
		TSAInformation tsaInfo = new TSAInformation();
		tsaInfo.setDigestToUseForRequest("SHA-256");
		try {
			tsaInfo.setTsaUrl(new URL("http://tsa.pki.admin.ch/tsa"));
		} catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
		return tsaInfo;
	}

	private SignatureCryptoInformation createSigCryptoInfo() {
		SignatureCryptoInformation sigCryptoInfo = new SignatureCryptoInformation();
		sigCryptoInfo.setCertAlias("Heiri Muster (Qualified Signature)");
		KeyStore myKeystore = loadKeystore();
		try {
			myKeystore.load(SigningTest.class
					.getResourceAsStream("/dummy_keystore.p12"), "keypassword"
					.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new RuntimeException(e);
		}
		sigCryptoInfo.setKeystore(myKeystore);
		sigCryptoInfo.setPassword("keypassword".toCharArray());
		sigCryptoInfo.setProvider(myKeystore.getProvider());

		return sigCryptoInfo;
	}

	private KeyStore loadKeystore() {
		try {
			return KeyStore.getInstance("PKCS12", "BC");
		} catch (KeyStoreException ex) {
			throw new RuntimeException(ex);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

}
