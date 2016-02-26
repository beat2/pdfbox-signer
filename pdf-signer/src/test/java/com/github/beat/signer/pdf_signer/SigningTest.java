package com.github.beat.signer.pdf_signer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

	
	private static final String DUMMY_PDF = "/dummy.pdf";

	@Test
	public void testX() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		InputStream is = SigningTest.class.getResourceAsStream(DUMMY_PDF);
		
		SignatureInformation signatureInfo = createSignatureInfo();
		Signing signing = new Signing(signatureInfo);
		
		ByteArrayOutputStream baos = signing.signPDF(is);
		
		File outputFile = new File("target/outputX.pdf");
		FileOutputStream fos = new FileOutputStream(outputFile);
		baos.writeTo(fos);
		fos.close();
	}
	
	@Test
	public void test() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		InputStream is = SigningTest.class.getResourceAsStream(DUMMY_PDF);
		
		SignatureInformation signatureInfo = createSignatureInfo();
		Signing signing = new Signing(signatureInfo);
		
		ByteArrayOutputStream baos = signing.signPDF(is);
		
		File outputFile = new File("target/output.pdf");
		FileOutputStream fos = new FileOutputStream(outputFile);
		baos.writeTo(fos);
		fos.close();
	}

	@Test
	public void testNotVis() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		InputStream is = SigningTest.class.getResourceAsStream(DUMMY_PDF);
		SignatureInformation signatureInfo = createSignatureInfo();
		signatureInfo.getSignatureAppearance().setVisibleSignature(false);
		
		Signing signing = new Signing(signatureInfo);
		File outputFile = new File("target/output_not_vis.pdf");
		ByteArrayOutputStream baos = signing.signPDF(is);
		FileOutputStream fos = new FileOutputStream(outputFile);
		baos.writeTo(fos);
		fos.close();
	}
	
	@Test
	public void noTsa() throws IOException{
		Security.addProvider(new BouncyCastleProvider());
		InputStream is = SigningTest.class.getResourceAsStream(DUMMY_PDF);
		SignatureInformation signatureInfo = createSignatureInfo();
		signatureInfo.getSignatureAppearance().setVisibleSignature(false);
		signatureInfo.setTimestamper(null);
		
		Signing signing = new Signing(signatureInfo);
		File outputFile = new File("target/output_no_tsa.pdf");
		ByteArrayOutputStream baos = signing.signPDF(is);
		FileOutputStream fos = new FileOutputStream(outputFile);
		baos.writeTo(fos);
		fos.close();
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
