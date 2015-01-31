package com.github.beat.signer.pdf_signer;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;

public class Signing implements SignatureInterface {

	private static BouncyCastleProvider provider = new BouncyCastleProvider();

	private PrivateKey privKey;

	private Certificate[] cert;
	
	private TSAClient tsaClient;

	public Signing(SignatureInformation signatureInformation) {
		try {

			SignatureCryptoInformation cryptoInfo = signatureInformation
					.getSignatureCryptoInfo();
			KeyStore keystore = cryptoInfo.getKeystore();
			privKey = (PrivateKey) keystore.getKey(cryptoInfo.getCertAlias(),
					cryptoInfo.getPassword());
			cert = keystore.getCertificateChain(cryptoInfo.getCertAlias());
			
			if (signatureInformation.getTimestamper() != null) {
				tsaClient = new TSAClient(
						signatureInformation.getTimestamper(),
						MessageDigest.getInstance("SHA-256"));
			}
		} catch (KeyStoreException e) {
			throw new RuntimeException("Password wrong", e);
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public File signPDF(File document) throws IOException, COSVisitorException,
			SignatureException {
		if (document == null || !document.exists()) {
			new RuntimeException("Document to sign not found");
		}

		File outputDocument = new File("resources/" + UUID.randomUUID().toString() + document.getName());
		FileInputStream fis = new FileInputStream(document);
		FileOutputStream fos = new FileOutputStream(outputDocument);

		org.apache.commons.io.IOUtils.copy(fis, fos);
		fis = new FileInputStream(outputDocument);

		// load document
		PDDocument doc = PDDocument.load(document);

		// create signature dictionary
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// subfilter for basic and PAdES Part 2 signatures
		signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		signature.setName("signer name");
		signature.setLocation("signer location");
		signature.setReason("reason for signature");

		// the signing date, needed for valid signature
		signature.setSignDate(Calendar.getInstance());

		// register signature dictionary and sign interface
		doc.addSignature(signature, this);

		// write incremental (only for signing purpose)
		doc.saveIncremental(fis, fos);

		return outputDocument;
	}

	public byte[] sign(InputStream content) throws SignatureException,
			IOException {
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		// CertificateChain
		List<Certificate> certList = Arrays.asList(cert);

		try {
			CertStore certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(certList), provider);

			Hashtable signedAttrs = new Hashtable();
			X509Certificate signingCert = (X509Certificate) certList.get(0);
			gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
					.setProvider("BC")
					.setSignedAttributeGenerator(
							new AttributeTable(signedAttrs))
					.build("SHA256withRSA", privKey, signingCert));

			gen.addCertificates(new JcaCertStore(certList));
			gen.addCRLs(new JcaCRLStore(certStore.getCRLs(null)));
			
			CMSProcessableByteArray processable = new CMSProcessableByteArray(
					IOUtils.toByteArray(content)); // TODO use commons io
			// CMSSignedData signedData = gen.generate(input, false, provider);
			CMSSignedData signedData = gen.generate(processable, false);
			if (tsaClient != null){
				signedData = signTimeStamps(signedData);
			}
			return signedData.getEncoded();
		} catch (Exception e) {
			new RuntimeException(e);
		}
		throw new RuntimeException("Problem while preparing signature");
	}

	public static void main(String[] args) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, COSVisitorException,
			SignatureException {

		SignatureInformation signatureInfo = new SignatureInformation();
		SignatureCryptoInformation signatureCryptoInfo = new SignatureCryptoInformation();
		signatureCryptoInfo
				.setCertAlias("Heiri Muster (Qualified Signature)");
		String password = "keypassword";
		signatureCryptoInfo.setPassword(password.toCharArray());

		File ksFile = new File("resources/swisssign_suisseid_test_qual_0000.p12");
		KeyStore keystore = KeyStore.getInstance("PKCS12", provider);

		keystore.load(new FileInputStream(ksFile), password.toCharArray());

		signatureCryptoInfo.setKeystore(keystore);
		signatureInfo.setSignatureCryptoInfo(signatureCryptoInfo);
		
		TSAInformation timestamper = new TSAInformation();
		timestamper.setTsaUrl(new URL("http://tsa.pki.admin.ch/tsa"));
		signatureInfo.setTimestamper(timestamper);

		Security.addProvider(provider);

		File document = new File("resources/test.pdf");

		Signing signing = new Signing(signatureInfo);
		signing.signPDF(document);
	}
	
	/**
	 * We just extend CMS signed Data
	 *
	 * @param signedData
	 *            -Generated CMS signed data
	 * @return CMSSignedData - Extended CMS signed data
	 */
	private CMSSignedData signTimeStamps(CMSSignedData signedData)
			throws IOException, TSPException {
		SignerInformationStore signerStore = signedData.getSignerInfos();
		List<SignerInformation> newSigners = new ArrayList<SignerInformation>();

		for (SignerInformation signer : (Collection<SignerInformation>) signerStore
				.getSigners()) {
			newSigners.add(signTimeStamp(signer));
		}

		// TODO do we have to return a new store?
		return CMSSignedData.replaceSigners(signedData,
				new SignerInformationStore(newSigners));
	}
	
	/**
	 * We are extending CMS Signature
	 *
	 * @param signer
	 *            information about signer
	 * @return information about SignerInformation
	 */
	private SignerInformation signTimeStamp(SignerInformation signer)
			throws IOException, TSPException {
		AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

		ASN1EncodableVector vector = new ASN1EncodableVector();
		if (unsignedAttributes != null) {
			vector = unsignedAttributes.toASN1EncodableVector();
		}

		byte[] token = tsaClient.getTimeStampToken(signer.getSignature());
		ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
		ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(
				ASN1Primitive.fromByteArray(token)));

		vector.add(signatureTimeStamp);
		Attributes signedAttributes = new Attributes(vector);

		SignerInformation newSigner = SignerInformation
				.replaceUnsignedAttributes(signer, new AttributeTable(
						signedAttributes));

		return newSigner;
	}
}
