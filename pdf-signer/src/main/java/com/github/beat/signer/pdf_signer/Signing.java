package com.github.beat.signer.pdf_signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
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

	private Certificate[] certChain;

	private TSAClient tsaClient;

	private SignatureAppearance signatureAppearance;

	public Signing(SignatureInformation signatureInformation) {
		try {
			this.signatureAppearance = signatureInformation.getSignatureAppearance();
			SignatureCryptoInformation cryptoInfo = signatureInformation.getSignatureCryptoInfo();
			KeyStore keystore = cryptoInfo.getKeystore();
			privKey = (PrivateKey) keystore.getKey(cryptoInfo.getCertAlias(), cryptoInfo.getPassword());
			certChain = keystore.getCertificateChain(cryptoInfo.getCertAlias());

			if (signatureInformation.getTimestamper() != null) {
				tsaClient = new TSAClient(signatureInformation.getTimestamper(),
						MessageDigest.getInstance(signatureInformation.getTimestamper().getDigestToUseForRequest()));
			}
		} catch (KeyStoreException e) {
			throw new RuntimeException("Password wrong", e);
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public ByteArrayOutputStream signPDF(InputStream document) throws IOException {
		if (document == null) {
			new RuntimeException("Document to sign not found");
		}

		// load document
		PDDocument doc = PDDocument.load(document);

		// create signature dictionary
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// subfilter for basic and PAdES Part 2 signatures
		signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		signature.setName(signatureAppearance.getContact());
		signature.setLocation(signatureAppearance.getLocation());
		signature.setReason(signatureAppearance.getReason());

		// the signing date, needed for valid signature
		signature.setSignDate(Calendar.getInstance());

		// register signature dictionary and sign interface
		SignatureOptions sigOpts;
		if (signatureAppearance.isVisibleSignature()) {
			 sigOpts = createVisibleSignature(doc);
			sigOpts.setPreferredSignatureSize(100000);
			doc.addSignature(signature, this, sigOpts);
		} else {
			sigOpts = new SignatureOptions();
			sigOpts.setPreferredSignatureSize(100000);
			doc.addSignature(signature, this, sigOpts);
		}
		// write incremental (only for signing purpose)
		ByteArrayOutputStream baos = new ByteArrayOutputStream();		
		doc.saveIncremental(baos);		

		// if this object dies, finalize will be called and the signature will fail
		sigOpts.close();
		return baos;
	}

	private SignatureOptions createVisibleSignature(PDDocument doc) throws IOException {
		SignatureOptions sigOpts = new SignatureOptions();

		// why is this needed?
		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(doc,
				Signing.class.getResourceAsStream("/test.jpg"), 1);
		visibleSig.xAxis(0).yAxis(0).zoom(-50).signatureFieldName("signature");

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();

		signatureProperties.signerName(signatureAppearance.getContact())
				.signerLocation(signatureAppearance.getLocation()).signatureReason(signatureAppearance.getReason())
				.preferredSize(0).page(1).visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

		sigOpts.setVisualSignature(signatureProperties);
		return sigOpts;
	}

	public byte[] sign(InputStream content) {
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		// CertificateChain
		List<Certificate> certList = Arrays.asList(certChain);

		try {
			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList),
					provider);

			Hashtable signedAttrs = new Hashtable();
			X509Certificate signingCert = (X509Certificate) certList.get(0);
			gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
					.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
					.build("SHA256withRSA", privKey, signingCert));

			gen.addCertificates(new JcaCertStore(certList));
			// gen.addCRLs(new JcaCRLStore(certStore.getCRLs(null)));
			boolean embedCrls = true;
			if (embedCrls) {
				X509CRL[] crls = fetchCRLs(signingCert);
				for (X509CRL crl : crls) {
					gen.addCRL(new JcaX509CRLHolder(crl));
				}
			}
			// gen.addOtherRevocationInfo(arg0, arg1);

			CMSProcessableByteArray processable = new CMSProcessableByteArray(IOUtils.toByteArray(content));

			CMSSignedData signedData = gen.generate(processable, false);
			if (tsaClient != null) {
				signedData = signTimeStamps(signedData);
			}
			return signedData.getEncoded();
		} catch (Exception e) {
			new RuntimeException(e);
		}
		throw new RuntimeException("Problem while preparing signature");

	}

	private X509CRL[] fetchCRLs(X509Certificate signingCert)
			throws CertificateException, MalformedURLException, CRLException, IOException {
		List<String> crlList = CRLDistributionPointsExtractor.getCrlDistributionPoints(signingCert);
		List<X509CRL> crls = new ArrayList<X509CRL>();
		for (String crlUrl : crlList) {
			if (!crlUrl.startsWith("http")) {
				continue;
			}
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			URL url = new URL(crlUrl);
			X509CRL crl = (X509CRL) cf.generateCRL(url.openStream());
			crls.add(crl);
		}
		return crls.toArray(new X509CRL[] {});
	}

	/**
	 * We just extend CMS signed Data
	 *
	 * @param signedData
	 *            -Generated CMS signed data
	 * @return CMSSignedData - Extended CMS signed data
	 */
	private CMSSignedData signTimeStamps(CMSSignedData signedData) throws IOException, TSPException {
		SignerInformationStore signerStore = signedData.getSignerInfos();
		List<SignerInformation> newSigners = new ArrayList<SignerInformation>();

		for (SignerInformation signer : (Collection<SignerInformation>) signerStore.getSigners()) {
			newSigners.add(signTimeStamp(signer));
		}

		// TODO do we have to return a new store?
		return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
	}

	/**
	 * We are extending CMS Signature
	 *
	 * @param signer
	 *            information about signer
	 * @return information about SignerInformation
	 */
	private SignerInformation signTimeStamp(SignerInformation signer) throws IOException, TSPException {
		AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

		ASN1EncodableVector vector = new ASN1EncodableVector();
		if (unsignedAttributes != null) {
			vector = unsignedAttributes.toASN1EncodableVector();
		}

		byte[] token = tsaClient.getTimeStampToken(signer.getSignature());
		ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
		ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

		vector.add(signatureTimeStamp);
		Attributes signedAttributes = new Attributes(vector);

		SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer,
				new AttributeTable(signedAttributes));

		return newSigner;
	}

	private AttributeTable createAttrs(byte[] digestBytes, Date signingDate) {
		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
		signedAttributes.add(
				new Attribute(CMSAttributes.contentType, new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));
		signedAttributes.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digestBytes))));
		signedAttributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(signingDate))));

		AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
		return signedAttributesTable;
	}
}
