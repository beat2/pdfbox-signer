package com.github.beat.signer.pdf_signer;

/**
 * Combines the crypto stuff, timestamping information and signature appearance.
 *
 */
public class SignatureInformation {

	private TSAInformation timestamper;
	private SignatureCryptoInformation signatureCryptoInfo;
	private SignatureAppearance signatureAppearance;

	public TSAInformation getTimestamper() {
		return timestamper;
	}

	public void setTimestamper(TSAInformation timestamper) {
		this.timestamper = timestamper;
	}

	public SignatureCryptoInformation getSignatureCryptoInfo() {
		return signatureCryptoInfo;
	}

	public void setSignatureCryptoInfo(
			SignatureCryptoInformation signatureCryptoInfo) {
		this.signatureCryptoInfo = signatureCryptoInfo;
	}

	public SignatureAppearance getSignatureAppearance() {
		return signatureAppearance;
	}

	public void setSignatureAppearance(SignatureAppearance signatureAppearance) {
		this.signatureAppearance = signatureAppearance;
	}

}
