package com.github.beat.signer.pdf_signer;

public class SignatureInformation {

	private TSAInformation timestamper;
	private SignatureCryptoInformation signatureCryptoInfo;

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

}
