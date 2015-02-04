package com.github.beat.signer.pdf_signer;

/**
 * Defines the human visible part of a signature.
 */
public class SignatureAppearance {

	private boolean visibleSignature;
	private String reason;
	private String contact;
	private String location;

	public boolean isVisibleSignature() {
		return visibleSignature;
	}

	public void setVisibleSignature(boolean visibleSignature) {
		this.visibleSignature = visibleSignature;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getContact() {
		return contact;
	}

	public void setContact(String contact) {
		this.contact = contact;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

}
