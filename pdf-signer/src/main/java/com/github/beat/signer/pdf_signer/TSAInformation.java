package com.github.beat.signer.pdf_signer;
import java.net.URL;

/**
 * Contains the information about one timestamp service.
 *
 */
public class TSAInformation {

	private URL tsaUrl;
	private char[] password;
	private String username;
	private String digestToUseForRequest;

	public char[] getPassword() {
		return password;
	}

	public void setPassword(char[] password) {
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public URL getTsaUrl() {
		return tsaUrl;
	}

	public void setTsaUrl(URL tsaUrl) {
		this.tsaUrl = tsaUrl;
	}

	public String getDigestToUseForRequest() {
		return digestToUseForRequest;
	}

	public void setDigestToUseForRequest(String digestToUseForRequest) {
		this.digestToUseForRequest = digestToUseForRequest;
	}


}
