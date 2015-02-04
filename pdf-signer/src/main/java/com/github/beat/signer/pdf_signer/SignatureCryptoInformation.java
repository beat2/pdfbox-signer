package com.github.beat.signer.pdf_signer;
import java.security.KeyStore;
import java.security.Provider;


/**
 * Defines access to the certificates used for signing and the associated private key.
 *
 */
public class SignatureCryptoInformation {
	
	private Provider provider;
	private KeyStore keystore;
	private char[] password;
	private String certAlias;
	
	public Provider getProvider() {
		return provider;
	}

	public void setProvider(Provider provider) {
		this.provider = provider;
	}

	public KeyStore getKeystore() {
		return keystore;
	}

	public void setKeystore(KeyStore keystore) {
		this.keystore = keystore;
	}

	public char[] getPassword() {
		return password;
	}

	public void setPassword(char[] password) {
		this.password = password;
	}

	public String getCertAlias() {
		return certAlias;
	}

	public void setCertAlias(String certAlias) {
		this.certAlias = certAlias;
	}
	

}
