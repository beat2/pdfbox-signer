package com.github.beat.signer.pdf_signer;

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Time Stamping Authority (TSA) Client [RFC 3161].
 * 
 * @author Vakhtang Koroghlishvili
 * @author John HewsonF
 */
public class TSAClient {
	private static final int CONNECT_TIMEOUT = 3000;

	private static final Log LOGGER = LogFactory.getLog(TSAClient.class);

	private final MessageDigest digest;

	private final TSAInformation tsaInfo;

	public TSAClient(TSAInformation tsaInfo, MessageDigest digest) {
		this.tsaInfo = tsaInfo;
		this.digest = digest;
	}

	/**
	 *
	 * @param messageImprint
	 *            imprint of message contents
	 * @return the encoded time stamp token
	 * @throws IOException
	 *             if there was an error with the connection or data from the
	 *             TSA server, or if the time stamp response could not be
	 *             validated
	 */
	public byte[] getTimeStampToken(byte[] messageImprint) throws IOException {
		digest.reset();
		byte[] hash = digest.digest(messageImprint);

		// 32-bit cryptographic nonce
		// FIXME sicher??
		SecureRandom random = new SecureRandom();
		int nonce = random.nextInt();

		// generate TSA request
		TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
		tsaGenerator.setCertReq(true);
		ASN1ObjectIdentifier oid = getHashObjectIdentifier(digest
				.getAlgorithm());
		TimeStampRequest request = tsaGenerator.generate(oid, hash,
				BigInteger.valueOf(nonce));

		// get TSA response
		byte[] tsaResponse = getTSAResponse(request.getEncoded());

		TimeStampResponse response;
		try {
			response = new TimeStampResponse(tsaResponse);
			response.validate(request);
		} catch (TSPException e) {
			throw new IOException(e);
		}

		TimeStampToken token = response.getTimeStampToken();
		if (token == null) {
			throw new IOException("Response does not have a time stamp token");
		}

		return token.getEncoded();
	}

	// gets response data for the given encoded TimeStampRequest data
	// throws IOException if a connection to the TSA cannot be established
	private byte[] getTSAResponse(byte[] request) throws IOException {
		LOGGER.debug("Opening connection to TSA server");

		// FIXME: support proxy servers
		URLConnection connection = tsaInfo.getTsaUrl().openConnection();
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setReadTimeout(CONNECT_TIMEOUT);
		connection.setConnectTimeout(CONNECT_TIMEOUT);
		connection.setRequestProperty("Content-Type",
				"application/timestamp-query");

		// TODO set accept header

		LOGGER.debug("Established connection to TSA server");

		String username = tsaInfo.getUsername();
		char[] password = tsaInfo.getPassword();
		if (StringUtils.isNotBlank(username) && password != null) {
			// FIXME this most likely wrong, e.g. set correct request property!
			// connection.setRequestProperty(username, password);
		}

		// read response
		sendRequest(request, connection);

		LOGGER.debug("Waiting for response from TSA server");

		byte[] response = getResponse(connection);

		LOGGER.debug("Received response from TSA server");

		return response;
	}

	private void sendRequest(byte[] request, URLConnection connection)
			throws IOException {
		OutputStream output = null;
		try {
			output = connection.getOutputStream();
			output.write(request);
		} finally {
			IOUtils.closeQuietly(output);
		}
	}

	private byte[] getResponse(URLConnection connection) throws IOException {
		InputStream input = null;
		try {
			input = connection.getInputStream();
			return IOUtils.toByteArray(input);
		} finally {
			IOUtils.closeQuietly(input);
		}
	}

	// returns the ASN.1 OID of the given hash algorithm
	private ASN1ObjectIdentifier getHashObjectIdentifier(String algorithm) {
		return DigestFactory.getOID(algorithm);
	}
}