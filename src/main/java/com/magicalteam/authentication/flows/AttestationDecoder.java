/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */
package com.magicalteam.authentication.flows;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.magicalteam.authentication.data.AttestationObject;
import com.magicalteam.authentication.data.FidoAttestationStatement;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * Class to decode the packed bytes of the authentication registration attestation response.
 * https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AttestationDecoder {

    private static final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Decode the byte data, converting it into rich objects which can be reasoned about.
     * @param attestationData the data as bytes.
     * @return the data as an AttestationObject.
     */
    AttestationObject decode(byte[] attestationData) throws DecodingException {

        AttestationObject attestationObject = new AttestationObject();
        ByteArrayInputStream bais = new ByteArrayInputStream(attestationData);
        List<DataItem> dataItems = null;
        try {
            dataItems = new CborDecoder(bais).decode();
        } catch (CborException e) {
            e.printStackTrace();
        }
        Map attObjMap = (Map) dataItems.get(0);
        for (DataItem key : attObjMap.getKeys()) {
            if (key instanceof UnicodeString) {
                if (((UnicodeString) key).getString().equals("fmt")) {
                    UnicodeString value = (UnicodeString) attObjMap.get(key);
                    attestationObject.fmt = value.getString();
                }
                if (((UnicodeString) key).getString().equals("authData")) {
                    byte[] authData = ((ByteString) attObjMap.get(key)).getBytes();
                    attestationObject.authData = AuthDataDecoder.decode(authData);
                }
                if (((UnicodeString) key).getString().equals("attStmt")) {
                    Map attSmtMap = (Map) attObjMap.get(key);
                    attestationObject.attestationStatement = decodeAttStmt(attSmtMap, attestationObject.fmt);
                }
            }
        }

        return attestationObject;
    }

    private FidoAttestationStatement decodeAttStmt(Map attSmtMap, String fmt) {
        byte[] attestnCert = new byte[0];
        byte[] caCert = new byte[0];
        byte[] sig = new byte[0];
        if ("fido-u2f".equals(fmt)) {
            for(DataItem attSmtKey : attSmtMap.getKeys()) {
                if (((UnicodeString) attSmtKey).getString().equals("x5c")) {
                    List<DataItem> items = ((Array) attSmtMap.get(attSmtKey)).getDataItems();
                    attestnCert = ((ByteString)items.get(0)).getBytes();
                    if (items.size() > 1) {
                        caCert = ((ByteString)items.get(1)).getBytes();
                    }
                }
                if (((UnicodeString) attSmtKey).getString().equals("sig")) {
                    sig = ((ByteString) attSmtMap.get(attSmtKey)).getBytes();
                }
            }
        }
        FidoAttestationStatement attestationStatement = new FidoAttestationStatement();
        attestationStatement.attestnCerts = new ArrayList<>();
        X509Certificate cert = createCert(attestnCert);
        if (cert != null) {
            attestationStatement.attestnCerts.add(cert);
        }
        attestationStatement.caCert = caCert;
        attestationStatement.sig = sig;
        return attestationStatement;
    }

    private static X509Certificate createCert(byte[] certData){
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certData));
        }
        catch (Exception e) {
            logger.debug("failed to convert certificate data into a certificate object");
            return null;
        }
    }
}
