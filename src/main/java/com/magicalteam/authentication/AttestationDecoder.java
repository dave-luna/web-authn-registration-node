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
package com.magicalteam.authentication;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import com.magicalteam.authentication.data.AttestationFlags;
import com.magicalteam.authentication.data.AttestationObject;
import com.magicalteam.authentication.data.AttestedCredentialData;
import com.magicalteam.authentication.data.AuthData;
import com.magicalteam.authentication.data.FidoAttestationStatement;
import com.magicalteam.authentication.data.Key;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * Class to decode the packed bytes of the authentication registration attestation response.
 * https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AttestationDecoder {

    /**
     * Decode the byte data, converting it into rich objects which can be reasoned about.
     * @param attestationData the data as bytes.
     * @return the data as an AttestationObject.
     */
    AttestationObject decode(byte[] attestationData) {

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
                    attestationObject.authData = decodeAuthData(authData);
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
        attestationStatement.attestnCert = attestnCert;
        attestationStatement.caCert = caCert;
        attestationStatement.sig = sig;
        return attestationStatement;
    }

    private AuthData decodeAuthData(byte[] authDataAsBytes) {
        AuthData authData = new AuthData();
        authData.rpIdHash = Arrays.copyOfRange(authDataAsBytes, 0, 32);

        BitSet flags = BitSet.valueOf(Arrays.copyOfRange(authDataAsBytes, 32, 33));
        authData.attestationFlags = new AttestationFlags(flags);

        byte[] signCount = Arrays.copyOfRange(authDataAsBytes, 33, 37);
        ByteBuffer wrapped = ByteBuffer.wrap(signCount);
        authData.signCount = wrapped.getInt();

        authData.attestedCredentialData = addAttestedCredentialData(authDataAsBytes);

        return authData;
    }

    private AttestedCredentialData addAttestedCredentialData(byte[] authData) {
        AttestedCredentialData attestedCredentialData = new AttestedCredentialData();

        attestedCredentialData.aaguid = Arrays.copyOfRange(authData, 37, 53);

        byte[] credentialIdLength = Arrays.copyOfRange(authData, 53, 55);
        ByteBuffer wrapped = ByteBuffer.wrap(credentialIdLength);
        int credentialIdLengthValue = wrapped.getShort();
        attestedCredentialData.credentialIdLength = credentialIdLengthValue;

        int index = 55;
        if (credentialIdLengthValue > 0) {
            attestedCredentialData.credentialId = Arrays.copyOfRange(authData, 55, 55 + credentialIdLengthValue);
            index = index + credentialIdLengthValue;
        }

        byte[] publicKeyBytes = Arrays.copyOfRange(authData, index, authData.length);

        List<DataItem> dataItems = null;
        try {
            dataItems = new CborDecoder(new ByteArrayInputStream(publicKeyBytes)).decode();
        } catch (CborException e) {
            e.printStackTrace();
        }
        Key publicKey = new Key();
        Map attObjMap = (Map) dataItems.get(0);
        for (DataItem key : attObjMap.getKeys()) {
            if (key instanceof Number) {
                if (((Number) key).getValue().intValue() == 1) {
                    Number value = (Number) attObjMap.get(key);
                    publicKey.keyType = value.getValue().intValue();
                }
                if (((Number) key).getValue().intValue() == 3) {
                    Number value = (Number) attObjMap.get(key);
                    publicKey.alg = value.getValue().intValue();
                }
                if (((Number) key).getValue().intValue() == -1) {
                    Number value = (Number) attObjMap.get(key);
                    publicKey.curve = value.getValue().intValue();
                }
                if (((Number) key).getValue().intValue() == -2) {
                    ByteString value = (ByteString) attObjMap.get(key);
                    publicKey.xpos = value.getBytes();
                }
                if (((Number) key).getValue().intValue() == -3) {
                    ByteString value = (ByteString) attObjMap.get(key);
                    publicKey.ypos = value.getBytes();
                }
            }
        }

        attestedCredentialData.publicKey = publicKey;
        return attestedCredentialData;
    }
}
