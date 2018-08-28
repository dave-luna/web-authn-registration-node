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
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.magicalteam.authentication.data.AttestationFlags;
import com.magicalteam.authentication.data.AttestedCredentialData;
import com.magicalteam.authentication.data.AuthData;
import com.magicalteam.authentication.data.Key;
import com.magicalteam.authentication.flows.DecodingException;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;

/**
 * https://www.w3.org/TR/webauthn/#authenticator-data
 */
class AuthDataDecoder {

    private static final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Decodes the Auth Data.
     * @param authDataAsBytes the auth data as bytes.
     * @return AuthData object.
     */
    static AuthData decode(byte[] authDataAsBytes) throws DecodingException {
        AuthData authData = new AuthData();
        authData.rpIdHash = Arrays.copyOfRange(authDataAsBytes, 0, 32);

        BitSet flags = BitSet.valueOf(Arrays.copyOfRange(authDataAsBytes, 32, 33));
        authData.attestationFlags = new AttestationFlags(flags);

        byte[] signCount = Arrays.copyOfRange(authDataAsBytes, 33, 37);
        ByteBuffer wrapped = ByteBuffer.wrap(signCount);
        authData.signCount = wrapped.getInt();

        if (authDataAsBytes.length > 37) {
            authData.attestedCredentialData = getAttestedCredentialData(authDataAsBytes);
        }

        return authData;
    }

    private static AttestedCredentialData getAttestedCredentialData(byte[] authData) throws DecodingException {

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

        List<DataItem> dataItems;
        try {
            dataItems = new CborDecoder(new ByteArrayInputStream(publicKeyBytes)).decode();
        } catch (CborException e) {
            logger.error("failed to decode data in CBOR format", e);
            throw new DecodingException();
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
