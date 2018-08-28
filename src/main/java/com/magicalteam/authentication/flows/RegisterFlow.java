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

import static com.magicalteam.authentication.flows.EncodingUtilities.base64UrlDecode;
import static com.magicalteam.authentication.flows.EncodingUtilities.getHash;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.magicalteam.authentication.data.AttestationObject;

/**
 * An implementation of https://www.w3.org/TR/webauthn/#registering-a-new-credential
 * Essentailly decodes the data and performs verification.
 */
@Singleton
public class RegisterFlow {

    private ObjectMapper mapper = new ObjectMapper();
    private AttestationDecoder attestationDecoder = new AttestationDecoder();

    public AttestationObject accept(String clientData, byte[] attestationData, byte[] challengeBytes, String rpId,
                                    boolean isUserVerificationRequired) {
        Map<String,Object> map;
        try {
            map = mapper.readValue(clientData, Map.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        if (!map.containsKey("type")) {
            return null;
        }
        if (!map.get("type").equals("webauthn.create")) {
            return null;
        }

        byte[] decodeBytes = base64UrlDecode(map.get("challenge").toString());
        if (!Arrays.equals(challengeBytes, decodeBytes)) {
            return null;
        }

        // TODO verify origin

        // TODO verify token binding status

        // TODO compute hash SHA-256 of clientData

        AttestationObject attestationObject;
        try {
            attestationObject = attestationDecoder.decode(attestationData);
        } catch (DecodingException e) {
            return null;
        }

        if (!Arrays.equals(getHash(rpId), attestationObject.authData.rpIdHash)) {
            return null;
        }

        if (isUserVerificationRequired) {
            if (!attestationObject.authData.attestationFlags.isUserVerified()) {
                return null;
            }
        } else {
            if (!attestationObject.authData.attestationFlags.isUserPresent()) {
                return null;
            }
        }

        // TODO handle extensions

        // verify depending on "fmt"
        if (attestationObject.fmt.equals("none")) {
            // store the key
            System.out.println("store the key");
        }
        if (attestationObject.fmt.equals("fido-u2f")) {
            if (attestationObject.authData.attestedCredentialData.publicKey.alg != -7) {
                return null;
            }
            // further, detailed verification required here
            // see https://www.w3.org/TR/webauthn/#fido-u2f-attestation
        }

        return attestationObject;
    }
}
