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

import static com.magicalteam.authentication.EncodingUtilities.base64UrlDecode;
import static com.magicalteam.authentication.EncodingUtilities.getHash;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.inject.Singleton;

import org.apache.commons.lang.ArrayUtils;
import org.forgerock.openam.utils.JsonValueBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.magicalteam.authentication.data.AuthData;
import com.magicalteam.authentication.data.Key;

@Singleton
public class AuthenticationFlow {

    private AuthenticatorDecoder authenticatorDecoder = new AuthenticatorDecoder();

    public boolean accept(String clientData, byte[] authenticatorData, byte[] signature, byte[] challengeBytes, Key keyData) {

        Map<String,Object> map;
        try {
            map = JsonValueBuilder.getObjectMapper().readValue(clientData, Map.class);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        if (!map.containsKey("type") || !map.get("type").toString().equals("webauthn.get")) {
            return false;
        }

        byte[] decodeBytes = base64UrlDecode(map.get("challenge").toString());
        if (!Arrays.equals(challengeBytes, decodeBytes)) {
            return false;
        }

        // TODO verify origin

        // TODO verify status

        AuthData authData = authenticatorDecoder.decode(authenticatorData);

        if (!Arrays.equals(getHash("am.example.com"), authData.rpIdHash)) {
            return false;
        }

        byte[] cDataHash = getHash(clientData);
        byte[] concatBytes = ArrayUtils.addAll(authenticatorData, cDataHash);

        // TODO MAGIC KEY STUFF HERE
        keyData.

        return true;
    }

}
