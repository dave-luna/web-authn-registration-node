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
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

import javax.inject.Singleton;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.forgerock.openam.utils.JsonValueBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.magicalteam.authentication.data.AuthData;
import com.magicalteam.authentication.data.Key;

@Singleton
public class AuthenticationFlow {

    private AuthenticatorDecoder authenticatorDecoder = new AuthenticatorDecoder();

    public AuthenticationFlow() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public boolean accept(String clientData, byte[] authenticatorData, byte[] signature, byte[] challengeBytes,
                          Key keyData, String registeredDomains) {

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

        if (!Arrays.equals(getHash(registeredDomains), authData.rpIdHash)) {
            return false;
        }

        byte[] cDataHash = getHash(clientData);
        byte[] concatBytes = ArrayUtils.addAll(authenticatorData, cDataHash);

        // TODO MAGIC KEY STUFF HERE

        ByteBuffer buffer = ByteBuffer.allocate(keyData.xpos.length + keyData.ypos.length + 1);
        buffer.put((byte) 0x04);
        buffer.put(keyData.xpos);
        buffer.put(keyData.ypos);
        byte[] keyArray = buffer.array();

        try {
            PublicKey publicKey = getPublicKeyFromBytes(keyArray);

            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initVerify(publicKey);
            ecdsaSign.update(concatBytes);
            return ecdsaSign.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return false;
    }

    private PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }

}
