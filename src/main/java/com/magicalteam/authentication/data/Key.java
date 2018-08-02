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
package com.magicalteam.authentication.data;

import org.forgerock.openam.utils.JsonValueBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Represents https://www.w3.org/TR/webauthn/#credential-public-key
 */
public class Key {
    public int keyType;
    public int alg;
    public int curve;
    public byte[] xpos;
    public byte[] ypos;

    @Override
    public String toString() {
        try {
            return JsonValueBuilder.getObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return null;
    }
}
