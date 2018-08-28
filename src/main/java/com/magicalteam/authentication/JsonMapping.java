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

import java.io.IOException;

import org.forgerock.openam.utils.JsonValueBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.magicalteam.authentication.database.WebAuthData;

/**
 * Utility class for converting Devices Object to JSON and back.
 */
public class JsonMapping {

    private static final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Serialize a Devices Object as a String.
     * @param devices the devices.
     * @return the devices as a String.
     */
    static String asString(WebAuthData devices) {
        try {
            return JsonValueBuilder.getObjectMapper().writeValueAsString(devices);
        } catch (JsonProcessingException e) {
            logger.error("failed to serialize the Devices object as a String.");
            return null;
        }
    }

    /**
     * Deserialize a Devices Object from a JSON String.
     * @param keyString the devices as a String.
     * @return the devices object.
     */
    public static WebAuthData fromString(String keyString) {
        try {
            return JsonValueBuilder.getObjectMapper().readValue(keyString, WebAuthData.class);
        } catch (IOException e) {
            logger.error("failed to deserialize the Devices object from a String.");
            return null;
        }
    }
}
