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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.inject.Singleton;

/**
 * Extracted so it can be a singleton, injected by guice. This is because SecureRandom is heavy, taking resources and
 * time to get initialized.
 */
@Singleton
public class ChallengeGenerator {

    private SecureRandom secureRandom;

    public ChallengeGenerator() {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate a new challenge.
     * @return a new challenge of 32 bytes.
     */
    byte[] getNewChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return challenge;
    }
}
