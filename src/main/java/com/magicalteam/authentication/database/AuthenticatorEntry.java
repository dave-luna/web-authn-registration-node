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
package com.magicalteam.authentication.database;

import com.magicalteam.authentication.data.Key;

/**
 * Represents and association between a credential ID and a public key.
 */
public class AuthenticatorEntry {
    public String credentialId;
    public Key key;

    /**
     * Creates a CredentialKeyObject.
     * @param credentialId the credential ID.
     * @param key the public key.
     */
    public AuthenticatorEntry(String credentialId, Key key) {
        this.credentialId = credentialId;
        this.key = key;
    }

    /**
     * Default constructor, required by object mapper for serialization.
     */
    public AuthenticatorEntry() {
    }
}
