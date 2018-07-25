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

/**
 * Represents https://www.w3.org/TR/webauthn/#attested-credential-data
 */
public class AttestedCredentialData {

    /** AAGUID of the authenticator **/
    public byte[] aaguid;

    /** byte length of credentialId **/
    public int credentialIdLength;

    /** https://www.w3.org/TR/webauthn/#credential-id **/
    public byte[] credentialId;

    /** https://www.w3.org/TR/webauthn/#credential-public-key **/
    public Key publicKey;
}
