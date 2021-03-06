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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Represents https://www.w3.org/TR/webauthn/#attestation-statement
 * Specifically the FIDO u2f format https://www.w3.org/TR/webauthn/#fido-u2f-attestation
 */
public class FidoAttestationStatement {
    // TODO the certs should be an array !
    public List<X509Certificate> attestnCerts;
    public byte[] caCert;
    public byte[] sig;
}
