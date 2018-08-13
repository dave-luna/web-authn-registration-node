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

import java.util.Set;

import com.iplanet.sso.SSOException;
import com.magicalteam.authentication.JsonMapping;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

/**
 * Will eventually become a DAO.
 */
public class DatabaseAccess {

    private String keyStorageAttribute;

    public DatabaseAccess(String keyStorageAttribute) {
        this.keyStorageAttribute = keyStorageAttribute;
    }

    /**
     * Get the web auth data from the user's profile.
     * @param user the user.
     * @return the web auth data.
     * @throws IdRepoException if the attribute doesn't exist.
     * @throws SSOException if the attribute doesn't exist.
     */
    public WebAuthData getWebAuthData(AMIdentity user) throws IdRepoException, SSOException {
        Set<String> attr = user.getAttribute(keyStorageAttribute);
        WebAuthData webAuthData = null;
        if (attr.size() > 0) {
            webAuthData = JsonMapping.fromString(attr.iterator().next());
        }
        if (webAuthData == null) {
            webAuthData = new WebAuthData();
        }
        return webAuthData;
    }
}
