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

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.forgerock.guava.common.base.Strings;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.CrestQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.magicalteam.authentication.data.AttestationObject;
import com.magicalteam.authentication.data.AttestedCredentialData;
import com.magicalteam.authentication.database.AuthenticatorEntry;
import com.magicalteam.authentication.database.DatabaseAccess;
import com.magicalteam.authentication.database.WebAuthData;
import com.magicalteam.authentication.flows.RegisterFlow;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = WebAuthnRegistrationNode.Config.class)
public class WebAuthnRegistrationNode extends AbstractDecisionNode {

    private static final String OUTCOME = "webAuthNOutcome";
    private static final String BUNDLE = WebAuthnRegistrationNode.class.getName().replace(".", "/");
    private static final String CHALLENGE = "web-reg-challenge";
    private static final String ANON_AUTHENTICATOR_ID = "anon";
    public static final String VALUE_SPLITTER = "SPLITTER";
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;

    private RegisterFlow registerFlow;
    private ChallengeGenerator challengeGenerator;
    private DatabaseAccess databaseAccess;

    private final CoreWrapper coreWrapper;

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 10)
        default String registeredDomains() {
            return "am.example.com";
        }

        @Attribute(order = 20)
        default String keyStorageAttribute() {
            return "pushDeviceProfiles";
        }

        @Attribute(order = 100)
        default boolean isUserVerificationRequired() {
            return false;
        }

        @Attribute(order = 200)
        default AttestationPreference attestationPreference() {
            return AttestationPreference.NONE;
        }

    }

    @Inject
    public WebAuthnRegistrationNode(@Assisted Config config, ChallengeGenerator challengeGenerator, RegisterFlow registerFlow,
                                    CoreWrapper coreWrapper) {
        this.config = config;
        this.challengeGenerator = challengeGenerator;
        this.registerFlow = registerFlow;
        this.coreWrapper = coreWrapper;
        this.databaseAccess = new DatabaseAccess(config.keyStorageAttribute());
    }

    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;


        byte[] challengeBytes;
        if(context.sharedState.get(CHALLENGE).isNull()) {
            challengeBytes = challengeGenerator.getNewChallenge();
            String base64String = Base64.encodeBase64String(challengeBytes);
            sharedState = sharedState.copy().put(CHALLENGE, base64String);
        } else {
            String base64String = context.sharedState.get(CHALLENGE).asString();
            challengeBytes = Base64.decodeBase64(base64String);
        }

        String rpId = config.registeredDomains();
        String webAuthnRegistrationScript = getScriptAsString("client-script.js");
        webAuthnRegistrationScript = String.format(webAuthnRegistrationScript, Arrays.toString(challengeBytes), rpId,
                config.attestationPreference().getValue());

        ResourceBundle bundle = context.request.locales
                .getBundleInPreferredLocale(BUNDLE, WebAuthnRegistrationNode.OutcomeProvider.class.getClassLoader());

        String spinnerScript = getScriptAsString("spinner.js");
        spinnerScript = String.format(spinnerScript, bundle.getString("waiting"));

        Optional<String> result = context.getCallback(HiddenValueCallback.class)
                .map(HiddenValueCallback::getValue)
                .filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));

        if (result.isPresent()) {
            String results = result.get();
            String[] resultsArray = results.split(VALUE_SPLITTER);
            byte[] attestationData = getBytesFromNumbers(resultsArray[1]);
            AttestationObject attestationObject = registerFlow.accept(resultsArray[0], attestationData, challengeBytes, rpId,
                    config.isUserVerificationRequired());

            try {
                AMIdentity user = getIdentity(context.sharedState.get(USERNAME).asString(),
                        context.sharedState.get(REALM).asString());
                WebAuthData webAuthData = databaseAccess.getWebAuthData(user);
                addAuthenticatorEntry(webAuthData, attestationObject, resultsArray[2]);
                Map<String, Set<String>> attrs = new HashMap<>();
                attrs.put(config.keyStorageAttribute(), Collections.singleton(JsonMapping.asString(webAuthData)));
                user.setAttributes(attrs);
                user.store();
            } catch (IdRepoException | SSOException e) {
                return goTo(false).build();
            }
            return goTo(true).build();
        } else {
            ScriptTextOutputCallback webAuthNRegistrationCallback = new ScriptTextOutputCallback(webAuthnRegistrationScript);
            ScriptTextOutputCallback spinnerCallback = new ScriptTextOutputCallback(spinnerScript);
            HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(OUTCOME, "false");
            ImmutableList<Callback> callbacks = ImmutableList.of(webAuthNRegistrationCallback, spinnerCallback,
                    hiddenValueCallback);
            return send(callbacks)
                    .replaceSharedState(sharedState)
                    .build();
        }
    }

    private void addAuthenticatorEntry(WebAuthData webAuthData, AttestationObject attestationObject, String credentialId) {
        AttestedCredentialData acd = attestationObject.authData.attestedCredentialData;
        AuthenticatorEntry authenticatorEntry = new AuthenticatorEntry(credentialId, acd.publicKey);
        String authenticatorId = ANON_AUTHENTICATOR_ID;
        if (attestationObject.attestationStatement.attestnCerts.size() > 0) {
            authenticatorId = attestationObject.attestationStatement.attestnCerts.get(0).getSubjectDN().toString();
        }
        webAuthData.getAuthenticators().put(authenticatorId, authenticatorEntry);
    }

    private AMIdentity getIdentity(String username, String realm) throws IdRepoException, SSOException {
        AMIdentityRepository idrepo = coreWrapper.getAMIdentityRepository(
                coreWrapper.convertRealmDnToRealmPath(realm));
        IdSearchControl idSearchControl = new IdSearchControl();
        idSearchControl.setAllReturnAttributes(true);

        IdSearchResults idSearchResults = idrepo.searchIdentities(IdType.USER,
                new CrestQuery(username), idSearchControl);
        return idSearchResults.getSearchResults().iterator().next();
    }

    private byte[] getBytesFromNumbers(String data) {
        byte[] results = new byte[data.length()];
        int size = 0;
        String[] numbersAsStrings = data.split(",");
        for (String numberAsString : numbersAsStrings) {
            int unsignedNumber = Integer.parseInt(numberAsString);
            results[size] = (byte)(unsignedNumber);
            size++;
        }
        return Arrays.copyOf(results, size);
    }

    // Reads a file stored under resources as a string
    private String getScriptAsString(String scriptFileName) throws NodeProcessException {
        InputStream resourceStream = getClass().getClassLoader().getResourceAsStream(scriptFileName);

        String script;
        try {
            script = IOUtils.toString(resourceStream, "UTF-8");
        } catch (IOException e) {
            logger.error("Failed to get the script, fatal error!", e);
            throw new NodeProcessException(e);
        }
        return script;
    }
}
