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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Optional;
import java.util.ResourceBundle;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = WebAuthnAuthenticationNode.Config.class)
public class WebAuthnAuthenticationNode extends AbstractDecisionNode {

    private static final String OUTCOME = "webAuthNOutcome";
    private static final String BUNDLE = WebAuthnAuthenticationNode.class.getName().replace(".", "/");
    private static final String WAN_CHALLENGE = "wan-challenge";
    private static final String CREDENTIAL_ID = "credential-id";
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;

    private ChallengeGenerator challengeGenerator;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default boolean isUserVerificationRequired() {
            return false;
        }
    }

    @Inject
    public WebAuthnAuthenticationNode(@Assisted Config config, ChallengeGenerator challengeGenerator) {
        this.config = config;
        this.challengeGenerator = challengeGenerator;
    }

    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;

        byte[] challengeBytes;
        if(context.sharedState.get(WAN_CHALLENGE).isNull()) {
            challengeBytes = challengeGenerator.getNewChallenge();
            String base64String = Base64.encodeBase64String(challengeBytes);
            sharedState = sharedState.copy().put(WAN_CHALLENGE, base64String);
        } else {
            String base64String = context.sharedState.get(WAN_CHALLENGE).asString();
            challengeBytes = Base64.decodeBase64(base64String);
        }

        String credentialId = context.sharedState.get(CREDENTIAL_ID).asString();

        String webAuthnRegistrationScript = getScriptAsString("client-auth-script.js");
        webAuthnRegistrationScript = String.format(webAuthnRegistrationScript, Arrays.toString(challengeBytes), Arrays.toString(getBytesFromNumbers(credentialId)));

        ResourceBundle bundle = context.request.locales
                .getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

        String spinnerScript = getScriptAsString("spinner.js");
        spinnerScript = String.format(spinnerScript, bundle.getString("waiting"));

        Optional<String> result = context.getCallback(HiddenValueCallback.class)
                .map(HiddenValueCallback::getValue)
                .filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));

        if (result.isPresent()) {
            return goTo(result.get().equals("true")).build();
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
