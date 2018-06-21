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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.apache.commons.io.IOUtils;
import org.forgerock.guava.common.base.Strings;
import org.forgerock.guava.common.collect.ImmutableList;
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
        configClass = WebAuthnRegistrationNode.Config.class)
public class WebAuthnRegistrationNode extends AbstractDecisionNode {

    private static final String OUTCOME = "webAuthNOutcome";
    private static final String BUNDLE = WebAuthnRegistrationNode.class.getName().replace(".", "/");
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;

    private static final int[] positiveBytes = new int[32];

    /**
     * Configuration for the node.
     */
    public interface Config {


    }

    @Inject
    public WebAuthnRegistrationNode(@Assisted Config config) {
        this.config = config;

        final byte[] challengeBytes = new byte[32];

        try {
            SecureRandom.getInstanceStrong().nextBytes(challengeBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        for (int i = 0; i < challengeBytes.length; i++) {
            positiveBytes[i] = challengeBytes[i] & 0xff;
        }

    }

    public Action process(TreeContext context) throws NodeProcessException {

        String webAuthnRegistrationScript = getScriptAsString("client-script.js");
        webAuthnRegistrationScript = String.format(webAuthnRegistrationScript, Arrays.toString(positiveBytes));

        ResourceBundle bundle = context.request.locales
                .getBundleInPreferredLocale(BUNDLE, WebAuthnRegistrationNode.OutcomeProvider.class.getClassLoader());

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
            return send(callbacks).build();
        }
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
