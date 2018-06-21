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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.forgerock.guava.common.base.Strings;
import org.forgerock.guava.common.collect.ImmutableList;
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
        configClass = WebAuthnRegistrationNode.Config.class)
public class WebAuthnRegistrationNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;

    private static final int[] positiveBytes = new int[32];

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 200)
        String scriptResult();
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

        String script = getScriptAsString("client-script.js");

        script = String.format(script, Arrays.toString(positiveBytes));

        Optional<String> result = context.getCallback(HiddenValueCallback.class)
                .map(HiddenValueCallback::getValue)
                .filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
        if (result.isPresent()) {
            if (result.get().equals("true")) {
                return goTo(true).build();
            } else {
                return goTo(false).build();
            }
        } else {
            ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(script);
          //  HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(config.scriptResult());
            ImmutableList<Callback> callbacks = ImmutableList.of(scriptAndSelfSubmitCallback);
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
