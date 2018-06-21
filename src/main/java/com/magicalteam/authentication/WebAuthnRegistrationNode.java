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
import static org.forgerock.openam.scripting.ScriptConstants.AUTHENTICATION_CLIENT_SIDE_NAME;

import java.util.Optional;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.guava.common.base.Strings;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.scripting.Script;
import org.forgerock.openam.scripting.service.ScriptConfiguration;
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

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * Sets the Node to Lock or Unlock accounts.
         * @return the intended lock status.
         */
        @Attribute(order = 100)
        @Script(AUTHENTICATION_CLIENT_SIDE_NAME)
        ScriptConfiguration script();

        @Attribute(order = 200)
        String scriptResult();
    }

    @Inject
    public WebAuthnRegistrationNode(@Assisted Config config) {
        this.config = config;
    }

    public Action process(TreeContext context) {
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
            ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(config.script().getScript());
            HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(config.scriptResult());
            ImmutableList<Callback> callbacks = ImmutableList.of(scriptAndSelfSubmitCallback, hiddenValueCallback);
            return send(callbacks).build();
        }
    }
}