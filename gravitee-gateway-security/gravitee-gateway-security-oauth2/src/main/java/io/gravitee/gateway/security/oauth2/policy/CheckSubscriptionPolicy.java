/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.gateway.security.oauth2.policy;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.policy.AbstractPolicy;
import io.gravitee.gateway.policy.PolicyException;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.SubscriptionRepository;
import io.gravitee.repository.management.model.Subscription;

import java.util.Date;
import java.util.Iterator;
import java.util.Set;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class CheckSubscriptionPolicy extends AbstractPolicy {

    static final String CONTEXT_ATTRIBUTE_CLIENT_ID = "oauth.client_id";

    private final static String OAUTH2_ERROR_ACCESS_DENIED = "access_denied";
    private final static String OAUTH2_ERROR_SERVER_ERROR = "server_error";

    @Override
    protected void onRequest(Request request, Response response, PolicyChain policyChain, ExecutionContext executionContext) throws PolicyException {
        SubscriptionRepository subscriptionRepository = executionContext.getComponent(SubscriptionRepository.class);

        // Get plan and client_id from execution context
        String plan = (String) executionContext.getAttribute(ExecutionContext.ATTR_PLAN);
        String clientId = (String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_CLIENT_ID);
        try {
            Set<Subscription> subscriptions = subscriptionRepository.findByPlanAndClientId(plan, clientId);

            // There are many subscriptions but only one may be active
            Iterator<Subscription> ite = subscriptions.iterator();
            if (ite.hasNext()) {
                Subscription current = ite.next();

                if (current.getClientId().equals(clientId) &&
                        (current.getEndingAt() == null ||
                        current.getEndingAt().after(Date.from(request.timestamp())))) {
                    policyChain.doNext(request, response);
                } else {
                    // As per https://tools.ietf.org/html/rfc6749#section-4.1.2.1
                    sendUnauthorized(policyChain, OAUTH2_ERROR_ACCESS_DENIED);
                }
            } else {
                // As per https://tools.ietf.org/html/rfc6749#section-4.1.2.1
                sendUnauthorized(policyChain, OAUTH2_ERROR_ACCESS_DENIED);
            }
        } catch (TechnicalException te) {
            // As per https://tools.ietf.org/html/rfc6749#section-4.1.2.1
            sendUnauthorized(policyChain, OAUTH2_ERROR_SERVER_ERROR);
        }
    }

    private void sendUnauthorized(PolicyChain policyChain, String description) {
        policyChain.failWith(PolicyResult.failure(
                HttpStatusCode.UNAUTHORIZED_401, description));
    }
}
