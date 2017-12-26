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
package io.gravitee.gateway.security.apikey;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.policy.Policy;
import io.gravitee.gateway.policy.PolicyManager;
import io.gravitee.gateway.policy.StreamType;
import io.gravitee.gateway.security.apikey.policy.DummyApiKeyPolicy;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class ApiKeySecurityProviderTest {

    @InjectMocks
    private ApiKeySecurityProvider securityProvider = new ApiKeySecurityProvider();

    @Mock
    private PolicyManager policyManager;

    @Test
    public void shouldNotHandleRequest() {
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(new HttpHeaders());

        MultiValueMap<String, String> parameters = mock(MultiValueMap.class);
        when(request.parameters()).thenReturn(parameters);

        boolean handle = securityProvider.canHandle(request);
        Assert.assertFalse(handle);
    }

    @Test
    public void shouldHandleRequestUsingHeaders() {
        Request request = mock(Request.class);
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Gravitee-Api-Key", "xxxxx-xxxx-xxxxx");
        when(request.headers()).thenReturn(headers);

        boolean handle = securityProvider.canHandle(request);
        Assert.assertTrue(handle);
    }

    @Test
    public void shouldHandleRequestUsingQueryParameters() {
        Request request = mock(Request.class);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.put("api-key", Collections.singletonList("xxxxx-xxxx-xxxxx"));
        when(request.parameters()).thenReturn(parameters);

        HttpHeaders headers = new HttpHeaders();
        when(request.headers()).thenReturn(headers);

        boolean handle = securityProvider.canHandle(request);
        Assert.assertTrue(handle);
    }

    @Test
    public void shouldReturnPolicies() {
        ExecutionContext executionContext = mock(ExecutionContext.class);

        DummyApiKeyPolicy apiKeyPolicy = mock(DummyApiKeyPolicy.class);
        when(policyManager.create(StreamType.ON_REQUEST, ApiKeySecurityProvider.API_KEY_POLICY, ApiKeySecurityProvider.API_KEY_POLICY_CONFIGURATION))
                .thenReturn(apiKeyPolicy);

        List<Policy> apikeyProviderPolicies = securityProvider.policies(executionContext);

        Assert.assertEquals(1, apikeyProviderPolicies.size());

        Policy policy = apikeyProviderPolicies.iterator().next();
        Assert.assertThat(policy, IsInstanceOf.instanceOf(DummyApiKeyPolicy.class));
        Assert.assertEquals(apiKeyPolicy, policy);
    }

    @Test
    public void shouldReturnName() {
        Assert.assertEquals("api_key", securityProvider.name());
    }

    @Test
    public void shouldReturnOrder() {
        Assert.assertEquals(500, securityProvider.order());
    }
}
