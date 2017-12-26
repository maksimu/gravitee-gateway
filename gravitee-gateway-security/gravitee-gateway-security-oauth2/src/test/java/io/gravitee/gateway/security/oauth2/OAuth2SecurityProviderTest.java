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
package io.gravitee.gateway.security.oauth2;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.policy.Policy;
import io.gravitee.gateway.policy.PolicyManager;
import io.gravitee.gateway.policy.StreamType;
import io.gravitee.gateway.security.oauth2.policy.CheckSubscriptionPolicy;
import io.gravitee.gateway.security.oauth2.policy.DummyOAuth2Policy;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Iterator;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2SecurityProviderTest {

    @Mock
    private PolicyManager policyManager;

    @InjectMocks
    private OAuth2SecurityProvider securityProvider = new OAuth2SecurityProvider();

    @Test
    public void shouldNotHandleRequest_noAuthorizationHeader() {
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(new HttpHeaders());

        boolean handle = securityProvider.canHandle(request);
        Assert.assertFalse(handle);
    }

    @Test
    public void shouldNotHandleRequest_invalidAuthorizationHeader() {
        HttpHeaders headers = new HttpHeaders();
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(headers);

        headers.add(HttpHeaders.AUTHORIZATION, "");

        boolean handle = securityProvider.canHandle(request);
        Assert.assertFalse(handle);
    }

    @Test
    public void shouldNotHandleRequest_noBearerAuthorizationHeader() {
        HttpHeaders headers = new HttpHeaders();
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(headers);

        headers.add(HttpHeaders.AUTHORIZATION, "Basic xxx-xx-xxx-xx-xx");

        boolean handle = securityProvider.canHandle(request);
        Assert.assertFalse(handle);
    }

    @Test
    public void shouldHandleRequest_validAuthorizationHeader() {
        HttpHeaders headers = new HttpHeaders();
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(headers);

        headers.add(HttpHeaders.AUTHORIZATION, OAuth2SecurityProvider.BEARER_AUTHORIZATION_TYPE + " xxx-xx-xxx-xx-xx");

        boolean handle = securityProvider.canHandle(request);
        Assert.assertTrue(handle);
    }

    @Test
    public void shouldHandleRequest_ignoreCaseAuthorizationHeader() {
        HttpHeaders headers = new HttpHeaders();
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(headers);

        headers.add(HttpHeaders.AUTHORIZATION, "BeaRer xxx-xx-xxx-xx-xx");

        boolean handle = securityProvider.canHandle(request);
        Assert.assertTrue(handle);
    }

    @Test
    public void shouldNotHandleRequest_noBearerValue() {
        HttpHeaders headers = new HttpHeaders();
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(headers);

        headers.add(HttpHeaders.AUTHORIZATION, OAuth2SecurityProvider.BEARER_AUTHORIZATION_TYPE + " ");

        boolean handle = securityProvider.canHandle(request);
        Assert.assertFalse(handle);
    }

    @Test
    public void shouldReturnPolicies() {
        ExecutionContext executionContext = mock(ExecutionContext.class);

        DummyOAuth2Policy oauth2Policy = mock(DummyOAuth2Policy.class);
        when(policyManager.create(StreamType.ON_REQUEST, OAuth2SecurityProvider.OAUTH2_POLICY, null))
                .thenReturn(oauth2Policy);

        List<Policy> oauth2ProviderPolicies = securityProvider.policies(executionContext);

        Assert.assertEquals(2, oauth2ProviderPolicies.size());

        Iterator<Policy> policies = oauth2ProviderPolicies.iterator();
        Assert.assertThat(policies.next(), IsInstanceOf.instanceOf(DummyOAuth2Policy.class));
        Assert.assertThat(policies.next(), IsInstanceOf.instanceOf(CheckSubscriptionPolicy.class));
    }

    @Test
    public void shouldReturnName() {
        Assert.assertEquals(OAuth2SecurityProvider.SECURITY_PROVIDER_OAUTH2, securityProvider.name());
    }

    @Test
    public void shouldReturnOrder() {
        Assert.assertEquals(0, securityProvider.order());
    }
}
