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
package io.gravitee.gateway.security.keyless;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.policy.Policy;
import io.gravitee.gateway.policy.PolicyManager;
import io.gravitee.gateway.policy.StreamType;
import io.gravitee.gateway.security.keyless.policy.DummyKeylessPolicy;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class KeylessSecurityProviderTest {

    @Mock
    private PolicyManager policyManager;

    @InjectMocks
    private KeylessSecurityProvider securityProvider = new KeylessSecurityProvider();

    @Test
    public void shouldHandleRequest() {
        Request request = mock(Request.class);
        when(request.headers()).thenReturn(new HttpHeaders());

        boolean handle = securityProvider.canHandle(request);
        Assert.assertTrue(handle);
    }

    @Test
    public void shouldReturnPolicies() {
        ExecutionContext executionContext = mock(ExecutionContext.class);

        DummyKeylessPolicy keylessPolicy = mock(DummyKeylessPolicy.class);
        when(policyManager.create(StreamType.ON_REQUEST, KeylessSecurityProvider.KEYLESS_POLICY, null))
                .thenReturn(keylessPolicy);

        List<Policy> keylessProviderPolicies = securityProvider.policies(executionContext);

        Assert.assertEquals(1, keylessProviderPolicies.size());

        Policy policy = keylessProviderPolicies.iterator().next();
        Assert.assertThat(policy, IsInstanceOf.instanceOf(DummyKeylessPolicy.class));
        Assert.assertEquals(keylessPolicy, policy);
    }

    @Test
    public void shouldReturnName() {
        Assert.assertEquals("key_less", securityProvider.name());
    }

    @Test
    public void shouldReturnOrder() {
        Assert.assertEquals(1000, securityProvider.order());
    }
}
