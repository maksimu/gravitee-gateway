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
package io.gravitee.gateway.security.core;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.policy.Policy;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class SecurityProviderTest {

    @Test
    public void shouldReturnNullConfiguration() {
        SecurityProvider provider = new SecurityProvider() {
            @Override
            public String name() {
                return null;
            }

            @Override
            public int order() {
                return 0;
            }

            @Override
            public boolean canHandle(Request request) {
                return false;
            }

            @Override
            public List<Policy> policies(ExecutionContext executionContext) {
                return null;
            }
        };

        Assert.assertNull(provider.configuration());
    }
}
