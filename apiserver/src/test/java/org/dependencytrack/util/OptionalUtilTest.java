/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */

package org.dependencytrack.util;

import org.junit.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class OptionalUtilTest {
    @Test
    public void testOptionalIfNotPresent() {
        Optional<Object> optional = OptionalUtil.optionalIf(false, new Object());
        assertThat(optional).isEmpty();
    }

    @Test
    public void testOptionalIfPresent() {
        Object content = new Object();
        Optional<Object> optional = OptionalUtil.optionalIf(true, content);
        assertThat(optional).isPresent();
        assertThat(optional).contains(content);
    }
}