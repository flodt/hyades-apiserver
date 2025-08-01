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

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.junit.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class ProtoUtilTest {
    @Test
    public void testConvertTimestampToDate() throws ParseException {
        final String TIMESTAMP = "2025-06-19T00:00:00Z";
        Timestamp timestamp = Timestamps.parse(TIMESTAMP);

        Date expected = Date.from(Instant.parse(TIMESTAMP));
        assertThat(ProtoUtil.convertToDate(timestamp)).isEqualTo(expected);
    }
}
