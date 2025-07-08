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

package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.junit.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class HealthMetaQueryManagerTest extends PersistenceCapableTest {
    @Test
    public void testGetHealthMetaComponent() {
        final String PURL = "pkg:maven/acme/example@1.0.0";

        HealthMetaComponent healthMeta = new HealthMetaComponent();
        healthMeta.setPurl(PURL);
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setStars(42);

        HealthMetaComponent nonExistentResult = qm.getHealthMetaComponent(PURL);
        assertThat(nonExistentResult).isNull();

        qm.persist(healthMeta);

        HealthMetaComponent existingResult = qm.getHealthMetaComponent(PURL);
        assertThat(existingResult)
                .usingRecursiveComparison()
                .ignoringFields("lastFetch")
                .isEqualTo(healthMeta);
    }

    @Test
    public void testCreateHealthMetaComponent() {
        final String PURL = "pkg:maven/acme/example@1.0.0";

        HealthMetaComponent healthMeta = new HealthMetaComponent();
        healthMeta.setPurl(PURL);
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setStars(42);

        HealthMetaComponent nonExistentResult = qm.getHealthMetaComponent(PURL);
        assertThat(nonExistentResult).isNull();

        qm.createHealthMetaComponent(healthMeta);

        HealthMetaComponent existingResult = qm.getHealthMetaComponent(PURL);
        assertThat(existingResult)
                .usingRecursiveComparison()
                .ignoringFields("lastFetch")
                .isEqualTo(healthMeta);
    }

    @Test
    public void testUpdateHealthMetaComponent() {
        final String PURL = "pkg:maven/acme/example@1.0.0";

        HealthMetaComponent oldHealthMeta = new HealthMetaComponent();
        oldHealthMeta.setPurl(PURL);
        oldHealthMeta.setStatus(FetchStatus.PROCESSED);
        oldHealthMeta.setStars(42);
        qm.createHealthMetaComponent(oldHealthMeta);

        HealthMetaComponent updatedHealthMeta = new HealthMetaComponent();
        updatedHealthMeta.setPurl(PURL);
        updatedHealthMeta.setStatus(FetchStatus.PROCESSED);
        updatedHealthMeta.setStars(50);

        Instant before = Instant.now();
        qm.updateHealthMetaComponent(updatedHealthMeta);

        HealthMetaComponent result = qm.getHealthMetaComponent(PURL);

        assertThat(result.getStars()).isEqualTo(50);
        assertThat(result.getStatus()).isEqualTo(FetchStatus.PROCESSED);
        assertThat(result.getPurl()).isEqualTo(PURL);

        assertThat(result.getLastFetch())
                .isNotNull()
                .satisfies(d -> assertThat(d.toInstant()).isAfter(before));
    }
}