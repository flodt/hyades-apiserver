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

package org.dependencytrack.policy.cel;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.mapping.ComponentProjection;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

public class CelPolicyQueryManagerTest extends PersistenceCapableTest {
    private CelPolicyQueryManager celQm;

    @Before
    public void setUp() {
        this.celQm = new CelPolicyQueryManager(this.qm);
    }


    @Test
    public void testFetchesComponentProjection() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
        component = qm.createComponent(component, false);

        HealthMetaComponent healthMeta = new HealthMetaComponent();
        healthMeta.setPurl(component.getPurl().toString());
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStars(39);
        healthMeta.setForks(12);
        qm.createHealthMetaComponent(healthMeta);

        Collection<String> protoFieldNames = List.of("name", "purl", "health_meta.scorecardScore", "health_meta.stars", "health_meta.forks");

        List<ComponentProjection> componentProjections = celQm.fetchAllComponents(project.getId(), protoFieldNames);

        assertThat(componentProjections).hasSize(1);
        assertThat(componentProjections).extracting(cp -> cp.healthMeta).doesNotContainNull();

        assertThat(componentProjections)
                .extracting(
                        cp -> cp.name,
                        cp -> cp.purl,
                        cp -> cp.healthMeta.scorecardScore,
                        cp -> cp.healthMeta.stars,
                        cp -> cp.healthMeta.forks
                )
                .containsExactly(
                        tuple(
                                "ABC",
                                "pkg:maven/org.http4s/blaze-core_2.12",
                                10.0f,
                                39,
                                12
                        )
                );
    }
}