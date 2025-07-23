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
import org.dependencytrack.policy.cel.mapping.HealthMetaProjection;
import org.junit.Before;
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
        qm.createComponent(component, false);

        Collection<String> protoFieldNames = List.of("name", "purl");

        List<ComponentProjection> componentProjections = celQm.fetchAllComponents(project.getId(), protoFieldNames);

        assertThat(componentProjections).hasSize(1);

        assertThat(componentProjections)
                .extracting(
                        cp -> cp.name,
                        cp -> cp.purl
                )
                .containsExactly(
                        tuple(
                                "ABC",
                                "pkg:maven/org.http4s/blaze-core_2.12"
                        )
                );
    }

    @Test
    public void testFetchesHealthProjection() {
        final String TEST_SCORECARD_CHECKS_JSON = "[{\"name\":\"Packaging\",\"description\":\"This check tries to determine if the project is published as a package.\",\"score\":5,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#packaging\"},{\"name\":\"Token-Permissions\",\"description\":\"This check determines whether the project's automated workflows tokens follow the principle of least privilege.\",\"score\":3,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions\"},{\"name\":\"Code-Review\",\"description\":\"This check determines whether the project requires human code review before pull requests (merge requests) are merged.\",\"score\":8,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#code-review\"},{\"name\":\"Pinned-Dependencies\",\"description\":\"This check tries to determine if the project pins dependencies used during its build and release process.\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies\"},{\"name\":\"Binary-Artifacts\",\"description\":\"This check determines whether the project has generated executable (binary) artifacts in the source repository.\",\"score\":10,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#binary-artifacts\"},{\"name\":\"Dangerous-Workflow\",\"description\":\"This check determines whether the project's GitHub Action workflows has dangerous code patterns.\",\"score\":2,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow\"},{\"name\":\"Maintained\",\"description\":\"Determines if the project is \\\"actively maintained\\\".\",\"score\":7,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained\"},{\"name\":\"CII-Best-Practices\",\"description\":\"This check determines whether the project has earned an OpenSSF (formerly CII) Best Practices Badge.\",\"score\":4,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#cii-best-practices\"},{\"name\":\"Security-Policy\",\"description\":\"This check tries to determine if the project has published a security policy.\",\"score\":9,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#security-policy\"},{\"name\":\"Fuzzing\",\"description\":\"This check tries to determine if the project uses fuzzing tools, e.g. OSS-Fuzz.\",\"score\":1,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing\"},{\"name\":\"License\",\"description\":\"This check determines whether the project has defined a license.\",\"score\":10,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#license\"},{\"name\":\"Signed-Releases\",\"description\":\"This check tries to determine if the project cryptographically signs release artifacts.\",\"score\":0,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#signed-releases\"},{\"name\":\"Branch-Protection\",\"description\":\"This check determines whether a project's default and release branches are protected with GitHub's branch protection or repository rules settings.\",\"score\":5,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection\"},{\"name\":\"SAST\",\"description\":\"This check tries to determine if the project uses Static Application Security Testing (SAST).\",\"score\":7,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#sast\"},{\"name\":\"Vulnerabilities\",\"description\":\"This check determines whether the project has open, unfixed vulnerabilities in its own codebase or dependencies using the OSV service.\",\"score\":3,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#vulnerabilities\"},{\"name\":\"CI-Tests\",\"description\":\"This check tries to determine if the project runs tests before pull requests are merged.\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#ci-tests\"},{\"name\":\"Contributors\",\"description\":\"This check tries to determine if the project has recent contributors from multiple organizations (e.g., companies).\",\"score\":8,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#contributors\"},{\"name\":\"Dependency-Update-Tool\",\"description\":\"This check tries to determine if the project uses a dependency update tool, specifically one of: Dependabot, Renovate bot, PyUp.\",\"score\":2,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#dependency-update-tool\"},{\"name\":\"Webhooks\",\"description\":\"This check determines whether the webhook defined in the repository has a token configured to authenticate the origins of requests.\",\"score\":4,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#webhooks\"}]";

        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
        qm.createComponent(component, false);

        HealthMetaComponent healthMetaComponent = new HealthMetaComponent();
        healthMetaComponent.setPurlCoordinates("pkg:maven/org.http4s/blaze-core_2.12");
        healthMetaComponent.setStatus(FetchStatus.PROCESSED);
        healthMetaComponent.setStars(42);
        healthMetaComponent.setScorecardScore(10.0f);
        healthMetaComponent.setScorecardChecksJson(TEST_SCORECARD_CHECKS_JSON);
        healthMetaComponent.setForks(10);
        qm.createHealthMetaComponent(healthMetaComponent);

        // Here we also test that the special case scoreCardChecks is handled correctly - it needs to fetch
        //   the scoreCardChecksJson field when the variable scoreCardChecks is in use.
        Collection<String> protoFieldNames = List.of("scoreCardScore", "stars", "forks", "scoreCardChecks");

        List<HealthMetaProjection> healthMetaProjections = celQm.fetchAllComponentHealthMeta(List.of("pkg:maven/org.http4s/blaze-core_2.12"), protoFieldNames);

        assertThat(healthMetaProjections).hasSize(1);

        assertThat(healthMetaProjections)
                .extracting(
                        hp -> hp.purlCoordinates,
                        hp -> hp.stars,
                        hp -> hp.scorecardScore,
                        hp -> hp.forks,
                        hp -> hp.scoreCardChecksJson
                )
                .containsExactly(
                        tuple(
                                "pkg:maven/org.http4s/blaze-core_2.12",
                                42,
                                10.0f,
                                10,
                                TEST_SCORECARD_CHECKS_JSON
                        )
                );
    }
}