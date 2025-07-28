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
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CelPolicyEnginePoliciesTest extends PersistenceCapableTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables()
            .set("FILE_STORAGE_EXTENSION_MEMORY_ENABLED", "true")
            .set("FILE_STORAGE_DEFAULT_EXTENSION", "memory");

    @Before
    public void before() throws Exception {
        super.before();

        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
    }

    @Test
    public void testPoliciesMWEWithHealth() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib" && health.scoreCardScore < 5.0
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setGroup("projectGroup");
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setClassifier(Classifier.APPLICATION);
        project.setInactiveSince(new Date(777));
        project.setCpe("projectCpe");
        project.setPurl("projectPurl");
        project.setSwidTagId("projectSwidTagId");
        project.setLastBomImport(new Date());
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardScore(4.0f);
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testDurationComputationHits() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - health.lastCommitDate) > duration('720h')
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setLastCommit(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testMixedScorecardAgeCompareSkipsWithNoScorecard() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (health.scoreCardChecks.maintained <= 5.0 || component.compare_age(">=", "P180D")) && vulns.exists(vuln, vuln.severity in ["CRITICAL", "HIGH"])
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(new java.util.Date(666));
        vuln.setPublished(new java.util.Date(777));
        vuln.setUpdated(new java.util.Date(888));
        vuln.setSeverity(Severity.CRITICAL);
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(6.0));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(6.4));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(6.8));
        vuln.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(9.1));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(5.3));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(3.1));
        vuln.setCvssV3Vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.5));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.0));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.75));
        vuln.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testMixedScorecardAgeCompareNoViolationWithNonMatchingScorecardAndRecentComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (health.scoreCardChecks.maintained <= 5.0 || component.compare_age(">=", "P180D")) && vulns.exists(vuln, vuln.severity in ["CRITICAL", "HIGH"])
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.now()));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(new java.util.Date(666));
        vuln.setPublished(new java.util.Date(777));
        vuln.setUpdated(new java.util.Date(888));
        vuln.setSeverity(Severity.CRITICAL);
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(6.0));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(6.4));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(6.8));
        vuln.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(9.1));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(5.3));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(3.1));
        vuln.setCvssV3Vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.5));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.0));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.75));
        vuln.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        // set maintained to 6 as we're looking for <= 5
        healthMeta.setScorecardChecksJson("[{\"name\":\"Maintained\",\"description\":\"Maintained\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained\"}]\n");
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testIndividualScorecardScoresEqual() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                health.scoreCardChecks.maintained == 6.0
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardChecksJson("[{\"name\":\"Maintained\",\"description\":\"Maintained\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained\"}]\n");
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testIndividualScorecardScoresNotEqual() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                health.scoreCardChecks.maintained == 6.0
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardChecksJson("[{\"name\":\"Maintained\",\"description\":\"Maintained\",\"score\":7,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained\"}]\n");
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testMixedDependentsStarsForksCompareAge() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                health.dependents < 100 && (component.compare_age("<", "P100D") || (health.stars + health.forks) < 100)
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl(component.getPurl().toString());
        integrityMeta.setPublishedAt(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));
        integrityMeta.setStatus(FetchStatus.PROCESSED);
        integrityMeta.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMeta);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setStars(3);
        healthMeta.setForks(10);
        healthMeta.setDependents(7968);
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }
}