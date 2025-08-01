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

import alpine.model.IConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Tools;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class CelPolicyEngineTest extends PersistenceCapableTest {

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

    /**
     * (Regression-)Test for ensuring that all data available in the policy expression context
     * can be accessed in the expression at runtime.
     * <p>
     * Data being available means:
     * <ul>
     *   <li>Expression requirements were analyzed correctly</li>
     *   <li>Data was retrieved from the database correctly</li>
     *   <li>The mapping from DB data to CEL Protobuf models worked as expected</li>
     * </ul>
     */
    @Test
    public void testEvaluateProjectWithAllFields() {
        final var project = new Project();
        project.setUuid(UUID.fromString("d7173786-60aa-4a4f-a950-c92fe6422307"));
        project.setGroup("projectGroup");
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setClassifier(Classifier.APPLICATION);
        project.setInactiveSince(new java.util.Date(777));
        project.setCpe("projectCpe");
        project.setPurl("projectPurl");
        project.setSwidTagId("projectSwidTagId");
        project.setLastBomImport(new java.util.Date());
        qm.persist(project);

        final var bom = new Bom();
        bom.setProject(project);
        bom.setGenerated(new java.util.Date(999));
        bom.setImported(new Date());
        qm.persist(bom);

        final var toolComponentLicense = new License();
        toolComponentLicense.setUuid(UUID.randomUUID());
        toolComponentLicense.setLicenseId("toolComponentLicenseId");

        final var toolComponent = new Component();
        toolComponent.setGroup("toolComponentGroup");
        toolComponent.setName("toolComponentName");
        toolComponent.setVersion("toolComponentVersion");
        toolComponent.setClassifier(Classifier.APPLICATION);
        toolComponent.setCpe("toolComponentCpe");
        toolComponent.setPurl("pkg:maven/toolComponentGroup/toolComponentName@toolComponentVersion"); // NB: Must be valid PURL, otherwise it's being JSON serialized as null
        toolComponent.setPurlCoordinates("pkg:maven/toolComponentGroup/toolComponentName@toolComponentVersion"); // NB: Must be valid PURL, otherwise it's being JSON serialized as null
        toolComponent.setSwidTagId("toolComponentSwidTagId");
        toolComponent.setInternal(true); // NB: Currently ignored for tool components.
        toolComponent.setMd5("toolComponentMd5");
        toolComponent.setSha1("toolComponentSha1");
        toolComponent.setSha256("toolComponentSha256");
        toolComponent.setSha384("toolComponentSha384");
        toolComponent.setSha512("toolComponentSha512");
        toolComponent.setSha3_256("toolComponentSha3_256");
        toolComponent.setSha3_384("toolComponentSha3_384");
        toolComponent.setSha3_512("toolComponentSha3_512");
        toolComponent.setBlake2b_256("toolComponentBlake2b_256");
        toolComponent.setBlake2b_384("toolComponentBlake2b_384");
        toolComponent.setBlake2b_512("toolComponentBlake2b_512");
        toolComponent.setBlake3("toolComponentBlake3");
        // NB: License data is currently ignored for tool components.
        //   Including it in the test for documentation purposes.
        toolComponent.setLicense("toolComponentLicense");
        toolComponent.setLicenseExpression("toolComponentLicenseExpression");
        toolComponent.setLicenseUrl("toolComponentLicenseUrl");
        toolComponent.setResolvedLicense(toolComponentLicense);

        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setTools(new Tools(List.of(toolComponent), null));
        qm.persist(projectMetadata);

        qm.createProjectProperty(project, "propertyGroup", "propertyName", "propertyValue", IConfigProperty.PropertyType.STRING, null);

        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var licenseGroup = new LicenseGroup();
        licenseGroup.setUuid(UUID.fromString("bbdb62f8-d854-4e43-a9ed-36481545c201"));
        licenseGroup.setName("licenseGroupName");
        qm.persist(licenseGroup);

        final var license = new License();
        license.setUuid(UUID.fromString("dc9876c2-0adc-422b-9f71-3ca78285f138"));
        license.setLicenseId("resolvedLicenseId");
        license.setName("resolvedLicenseName");
        license.setOsiApproved(true);
        license.setFsfLibre(true);
        license.setDeprecatedLicenseId(true);
        license.setCustomLicense(true);
        license.setLicenseGroups(List.of(licenseGroup));
        qm.persist(license);

        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("7e5f6465-d2f2-424f-b1a4-68d186fa2b46"));
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setClassifier(Classifier.LIBRARY);
        component.setCpe("componentCpe");
        component.setPurl("componentPurl");
        component.setPurlCoordinates("componentPurl");
        component.setSwidTagId("componentSwidTagId");
        component.setInternal(true);
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha384("componentSha384");
        component.setSha512("componentSha512");
        component.setSha3_256("componentSha3_256");
        component.setSha3_384("componentSha3_384");
        component.setSha3_512("componentSha3_512");
        component.setBlake2b_256("componentBlake2b_256");
        component.setBlake2b_384("componentBlake2b_384");
        component.setBlake2b_512("componentBlake2b_512");
        component.setBlake3("componentBlake3");
        component.setLicense("componentLicenseName");
        component.setLicenseExpression("componentLicenseExpression");
        component.setResolvedLicense(license);
        qm.persist(component);

        final var metaComponent = new IntegrityMetaComponent();
        metaComponent.setPurl("componentPurl");
        metaComponent.setPublishedAt(new java.util.Date(222));
        metaComponent.setStatus(FetchStatus.PROCESSED);
        metaComponent.setLastFetch(new Date());
        qm.persist(metaComponent);

        final var healthMetaComponent = new HealthMetaComponent();
        healthMetaComponent.setPurlCoordinates("componentPurl");
        healthMetaComponent.setStatus(FetchStatus.PROCESSED);
        healthMetaComponent.setStars(1);
        healthMetaComponent.setForks(2);
        healthMetaComponent.setContributors(3);
        healthMetaComponent.setCommitFrequencyWeekly(4.5f);
        healthMetaComponent.setOpenIssues(5);
        healthMetaComponent.setOpenPRs(6);
        healthMetaComponent.setLastCommit(new Date(333));
        healthMetaComponent.setBusFactor(7);
        healthMetaComponent.setHasReadme(true);
        healthMetaComponent.setHasCodeOfConduct(true);
        healthMetaComponent.setHasSecurityPolicy(false);
        healthMetaComponent.setDependents(8);
        healthMetaComponent.setFiles(9);
        healthMetaComponent.setRepoArchived(false);
        healthMetaComponent.setScorecardScore(0.75f);
        healthMetaComponent.setScorecardReferenceVersion("scoreRefVer");
        healthMetaComponent.setScorecardChecksJson("[{\"name\":\"Packaging\",\"description\":\"This check tries to determine if the project is published as a package.\",\"score\":5,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#packaging\"},{\"name\":\"Token-Permissions\",\"description\":\"This check determines whether the project's automated workflows tokens follow the principle of least privilege.\",\"score\":3,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions\"},{\"name\":\"Code-Review\",\"description\":\"This check determines whether the project requires human code review before pull requests (merge requests) are merged.\",\"score\":8,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#code-review\"},{\"name\":\"Pinned-Dependencies\",\"description\":\"This check tries to determine if the project pins dependencies used during its build and release process.\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies\"},{\"name\":\"Binary-Artifacts\",\"description\":\"This check determines whether the project has generated executable (binary) artifacts in the source repository.\",\"score\":10,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#binary-artifacts\"},{\"name\":\"Dangerous-Workflow\",\"description\":\"This check determines whether the project's GitHub Action workflows has dangerous code patterns.\",\"score\":2,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow\"},{\"name\":\"Maintained\",\"description\":\"Determines if the project is \\\"actively maintained\\\".\",\"score\":7,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained\"},{\"name\":\"CII-Best-Practices\",\"description\":\"This check determines whether the project has earned an OpenSSF (formerly CII) Best Practices Badge.\",\"score\":4,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#cii-best-practices\"},{\"name\":\"Security-Policy\",\"description\":\"This check tries to determine if the project has published a security policy.\",\"score\":9,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#security-policy\"},{\"name\":\"Fuzzing\",\"description\":\"This check tries to determine if the project uses fuzzing tools, e.g. OSS-Fuzz.\",\"score\":1,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing\"},{\"name\":\"License\",\"description\":\"This check determines whether the project has defined a license.\",\"score\":10,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#license\"},{\"name\":\"Signed-Releases\",\"description\":\"This check tries to determine if the project cryptographically signs release artifacts.\",\"score\":0,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#signed-releases\"},{\"name\":\"Branch-Protection\",\"description\":\"This check determines whether a project's default and release branches are protected with GitHub's branch protection or repository rules settings.\",\"score\":5,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection\"},{\"name\":\"SAST\",\"description\":\"This check tries to determine if the project uses Static Application Security Testing (SAST).\",\"score\":7,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#sast\"},{\"name\":\"Vulnerabilities\",\"description\":\"This check determines whether the project has open, unfixed vulnerabilities in its own codebase or dependencies using the OSV service.\",\"score\":3,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#vulnerabilities\"},{\"name\":\"CI-Tests\",\"description\":\"This check tries to determine if the project runs tests before pull requests are merged.\",\"score\":6,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#ci-tests\"},{\"name\":\"Contributors\",\"description\":\"This check tries to determine if the project has recent contributors from multiple organizations (e.g., companies).\",\"score\":8,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#contributors\"},{\"name\":\"Dependency-Update-Tool\",\"description\":\"This check tries to determine if the project uses a dependency update tool, specifically one of: Dependabot, Renovate bot, PyUp.\",\"score\":2,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#dependency-update-tool\"},{\"name\":\"Webhooks\",\"description\":\"This check determines whether the webhook defined in the repository has a token configured to authenticate the origins of requests.\",\"score\":4,\"reason\":\"\",\"details\":[],\"documentationUrl\":\"https://github.com/ossf/scorecard/blob/main/docs/checks.md#webhooks\"}]");
        healthMetaComponent.setScorecardTimestamp(new Date(444));
        healthMetaComponent.setAvgIssueAgeDays(123.5f);
        qm.persist(healthMetaComponent);

        final var vuln = new Vulnerability();
        vuln.setUuid(UUID.fromString("ffe9743f-b916-431e-8a68-9b3ac56db72c"));
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(new java.util.Date(666));
        vuln.setPublished(new java.util.Date(777));
        vuln.setUpdated(new java.util.Date(888));
        vuln.setSeverity(Severity.INFO);
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

        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-001");
        vulnAlias.setGhsaId("GHSA-001");
        vulnAlias.setGsdId("GSD-001");
        vulnAlias.setInternalId("INT-001");
        vulnAlias.setOsvId("OSV-001");
        vulnAlias.setSnykId("SNYK-001");
        vulnAlias.setSonatypeId("SONATYPE-001");
        vulnAlias.setVulnDbId("VULNDB-001");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        final var epss = new Epss();
        epss.setCve("CVE-001");
        epss.setScore(BigDecimal.valueOf(0.6));
        epss.setPercentile(BigDecimal.valueOf(0.2));
        qm.synchronizeEpss(epss);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.uuid == "__COMPONENT_UUID__"
                  && component.group == "componentGroup"
                  && component.name == "componentName"
                  && component.version == "componentVersion"
                  && component.classifier == "LIBRARY"
                  && component.cpe == "componentCpe"
                  && component.purl == "componentPurl"
                  && component.swid_tag_id == "componentSwidTagId"
                  && component.is_internal
                  && component.md5 == "componentmd5"
                  && component.sha1 == "componentsha1"
                  && component.sha256 == "componentsha256"
                  && component.sha384 == "componentsha384"
                  && component.sha512 == "componentsha512"
                  && component.sha3_256 == "componentsha3_256"
                  && component.sha3_384 == "componentsha3_384"
                  && component.sha3_512 == "componentsha3_512"
                  && component.blake2b_256 == "componentBlake2b_256"
                  && component.blake2b_384 == "componentBlake2b_384"
                  && component.blake2b_512 == "componentBlake2b_512"
                  && component.blake3 == "componentBlake3"
                  && component.license_name == "componentLicenseName"
                  && component.license_expression == "componentLicenseExpression"
                  && component.resolved_license.uuid == "__RESOLVED_LICENSE_UUID__"
                  && component.resolved_license.id == "resolvedLicenseId"
                  && component.resolved_license.name == "resolvedLicenseName"
                  && component.resolved_license.is_osi_approved
                  && component.resolved_license.is_fsf_libre
                  && component.resolved_license.is_deprecated_id
                  && component.resolved_license.is_custom
                  && component.resolved_license.groups.all(licenseGroup,
                       licenseGroup.uuid == "__LICENSE_GROUP_UUID__"
                         && licenseGroup.name == "licenseGroupName"
                     )
                  && component.published_at == timestamp("1970-01-01T00:00:00.222Z")
                  && project.uuid == "__PROJECT_UUID__"
                  && project.group == "projectGroup"
                  && project.name == "projectName"
                  && project.version == "projectVersion"
                  && project.classifier == "APPLICATION"
                  && !project.is_active
                  && project.cpe == "projectCpe"
                  && project.purl == "projectPurl"
                  && project.swid_tag_id == "projectSwidTagId"
                  && has(project.last_bom_import)
                  && project.metadata.bom_generated == timestamp("1970-01-01T00:00:00.999Z")
                  && project.metadata.tools.components.all(tool,
                       tool.group == "toolComponentGroup"
                         && tool.name == "toolComponentName"
                         && tool.version == "toolComponentVersion"
                         && tool.classifier == "APPLICATION"
                         && tool.cpe == "toolComponentCpe"
                         && tool.purl == "pkg:maven/toolComponentGroup/toolComponentName@toolComponentVersion"
                         && tool.swid_tag_id == "toolComponentSwidTagId"
                         && !tool.is_internal
                         && tool.md5 == "toolcomponentmd5"
                         && tool.sha1 == "toolcomponentsha1"
                         && tool.sha256 == "toolcomponentsha256"
                         && tool.sha384 == "toolcomponentsha384"
                         && tool.sha512 == "toolcomponentsha512"
                         && tool.sha3_256 == "toolcomponentsha3_256"
                         && tool.sha3_384 == "toolcomponentsha3_384"
                         && tool.sha3_512 == "toolcomponentsha3_512"
                         && tool.blake2b_256 == "toolComponentBlake2b_256"
                         && tool.blake2b_384 == "toolComponentBlake2b_384"
                         && tool.blake2b_512 == "toolComponentBlake2b_512"
                         && tool.blake3 == "toolComponentBlake3"
                         && !has(tool.license_name)
                         && !has(tool.license_expression)
                         && !has(tool.resolved_license)
                     )
                  && "projecttaga" in project.tags
                  && project.properties.all(property,
                       property.group == "propertyGroup"
                         && property.name == "propertyName"
                         && property.value == "propertyValue"
                         && property.type == "STRING"
                     )
                  && vulns.all(vuln,
                       vuln.uuid == "__VULN_UUID__"
                         && vuln.id == "CVE-001"
                         && vuln.source == "NVD"
                         && 666 in vuln.cwes
                         && vuln.aliases
                              .map(alias, alias.source + ":" + alias.id)
                              .all(alias, alias in [
                                "NVD:CVE-001",
                                "GITHUB:GHSA-001",
                                "GSD:GSD-001",
                                "INTERNAL:INT-001",
                                "OSV:OSV-001",
                                "SNYK:SNYK-001",
                                "OSSINDEX:SONATYPE-001",
                                "VULNDB:VULNDB-001"
                              ])
                         && vuln.created == timestamp("1970-01-01T00:00:00.666Z")
                         && vuln.published == timestamp("1970-01-01T00:00:00.777Z")
                         && vuln.updated == timestamp("1970-01-01T00:00:00.888Z")
                         && vuln.severity == "INFO"
                         && vuln.cvssv2_base_score == 6.0
                         && vuln.cvssv2_impact_subscore == 6.4
                         && vuln.cvssv2_exploitability_subscore == 6.8
                         && vuln.cvssv2_vector == "(AV:N/AC:M/Au:S/C:P/I:P/A:P)"
                         && vuln.cvssv3_base_score == 9.1
                         && vuln.cvssv3_impact_subscore == 5.3
                         && vuln.cvssv3_exploitability_subscore == 3.1
                         && vuln.cvssv3_vector == "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L"
                         && vuln.owasp_rr_likelihood_score == 4.5
                         && vuln.owasp_rr_technical_impact_score == 5.0
                         && vuln.owasp_rr_business_impact_score == 3.75
                         && vuln.owasp_rr_vector == "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)"
                         && vuln.epss_score == 0.6
                         && vuln.epss_percentile == 0.2
                     )
                   && health.stars == 1
                   && health.forks == 2
                   && health.contributors == 3
                   && health.commitFrequencyWeekly == 4.5
                   && health.openIssues == 5
                   && health.openPRs == 6
                   && health.lastCommitDate == timestamp("1970-01-01T00:00:00.333Z")
                   && health.busFactor == 7
                   && health.hasReadme
                   && health.hasCodeOfConduct
                   && !health.hasSecurityPolicy
                   && health.dependents == 8
                   && health.files == 9
                   && !health.isRepoArchived
                   && health.avgIssueAgeDays == 123.5
                   && health.scoreCardScore == 0.75
                   && health.scoreCardReferenceVersion == "scoreRefVer"
                   && health.scoreCardTimestamp == timestamp("1970-01-01T00:00:00.444Z")
                   && health.scoreCardChecks.packaging == 5.0
                   && health.scoreCardChecks.tokenPermissions == 3.0
                   && health.scoreCardChecks.codeReview == 8.0
                   && health.scoreCardChecks.pinnedDependencies == 6.0
                   && health.scoreCardChecks.binaryArtifacts == 10.0
                   && health.scoreCardChecks.dangerousWorkflow == 2.0
                   && health.scoreCardChecks.maintained == 7.0
                   && health.scoreCardChecks.ciiBestPractices == 4.0
                   && health.scoreCardChecks.securityPolicy == 9.0
                   && health.scoreCardChecks.fuzzing == 1.0
                   && health.scoreCardChecks.license == 10.0
                   && health.scoreCardChecks.signedReleases == 0.0
                   && health.scoreCardChecks.branchProtection == 5.0
                   && health.scoreCardChecks.sast == 7.0
                   && health.scoreCardChecks.vulnerabilities == 3.0
                   && health.scoreCardChecks.ciTests == 6.0
                   && health.scoreCardChecks.contributors == 8.0
                   && health.scoreCardChecks.dependencyUpdateTool == 2.0
                   && health.scoreCardChecks.webhooks == 4.0
                """
                .replace("__COMPONENT_UUID__", component.getUuid().toString())
                .replace("__PROJECT_UUID__", project.getUuid().toString())
                .replace("__RESOLVED_LICENSE_UUID__", license.getUuid().toString())
                .replace("__LICENSE_GROUP_UUID__", licenseGroup.getUuid().toString())
                .replace("__VULN_UUID__", vuln.getUuid().toString()), PolicyViolation.Type.OPERATIONAL);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(project)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAnyAndAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForComponentAgeLessThan() throws MalformedPackageURLException {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.compare_age("NUMERIC_LESS_THAN", "P666D")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);
        Date publishedDate = Date.from(Instant.now());
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(publishedDate);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.compare_age("NUMERIC_LESS_THAN", "P666D")
                """);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForVersionDistance() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.version_distance(">=", v1.VersionDistance{ major: \"0\", minor: \"1\", patch: \"?\" })
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("name");
        project.setInactiveSince(null);

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.3.1");
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("foo");
        component.setName("bar");
        component.setPurl("pkg:maven/foo/bar@1.0.0");
        component.setVersion("1.2.3");
        qm.persist(component);

        project.setDirectDependencies("[{\"uuid\":\"" + component.getUuid() + "\"}]");
        qm.persist(project);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.version_distance(">=", v1.VersionDistance{ major: \"0\", minor: \"1\", patch: \"?\" })
                """);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForComponentAgeGreaterThan() throws MalformedPackageURLException {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.compare_age("<", "P666D")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);
        Date publishedDate = Date.from(Instant.now());
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(publishedDate);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.compare_age("<", "P666D")
                """);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonGreaterThan() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonLessThan() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) < duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonUnknown() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        // Omitted; Publish date is unknown.
        // integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());

        // This matches because the default value of Timestamp is 1970-01-01T00:00:00Z.
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonUnknownAndHasCheck() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                has(component.published_at) && (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        // Omitted; Publish date is unknown.
        // integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAnyAndNotAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAnyAndNoConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "someOtherProjectThatIsNotAcmeApp"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndNotAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndNoConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "someOtherProjectThatIsNotAcmeApp"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToProject() {
        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        policyB.setProjects(List.of(projectB));
        qm.persist(policyB);

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToProjectParent() {
        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectParentB = new Project();
        projectParentB.setName("acme-app-parent-b");
        qm.persist(projectParentB);

        policyB.setProjects(List.of(projectParentB));
        policyB.setIncludeChildren(true);
        qm.persist(policyB);

        final var projectB = new Project();
        projectB.setParent(projectParentB);
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToTag() {
        final Tag tag = qm.createTag("foo");

        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyB);
        qm.bind(policyB, List.of(tag));

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        qm.bind(projectB, List.of(tag));

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithInvalidScript() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.doesNotExist == "foo"
                """, PolicyViolation.Type.OPERATIONAL);
        final PolicyCondition validCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES, """
                        project.name == "acme-app"
                        """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(component)).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition()).isEqualTo(validCondition)
        );
    }

    @Test
    public void testEvaluateProjectWithScriptExecutionException() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.last_bom_import == timestamp("invalid")
                """, PolicyViolation.Type.OPERATIONAL);
        final PolicyCondition validCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES, """
                        project.name == "acme-app"
                        """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(component)).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition()).isEqualTo(validCondition)
        );
    }

    @Test
    public void testEvaluateProjectWithFuncProjectDependsOnComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.depends_on(v1.Component{name: "acme-lib-a"})
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncProjectDependsOnComponentWithRegexAndVers() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.depends_on(v1.Component{name: "re:^acme-lib-.*$", version: "vers:generic/>1|<2.0"})
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("2.1.1");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.is_dependency_of(v1.Component{name: "acme-lib-a"})
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfComponentWithRegex() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.is_dependency_of(v1.Component{name: "re:.*-lib-.*"})
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfComponentWithVersRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.is_dependency_of(v1.Component{
                  name: "re:.*-lib-*",
                  version: "vers:maven/>=2.1.2|<2.2"
                })
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("2.1.2");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithSinglePath() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("acme-lib-c");
        qm.persist(componentC);

        final var componentD = new Component();
        componentD.setProject(project);
        componentD.setName("acme-lib-d");
        qm.persist(componentD);

        //  /-> A -> C
        // *
        //  \-> B -> D
        project.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentA).toJSON(),
                new ComponentIdentity(componentB).toJSON())
        );
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentC).toJSON()));
        componentB.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentD).toJSON()));
        qm.persist(project);
        qm.persist(componentA);
        qm.persist(componentB);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through A?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-a"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through B?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-b"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).hasSize(1);

        // Is component introduced exclusively through C?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-c"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through D?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-d"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithMultiplePaths() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("acme-lib-c");
        qm.persist(componentC);

        final var componentD = new Component();
        componentD.setProject(project);
        componentD.setName("acme-lib-d");
        qm.persist(componentD);

        //  /-> A -------\
        // *              > C
        //  \-> B -> D --/
        project.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentA).toJSON(),
                new ComponentIdentity(componentB).toJSON())
        );
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentC).toJSON()));
        componentB.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentD).toJSON()));
        componentD.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentC).toJSON()));
        qm.persist(project);
        qm.persist(componentA);
        qm.persist(componentB);
        qm.persist(componentD);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through A?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-a"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through B?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-b"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).hasSize(1);

        // Is component introduced exclusively through C?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-c"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through D?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-D"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithMultiplePaths2() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("acme-lib-c");
        qm.persist(componentC);

        final var componentD = new Component();
        componentD.setProject(project);
        componentD.setName("acme-lib-d");
        qm.persist(componentD);

        //  /-> A --\
        // *         > C -> D
        //  \-> B --/
        project.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentA).toJSON(),
                new ComponentIdentity(componentB).toJSON())
        );
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentC).toJSON()));
        componentB.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentC).toJSON()));
        componentC.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentD).toJSON()));
        qm.persist(project);
        qm.persist(componentA);
        qm.persist(componentB);
        qm.persist(componentC);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through A?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-a"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through B?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-b"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).isEmpty();

        // Is component introduced exclusively through C?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-c"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentC)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentD)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithMultiplePaths3() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentSpringBootStarter = new Component();
        componentSpringBootStarter.setProject(project);
        componentSpringBootStarter.setName("spring-boot-starter");
        qm.persist(componentSpringBootStarter);

        final var componentSpringCore = new Component();
        componentSpringCore.setProject(project);
        componentSpringCore.setName("spring-core");
        qm.persist(componentSpringCore);

        final var componentJacksonDataformatYaml = new Component();
        componentJacksonDataformatYaml.setProject(project);
        componentJacksonDataformatYaml.setName("jackson-dataformat-yaml");
        qm.persist(componentJacksonDataformatYaml);

        final var componentSnakeYaml = new Component();
        componentSnakeYaml.setProject(project);
        componentSnakeYaml.setName("snakeyaml");
        qm.persist(componentSnakeYaml);

        //    /------------------------------------------\
        //   /                                           v
        //  /-> spring-boot-starter -> spring-core -> snakeyaml
        // *                                             ^
        //  \-> jackson-dataformat-yaml ----------------/
        project.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentSpringBootStarter).toJSON(),
                new ComponentIdentity(componentSnakeYaml).toJSON())
        );
        componentSpringBootStarter.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSpringCore).toJSON()));
        componentSpringCore.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSnakeYaml).toJSON()));
        componentJacksonDataformatYaml.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSnakeYaml).toJSON()));
        qm.persist(project);
        qm.persist(componentSpringBootStarter);
        qm.persist(componentSpringCore);
        qm.persist(componentJacksonDataformatYaml);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through spring-boot-starter?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "spring-boot-starter"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentJacksonDataformatYaml)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSnakeYaml)).isEmpty();

        // Is component introduced exclusively through spring-core?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-core"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentJacksonDataformatYaml)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSnakeYaml)).isEmpty();

        // Is component introduced exclusively through jackson-dataformat-yaml?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "jackson-dataformat-yaml"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentJacksonDataformatYaml)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSnakeYaml)).isEmpty();

        // Is component introduced exclusively through snakeyaml?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "snakeyaml"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentJacksonDataformatYaml)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSnakeYaml)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithMultiplePaths4() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentSpringBootStarter = new Component();
        componentSpringBootStarter.setProject(project);
        componentSpringBootStarter.setName("spring-boot-starter");
        qm.persist(componentSpringBootStarter);

        final var componentSpringBoot = new Component();
        componentSpringBoot.setProject(project);
        componentSpringBoot.setName("spring-boot");
        qm.persist(componentSpringBoot);

        final var componentSpringContext = new Component();
        componentSpringContext.setProject(project);
        componentSpringContext.setName("spring-context");
        qm.persist(componentSpringContext);

        final var componentSpringAop = new Component();
        componentSpringAop.setProject(project);
        componentSpringAop.setName("spring-aop");
        qm.persist(componentSpringAop);

        final var componentSpringBeans = new Component();
        componentSpringBeans.setProject(project);
        componentSpringBeans.setName("spring-beans");
        qm.persist(componentSpringBeans);

        final var componentSpringExpression = new Component();
        componentSpringExpression.setProject(project);
        componentSpringExpression.setName("spring-expression");
        qm.persist(componentSpringExpression);

        final var componentSpringCore = new Component();
        componentSpringCore.setProject(project);
        componentSpringCore.setName("spring-core");
        qm.persist(componentSpringCore);
        //                                                     /-------------------------------------------\
        //                                                    /                                            v
        //                                                   /               /-----------------------------\
        //                                                  /               /                              v
        // * -> spring-boot-starter -> spring-boot -> spring-context -> spring-aop -> spring-beans -> spring-core
        //                                   \              \                                               ^
        //                                    \              \---------> spring-expression ----------------/
        //                                     \                                                            ^
        //                                      \----------------------------------------------------------/
        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSpringBootStarter).toJSON()));
        componentSpringBootStarter.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSpringBoot).toJSON()));
        componentSpringBoot.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentSpringCore).toJSON(),
                new ComponentIdentity(componentSpringContext).toJSON())
        );
        componentSpringContext.setDirectDependencies("[%s, %s, %s]".formatted(
                new ComponentIdentity(componentSpringAop).toJSON(),
                new ComponentIdentity(componentSpringExpression).toJSON(),
                new ComponentIdentity(componentSpringCore).toJSON()
        ));
        componentSpringAop.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentSpringCore).toJSON(),
                new ComponentIdentity(componentSpringBeans).toJSON()
        ));
        componentSpringBeans.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSpringCore).toJSON()));
        componentSpringExpression.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentSpringCore).toJSON()));
        qm.persist(project);
        qm.persist(componentSpringBootStarter);
        qm.persist(componentSpringBoot);
        qm.persist(componentSpringContext);
        qm.persist(componentSpringAop);
        qm.persist(componentSpringBeans);
        qm.persist(componentSpringExpression);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through spring-boot-starter?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "spring-boot-starter"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).hasSize(1);

        // Is component introduced exclusively through spring-boot?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-boot"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).hasSize(1);

        // Is component introduced exclusively through spring-context?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-context"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();

        // Is component introduced exclusively through spring-aop?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-aop"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();

        // Is component introduced exclusively through spring-beans?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-beans"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();

        // Is component introduced exclusively through spring-expression?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-expression"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();

        // Is component introduced exclusively through spring-core?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "spring-core"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).isEmpty();

        // Is component introduced exclusively through components with names matching a regular expression?
        condition.setValue("""
                has(component.name) && component.is_exclusive_dependency_of(v1.Component{name: "re:^spring-.*$"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentSpringBootStarter)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentSpringBoot)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringContext)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringAop)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringBeans)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringExpression)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentSpringCore)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithFuncComponentIsDependencyOfExclusiveComponentWithMultiplePaths5() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        //  /-> A -> B
        // *         ^
        //  \-------/
        project.setDirectDependencies("[%s, %s]".formatted(
                new ComponentIdentity(componentA).toJSON(),
                new ComponentIdentity(componentB).toJSON()
        ));
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(project);
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Is component introduced exclusively through acme-lib-a?
        PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-a"})
                        """, PolicyViolation.Type.OPERATIONAL);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();

        // Is component introduced exclusively through acme-lib-b?
        condition.setValue("""
                component.is_exclusive_dependency_of(v1.Component{name: "acme-lib-b"})
                """);
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncMatchesRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.matches_range("vers:generic/<1")
                    && component.matches_range("vers:golang/>0|<v2.0.0")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("0.1");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("v2.0.0");
        qm.persist(componentB);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncMatchesRangeWithInvalidRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.matches_range("foo")
                    && component.matches_range("bar")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("0.1");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("v2.0.0");
        qm.persist(componentB);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithToolMetadata() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.metadata.tools.components.exists(tool,
                  tool.name == "toolName" && tool.matches_range("vers:generic/>=1.2.3|<3"))
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("0.1");
        qm.persist(project);

        final var toolComponent = new Component();
        toolComponent.setName("toolName");
        toolComponent.setVersion("2.3.1");

        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setTools(new Tools(List.of(toolComponent), null));
        qm.persist(projectMetadata);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);

        toolComponent.setVersion("3.1");
        projectMetadata.setTools(new Tools(List.of(toolComponent), null));
        qm.persist(projectMetadata);
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWhenProjectDoesNotExist() {
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(UUID.randomUUID()));
    }

    @Test
    public void testEvaluateComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateComponentWhenComponentDoesNotExist() {
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateComponent(UUID.randomUUID()));
    }

    @Test
    public void issue1924() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, "pkg:deb");
        Project project = qm.createProject("My Project", null, "1", null, null, null, null, false);
        qm.persist(project);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("OpenSSL");
        component.setVersion("3.0.2-0ubuntu1.6");
        component.setPurl("pkg:deb/openssl@3.0.2-0ubuntu1.6");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("1");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("2");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        component = new Component();
        component.setName("Log4J");
        component.setVersion("1.2.16");
        component.setPurl("pkg:mvn/log4j/log4j@1.2.16");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("3");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("4");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        CelPolicyEngine policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        final List<PolicyViolation> violations = qm.getAllPolicyViolations();
        // NOTE: This behavior changed in CelPolicyEngine over the legacy PolicyEngine.
        // A matched PolicyCondition can now only yield a single PolicyViolation, whereas
        // with the legacy PolicyEngine, multiple PolicyViolations could be raised.
//        Assert.assertEquals(3, violations.size());
//        PolicyViolation policyViolation = violations.get(0);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
//        policyViolation = violations.get(1);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
//        policyViolation = violations.get(2);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.PACKAGE_URL, policyViolation.getPolicyCondition().getSubject());
        assertThat(violations).satisfiesExactlyInAnyOrder(
                violation -> {
                    assertThat(violation.getComponent().getName()).isEqualTo("Log4J");
                    assertThat(violation.getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.SEVERITY);
                },
                violation -> {
                    assertThat(violation.getComponent().getName()).isEqualTo("Log4J");
                    assertThat(violation.getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.PACKAGE_URL);
                }
        );
    }

    @Test
    public void issue2455() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);

        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group 1");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        license = new License();
        license.setName("MIT");
        license.setLicenseId("MIT");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        lg = qm.createLicenseGroup("Test License Group 2");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        Project project = qm.createProject("My Project", null, "1", null, null, null, null, false);
        qm.persist(project);

        license = new License();
        license.setName("LGPL");
        license.setLicenseId("LGPL");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("Log4J");
        component.setVersion("2.0.0");
        component.setProject(project);
        component.setResolvedLicense(license);
        components.add(component);
        qm.persist(component);

        CelPolicyEngine policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        final List<PolicyViolation> violations = qm.getAllPolicyViolations();
        Assert.assertEquals(2, violations.size());
        PolicyViolation policyViolation = violations.get(0);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void testEvaluateProjectWithNoLongerApplicableViolationWithAnalysis() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("org.acme");
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        final Policy policyA = qm.createPolicy("Policy A", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, """
                {"group": "*", name: "*", version: "*"}
                """);

        // Create another policy which already has a violation files for the component.
        // The violation has both an analysis (REJECTED), and a comment added to it.
        // As it is checking for component version == 1.5.0, it should no longer violate and be cleaned up.
        final Policy policyB = qm.createPolicy("Policy B", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition conditionB = qm.createPolicyCondition(policyB,
                PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.5.0");
        final var violationB = new PolicyViolation();
        violationB.setComponent(component);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(Date.from(Instant.EPOCH));
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(violationB);
        final var violationAnalysisB = qm.makeViolationAnalysis(component, violationB, ViolationAnalysisState.REJECTED, false);
        qm.makeViolationAnalysisComment(violationAnalysisB, "comment", "commenter");

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(project)).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition().getPolicy().getName()).isEqualTo("Policy A"));
    }

    @Test
    @Ignore  // Un-ignore for manual profiling purposes.
    public void testWithBloatedBom() throws Exception {
        // Import all default objects (includes licenses and license groups).
        new DefaultObjectGenerator().contextInitialized(null);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        // Create a policy that will be violated by the vast majority (>8000) components.
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyConditionA = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.resolved_license.groups.exists(lg, lg.name == "Permissive")
                        """);
        policyConditionA.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyConditionA);

        // Import the bloated BOM.
        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), storeBomFile("bom-bloated.json")));

        // Evaluate policies on the project.
        new CelPolicyEngine().evaluateProject(project.getUuid());
    }

    private static FileMetadata storeBomFile(final String testFileName) throws Exception {
        final Path bomFilePath = Paths.get(resourceToURL("/unit/" + testFileName).toURI());
        final byte[] bomBytes = Files.readAllBytes(bomFilePath);

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            return fileStorage.store(
                    "test/%s-%s".formatted(CelPolicyEngineTest.class.getSimpleName(), UUID.randomUUID()), bomBytes);
        }
    }

    @Test
    public void testPoliciesShouldNotFailWhenHealthNotPresent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib" && health.scoreCardScore < 5.0
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testPoliciesShouldNotFailWhenHealthPresentButIncomplete() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib" && health.scoreCardScore < 5.0 && health.avgIssueAgeDays > 100.0
                """, PolicyViolation.Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurlCoordinates("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(component.getPurlCoordinates().toString());
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setAvgIssueAgeDays(150.0f);
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testPoliciesShouldBeSkippedWhenIndividualScorecardChecksNotPresent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib" && health.scoreCardChecks.maintained < 5.0 && health.avgIssueAgeDays > 100.0
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
        healthMeta.setPurlCoordinates(component.getPurlCoordinates().toString());
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setAvgIssueAgeDays(150.0f);
        healthMeta.setScorecardChecksJson("[]");
        qm.persist(healthMeta);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }
}