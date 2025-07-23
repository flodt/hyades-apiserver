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
package org.dependencytrack.event.kafka.processor;

import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.Timestamp;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.repometaanalysis.v1.HealthMeta;
import org.dependencytrack.proto.repometaanalysis.v1.IntegrityMeta;
import org.dependencytrack.proto.repometaanalysis.v1.ScoreCardCheck;
import org.dependencytrack.util.ProtoUtil;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import javax.jdo.Query;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.tuple;
import static org.awaitility.Awaitility.await;

public class RepositoryMetaResultProcessorTest extends AbstractProcessorTest {
    private static final ConcurrentLinkedQueue<Event> EVENTS = new ConcurrentLinkedQueue<>();

    public static class EventSubscriber implements Subscriber {
        @Override
        public void inform(final Event event) {
            EVENTS.add(event);
        }
    }

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("INTEGRITY_CHECK_ENABLED", "true");

        EventService.getInstance().subscribe(ComponentMetricsUpdateEvent.class, EventSubscriber.class);
        EventService.getInstance().subscribe(ComponentPolicyEvaluationEvent.class, EventSubscriber.class);
    }

    @After
    @Override
    public void after() {
        EventService.getInstance().unsubscribe(ProcessedVulnerabilityScanResultProcessorTest.EventSubscriber.class);
        EVENTS.clear();
        super.after();
    }

    @Test
    public void processNewMetaModelTest() throws Exception {
        final var published = Instant.now().minus(5, ChronoUnit.MINUTES);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));
    }

    @Test
    public void processWithoutComponentDetailsTest() throws Exception {
        final var result = AnalysisResult.newBuilder()
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(Instant.now().getEpochSecond()))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        final Query<RepositoryMetaComponent> query = qm.getPersistenceManager().newQuery(RepositoryMetaComponent.class);
        query.setResult("count(this)");

        assertThat(query.executeResultUnique(Long.class)).isZero();
    }

    @Test
    public void processUpdateExistingMetaModelTest() throws Exception {
        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.0.0");
        metaComponent.setPublished(Date.from(Instant.now().minus(Duration.ofDays(1))));
        metaComponent.setLastCheck(Date.from(Instant.now().minus(Duration.ofMinutes(5))));
        qm.persist(metaComponent);

        final var published = Instant.now();

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));
    }

    @Test
    public void processUpdateOutOfOrderMetaModelTest() throws Exception {
        final var testStartTime = new Date();

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.2.5");
        metaComponent.setPublished(Date.from(Instant.now().minus(Duration.ofDays(1))));
        metaComponent.setLastCheck(Date.from(Instant.now().minusSeconds(5)));
        qm.persist(metaComponent);

        final var published = Instant.now();

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .build();

        // Pipe in a record that was produced 10 seconds ago, 5 seconds before metaComponent's lastCheck.
        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).withTimestamp(Instant.now().minusSeconds(10)).build());

        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.5"); // Must not have been updated
        assertThat(metaComponent.getPublished()).isNotEqualTo(Date.from(published)); // Must not have been updated
        assertThat(metaComponent.getLastCheck()).isBefore(testStartTime); // Must not have been updated
    }

    @Test
    public void processUpdateIntegrityResultTest() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getUpdatedAt()).isNotNull();
        assertThat(analysis.getComponent().getPurl().toString()).isEqualTo("pkg:maven/foo/bar@1.2.3");
    }

    @Test
    public void testIntegrityCheckWhenComponentHashIsMissing() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getUpdatedAt()).isNotNull();
        assertThat(analysis.getComponent().getPurl().toString()).isEqualTo("pkg:maven/foo/bar@1.2.3");
    }

    @Test
    public void testIntegrityAnalysisWillNotBePerformedIfNoIntegrityDataInResult() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityCheckWillNotBeDoneIfComponentUuidAndIntegrityDataIsMissing() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                //component uuid has not been set
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityIfResultHasIntegrityDataAndComponentUuidIsMissing() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");

        Component c = qm.persist(componentProjectA);
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .build())
                //component uuid has not been set
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis).isNotNull();
        assertThat(analysis.getComponent()).isEqualTo(c);
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
    }


    @Test
    public void testIntegrityCheckWillNotBeDoneIfComponentIsNotInDb() throws Exception {

        UUID uuid = UUID.randomUUID();

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(uuid.toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))

                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(uuid);
        assertThat(analysis).isNull();
    }

    @Test
    public void testIntegrityCheckShouldReturnComponentHashMissing() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void testIntegrityCheckShouldReturnComponentHashMissingAndMatchUnknown() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void testIntegrityCheckShouldFailIfNoHashMatch() throws Exception {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        UUID uuid = UUID.randomUUID();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/foo/bar@1.2.3?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        componentProjectA.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        componentProjectA.setMd5("098f6bcd4621d373cade4e832627b4f6");
        componentProjectA.setUuid(uuid);

        Component c = qm.persist(componentProjectA);

        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setUuid(c.getUuid().toString())
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder()
                        .setSha1("somevalue")
                        .setMd5("someothervalue")
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("someothervalue");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("somevalue");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        IntegrityAnalysis analysis = qm.getIntegrityAnalysisByComponentUuid(c.getUuid());
        assertThat(analysis.getIntegrityCheckStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getMd5HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getSha1HashMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
        assertThat(analysis.getSha256HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
        assertThat(analysis.getSha512HashMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN);
    }

    @Test
    public void processUpdateIntegrityResultNotAvailableTest() throws Exception {
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);


        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isNull();
        assertThat(integrityMetaComponent.getSha1()).isNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.NOT_AVAILABLE);
    }

    @Test
    public void processUpdateOldIntegrityResultSent() throws Exception {

        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(date);
        integrityMetaComponent.setMd5("098f6bcd4621d373cade4e832627b4f6");
        integrityMetaComponent.setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        integrityMetaComponent.setRepositoryUrl("test1");
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e587982fbbd3").setMetaSourceUrl("test2").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getLastFetch()).isEqualTo(date);
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test1");
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }


    @Test
    public void processBothMetaModelAndIntegrityMeta() throws Exception {
        final var published = Instant.now().minus(5, ChronoUnit.MINUTES);
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setLatestVersion("1.2.4")
                .setPublished(Timestamp.newBuilder()
                        .setSeconds(published.getEpochSecond()))
                .setIntegrityMeta(IntegrityMeta.newBuilder().setMd5("098f6bcd4621d373cade4e832627b4f6")
                        .setSha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
                        .setMetaSourceUrl("test").build())
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        final RepositoryMetaComponent metaComponent =
                qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar");
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getRepositoryType()).isEqualTo(RepositoryType.MAVEN);
        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
        assertThat(metaComponent.getName()).isEqualTo("bar");
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
        assertThat(metaComponent.getPublished()).isEqualToIgnoringMillis(Date.from(published));

        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isEqualTo("098f6bcd4621d373cade4e832627b4f6");
        assertThat(integrityMetaComponent.getSha1()).isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        assertThat(integrityMetaComponent.getRepositoryUrl()).isEqualTo("test");
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }

    @Test
    public void processUpdateIntegrityResultNotSentTest() throws Exception {
        var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl("pkg:maven/foo/bar@1.2.3");
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        Date date = Date.from(Instant.now().minus(15, ChronoUnit.MINUTES));
        integrityMetaComponent.setLastFetch(date);
        qm.persist(integrityMetaComponent);


        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar@1.2.3", result).build());
        qm.getPersistenceManager().refresh(integrityMetaComponent);
        integrityMetaComponent = qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3");
        assertThat(integrityMetaComponent).isNotNull();
        assertThat(integrityMetaComponent.getMd5()).isNull();
        assertThat(integrityMetaComponent.getSha1()).isNull();
        assertThat(integrityMetaComponent.getRepositoryUrl()).isNull();
        assertThat(integrityMetaComponent.getLastFetch()).isEqualTo(date);
        assertThat(integrityMetaComponent.getStatus()).isEqualTo(FetchStatus.IN_PROGRESS);
    }

    @Test
    public void processNewHealthMetaModelTest() throws Exception {
        Component component = persistTestComponent();

        Instant lastCommitInstant = Instant.parse("2025-07-01T12:00:00Z");
        Instant scorecardInstant = Instant.parse("2025-07-02T13:00:00Z");

        Timestamp lastCommitTs = Timestamp.newBuilder()
                .setSeconds(lastCommitInstant.getEpochSecond())
                .setNanos(lastCommitInstant.getNano())
                .build();
        Timestamp scorecardTs = Timestamp.newBuilder()
                .setSeconds(scorecardInstant.getEpochSecond())
                .setNanos(scorecardInstant.getNano())
                .build();

        AnalysisResult result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setHealthMeta(HealthMeta.newBuilder()
                        .setStars(42)
                        .setForks(10)
                        .setContributors(5)
                        .setCommitFrequencyWeekly(3.14f)
                        .setOpenIssues(7)
                        .setOpenPRs(2)
                        .setLastCommitDate(lastCommitTs)
                        .setBusFactor(1)
                        .setHasReadme(true)
                        .setHasCodeOfConduct(false)
                        .setHasSecurityPolicy(true)
                        .setDependents(4)
                        .setFiles(100)
                        .setIsRepoArchived(true)
                        .setScoreCardScore(9.8f)
                        .setScoreCardReferenceVersion("v1.2.3")
                        .setScoreCardTimestamp(scorecardTs)
                        .setAvgIssueAgeDays(789.0f))
                .build();

        var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        HealthMetaComponent h = qm.getHealthMetaComponent("pkg:maven/foo/bar@1.2.3");

        assertThat(h).isNotNull();
        assertThat(h.getStars()).isEqualTo(42);
        assertThat(h.getForks()).isEqualTo(10);
        assertThat(h.getContributors()).isEqualTo(5);
        assertThat(h.getCommitFrequencyWeekly()).isEqualTo(3.14f);
        assertThat(h.getOpenIssues()).isEqualTo(7);
        assertThat(h.getOpenPRs()).isEqualTo(2);
        assertThat(h.getBusFactor()).isEqualTo(1);
        assertThat(h.getDependents()).isEqualTo(4);
        assertThat(h.getFiles()).isEqualTo(100);
        assertThat(h.getScorecardScore()).isEqualTo(9.8f);
        assertThat(h.getHasReadme()).isTrue();
        assertThat(h.getHasCodeOfConduct()).isFalse();
        assertThat(h.getHasSecurityPolicy()).isTrue();
        assertThat(h.getRepoArchived()).isTrue();
        assertThat(h.getLastCommit()).isEqualTo(ProtoUtil.convertToDate(lastCommitTs));
        assertThat(h.getScorecardTimestamp()).isEqualTo(ProtoUtil.convertToDate(scorecardTs));
        assertThat(h.getScorecardReferenceVersion()).isEqualTo("v1.2.3");
        assertThat(h.getAvgIssueAgeDays()).isEqualTo(789.0f);
        assertThat(h.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        await("Internal event publish")
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThat(EVENTS).satisfiesExactly(
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentPolicyEvaluationEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        ),
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentMetricsUpdateEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        )
                ));
    }

    @Test
    public void processWithoutHealthMetaResultTest() throws Exception {
        final var result = AnalysisResult.newBuilder().build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        try (Query<HealthMetaComponent> query = qm.getPersistenceManager().newQuery(HealthMetaComponent.class)) {
            query.setResult("count(this)");
            assertThat(query.executeResultUnique(Long.class)).isZero();
        }

        await("Internal event publish")
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThat(EVENTS).isEmpty());
    }

    @Test
    public void processUpdateExistingHealthMetaTest() throws Exception {
        Component component = persistTestComponent();

        final var healthMetaComponent = new HealthMetaComponent();
        healthMetaComponent.setPurlCoordinates("pkg:maven/foo/bar@1.2.3");
        healthMetaComponent.setStatus(FetchStatus.PROCESSED);
        healthMetaComponent.setScorecardScore(10.0f);
        healthMetaComponent.setStars(500);

        qm.persist(healthMetaComponent);

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setHealthMeta(HealthMeta.newBuilder()
                        .setScoreCardScore(0.0f)
                        .setStars(1))
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        qm.getPersistenceManager().refresh(healthMetaComponent);
        assertThat(healthMetaComponent).isNotNull();
        assertThat(healthMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);
        assertThat(healthMetaComponent.getScorecardScore()).isEqualTo(0.0f);
        assertThat(healthMetaComponent.getStars()).isEqualTo(1);

        await("Internal event publish")
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThat(EVENTS).satisfiesExactly(
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentPolicyEvaluationEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        ),
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentMetricsUpdateEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        )
                ));
    }

    @Test
    public void processScorecardResultHealthMetaModelTest() throws Exception {
        Component component = persistTestComponent();

        final var result = AnalysisResult.newBuilder()
                .setComponent(org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                        .setPurl("pkg:maven/foo/bar@1.2.3"))
                .setHealthMeta(
                        HealthMeta.newBuilder()
                                .addScoreCardChecks(
                                        ScoreCardCheck.newBuilder()
                                                .setName("Check A")
                                                .setScore(0.0f)
                                                .setDescription("Check A Description")
                                                .setReason("Check A Reason")
                                                .setDocumentationUrl("https://checkADocumentation.com")
                                                .addDetails("Detail A.1")
                                                .addDetails("Detail A.2")
                                                .build()
                                )
                                .addScoreCardChecks(
                                        ScoreCardCheck.newBuilder()
                                                .setName("Check B")
                                                .setScore(10.0f)
                                                .setDescription("Check B Description")
                                                .setReason("Check B Reason")
                                                .setDocumentationUrl("https://checkBDocumentation.com")
                                                .addDetails("Detail B.1")
                                                .addDetails("Detail B.2")
                                                .build()
                                )
                )
                .build();

        final var processor = new RepositoryMetaResultProcessor();
        processor.process(aConsumerRecord("pkg:maven/foo/bar", result).build());

        final HealthMetaComponent healthMetaComponent =
                qm.getHealthMetaComponent("pkg:maven/foo/bar@1.2.3");

        assertThat(healthMetaComponent).isNotNull();
        assertThat(healthMetaComponent.getStatus()).isEqualTo(FetchStatus.PROCESSED);

        ObjectMapper mapper = new ObjectMapper();
        List<Map<String, Object>> checks = mapper.readValue(
                healthMetaComponent.getScorecardChecksJson(), new TypeReference<List<Map<String, Object>>>() {
                }
        );

        assertThat(checks).hasSize(2);

        assertThat(checks)
                .extracting(
                        m -> m.get("name"),
                        m -> m.get("description"),
                        m -> ((Number) m.get("score")).doubleValue(),
                        m -> m.get("reason"),
                        m -> m.get("details"),
                        m -> m.get("documentationUrl")
                )
                .containsExactly(
                        tuple(
                                "Check A",
                                "Check A Description",
                                0.0,
                                "Check A Reason",
                                List.of("Detail A.1", "Detail A.2"),
                                "https://checkADocumentation.com"
                        ),
                        tuple(
                                "Check B",
                                "Check B Description",
                                10.0,
                                "Check B Reason",
                                List.of("Detail B.1", "Detail B.2"),
                                "https://checkBDocumentation.com"
                        )
                );

        await("Internal event publish")
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThat(EVENTS).satisfiesExactly(
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentPolicyEvaluationEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        ),
                        event ->
                                assertThat(event)
                                        .isInstanceOfSatisfying(
                                                ComponentMetricsUpdateEvent.class,
                                                e ->
                                                        assertThat(e.getUuid())
                                                                .isNotNull()
                                                                .isEqualTo(component.getUuid())
                                        )
                ));
    }

    private @NotNull Component persistTestComponent() {
        Project project = new Project();
        project.setName("Test Project");

        Component component = new Component();
        component.setName("Test Component");
        component.setPurl("pkg:maven/foo/bar@1.2.3");
        component.setProject(project);

        return qm.persist(component);
    }
}