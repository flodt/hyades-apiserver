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

package org.dependencytrack.event.kafka.componentmeta.health;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.event.kafka.componentmeta.Handler;
import org.dependencytrack.event.kafka.componentmeta.HandlerFactory;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class SupportedHealthMetaHandlerTest extends PersistenceCapableTest {
    private static final String TEST_PURL = "pkg:maven/org.http4s/blaze-core_2.12";

    private void assertEventRecordsAndFetchStatus(UUID uuid, HealthMetaComponent result) {
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo(TEST_PURL);
                    assertThat(command.getComponent().getUuid()).isEqualTo(uuid.toString());
                    assertThat(command.getComponent().getInternal()).isFalse();
                    assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_HEALTH);
                }

        );
        Assertions.assertEquals(FetchStatus.IN_PROGRESS, result.getStatus());
    }

    @Test
    public void testHandleHealthComponentNotInDB() throws MalformedPackageURLException {
        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // is not in database
        HealthMetaComponent healthMetaComponent = qm.getHealthMetaComponent(componentProjection.purl().toString());
        Assertions.assertNull(healthMetaComponent);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent result = handler.handle();

        assertEventRecordsAndFetchStatus(uuid, result);
    }

    @Test
    public void testHandleHealthWhenStaleMetadataExists() throws MalformedPackageURLException {
        final String TEST_PURL = SupportedHealthMetaHandlerTest.TEST_PURL;
        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // persist
        var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(TEST_PURL);
        healthMeta.setStars(42);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStatus(FetchStatus.PROCESSED);
        // -> set last fetch older than RepoMetaConstants.TIME_SPAN_HEALTH_META (which is 3 days)
        healthMeta.setLastFetch(Date.from(Instant.now().minus(4, ChronoUnit.DAYS)));
        qm.createHealthMetaComponent(healthMeta);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent healthMetaComponent = handler.handle();

        assertEventRecordsAndFetchStatus(uuid, healthMetaComponent);
    }

    @Test
    public void testHandleHealthWhenUnknownAgeMetadataExists() throws MalformedPackageURLException {
        final String TEST_PURL = SupportedHealthMetaHandlerTest.TEST_PURL;
        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // persist
        var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(TEST_PURL);
        healthMeta.setStars(42);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStatus(FetchStatus.PROCESSED);
        // -> set last fetch to null (don't have info)
        healthMeta.setLastFetch(null);
        qm.createHealthMetaComponent(healthMeta);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent healthMetaComponent = handler.handle();

        assertEventRecordsAndFetchStatus(uuid, healthMetaComponent);
    }

    @Test
    public void testHandleHealthWhenBrokenStaleFetchExists() throws MalformedPackageURLException {
        final String TEST_PURL = SupportedHealthMetaHandlerTest.TEST_PURL;
        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // persist
        var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(TEST_PURL);
        healthMeta.setStars(42);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStatus(FetchStatus.IN_PROGRESS);
        // -> set last fetch older than RepoMetaConstants.TIME_SPAN_HEALTH_META (which is 3 days)
        healthMeta.setLastFetch(Date.from(Instant.now().minus(4, ChronoUnit.DAYS)));
        qm.createHealthMetaComponent(healthMeta);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent healthMetaComponent = handler.handle();

        assertEventRecordsAndFetchStatus(uuid, healthMetaComponent);
    }

    @Test
    public void testHandleHealthWhenCurrentMetadataExists() throws MalformedPackageURLException {
        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // persist
        var healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(TEST_PURL);
        healthMeta.setStars(42);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStatus(FetchStatus.PROCESSED);
        // -> set last fetch significantly younger than RepoMetaConstants.TIME_SPAN_HEALTH_META (which is 3 days)
        healthMeta.setLastFetch(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        qm.createHealthMetaComponent(healthMeta);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent healthMetaComponent = handler.handle();
        assertThat(kafkaMockProducer.history()).isEmpty();
        Assertions.assertEquals(FetchStatus.PROCESSED, healthMetaComponent.getStatus());
    }
}