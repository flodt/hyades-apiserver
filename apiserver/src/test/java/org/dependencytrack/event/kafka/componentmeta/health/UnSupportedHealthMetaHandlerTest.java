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
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.event.kafka.componentmeta.Handler;
import org.dependencytrack.event.kafka.componentmeta.HandlerFactory;
import org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class UnSupportedHealthMetaHandlerTest extends PersistenceCapableTest {
    private static final String TEST_PURL = "pkg:hex/jason@1.1.2";

    @Test
    public void testHandleHealthComponentNotInDB() throws MalformedPackageURLException {
        assertThat(RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_HEALTH_CHECK)
                .withFailMessage("Test PURL type hex is actually supported, test assumption invalid")
                .doesNotContain("hex");

        Handler<HealthMetaComponent> handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL(TEST_PURL);
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);

        // is not in database before
        HealthMetaComponent healthMetaComponent = qm.getHealthMetaComponent(componentProjection.purl().toString());
        Assertions.assertNull(healthMetaComponent);

        handler = HandlerFactory.createHealthMetaHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_HEALTH);
        HealthMetaComponent result = handler.handle();

        // no events and nothing in DB after, as we don't support this
        assertThat(kafkaMockProducer.history()).isEmpty();
        assertThat(result).isNull();
        assertThat(qm.getHealthMetaComponent(componentProjection.purl().toString())).isNull();
    }
}