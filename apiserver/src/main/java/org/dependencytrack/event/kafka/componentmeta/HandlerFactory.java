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
package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.health.SupportedHealthMetaHandler;
import org.dependencytrack.event.kafka.componentmeta.health.UnSupportedHealthMetaHandler;
import org.dependencytrack.event.kafka.componentmeta.integrity.SupportedIntegrityMetaHandler;
import org.dependencytrack.event.kafka.componentmeta.integrity.UnSupportedIntegrityMetaHandler;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

public class HandlerFactory {
    public static Handler<HealthMetaComponent> createHealthMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        boolean result = RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_HEALTH_CHECK.contains(componentProjection.purl().getType());
        if (result) {
            return new SupportedHealthMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
        } else {
            return new UnSupportedHealthMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
        }
    }

    public static Handler<IntegrityMetaComponent> createIntegrityMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) throws MalformedPackageURLException {
        boolean result = RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(componentProjection.purl().getType());
        if (result) {
            return new SupportedIntegrityMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
        } else {
            return new UnSupportedIntegrityMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, FetchMeta.FETCH_META_LATEST_VERSION);
        }
    }
}