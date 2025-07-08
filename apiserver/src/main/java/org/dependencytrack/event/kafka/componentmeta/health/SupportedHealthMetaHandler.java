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
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.AbstractMetaHandler;
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.time.Instant;
import java.util.Date;

import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.TIME_SPAN_HEALTH_META;

public class SupportedHealthMetaHandler extends AbstractMetaHandler<HealthMetaComponent> {
    public SupportedHealthMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        super(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
    }

    private void dispatchEvent() {
        kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(
                componentProjection.componentUuid(),
                componentProjection.purl().canonicalize(),
                componentProjection.internal(),
                fetchMeta
        ));
    }

    private boolean lastFetchIsStale(HealthMetaComponent persistentHealthMeta) {
        return persistentHealthMeta.getLastFetch() != null
                && Date.from(Instant.now()).getTime() - persistentHealthMeta.getLastFetch().getTime() > TIME_SPAN_HEALTH_META;
    }

    @Override
    public HealthMetaComponent handle() throws MalformedPackageURLException {
        HealthMetaComponent persistentHealthMeta = queryManager.getHealthMetaComponent(componentProjection.purl().toString());

        // Case 1: don't have anything in the DB yet, trigger request and create new entry
        if (persistentHealthMeta == null) {
            HealthMetaComponent healthMetaComponent = queryManager
                    .createHealthMetaComponent(createHealthMetaComponent(componentProjection.purl().toString()));
            dispatchEvent();
            return healthMetaComponent;
        }

        boolean needsUpdate = false;

        // Case 2: Data exists but is stale (older than TIME_SPAN)
        boolean hasData = persistentHealthMeta.getStatus() == FetchStatus.PROCESSED
                || persistentHealthMeta.getStatus() == FetchStatus.NOT_AVAILABLE;
        boolean existingDataIsStale = lastFetchIsStale(persistentHealthMeta);
        if (hasData && existingDataIsStale) {
            needsUpdate = true;
        }

        // Case 3: Status is not present or fetch is stalled (running but stale)
        boolean noStatus = persistentHealthMeta.getStatus() == null;
        boolean hasStalled = persistentHealthMeta.getStatus() == FetchStatus.IN_PROGRESS
                && lastFetchIsStale(persistentHealthMeta);
        if (noStatus || hasStalled) {
            needsUpdate = true;
        }

        if (needsUpdate) {
            persistentHealthMeta.setStatus(FetchStatus.IN_PROGRESS);
            persistentHealthMeta.setLastFetch(Date.from(Instant.now()));
            persistentHealthMeta = queryManager.updateHealthMetaComponent(persistentHealthMeta);
            dispatchEvent();
        }

        return persistentHealthMeta;
    }
}
