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
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.AbstractMetaHandler;
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

public class UnSupportedHealthMetaHandler extends AbstractMetaHandler<HealthMetaComponent> {
    public UnSupportedHealthMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        super(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
    }

    @Override
    public HealthMetaComponent handle() throws MalformedPackageURLException {
        // TODO: can we do anything sensible in this case? fallback to other data sources?
        return null;
    }
}
