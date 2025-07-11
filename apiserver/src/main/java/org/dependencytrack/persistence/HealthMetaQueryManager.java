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

package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.HealthMetaComponent;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Instant;
import java.util.Date;

public class HealthMetaQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(HealthMetaQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    HealthMetaQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    HealthMetaQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    @Override
    public HealthMetaComponent getHealthMetaComponent(String purl) {
        final Query<HealthMetaComponent> q = pm.newQuery(HealthMetaComponent.class, "purl == :purl");
        q.setParameters(purl);
        return q.executeUnique();
    }

    @Override
    public synchronized HealthMetaComponent updateHealthMetaComponent(HealthMetaComponent transientHealthMetaComponent) {
        final HealthMetaComponent healthMeta = getHealthMetaComponent(transientHealthMetaComponent.getPurl());
        if (healthMeta != null) {
            healthMeta.setStars(transientHealthMetaComponent.getStars());
            healthMeta.setForks(transientHealthMetaComponent.getForks());
            healthMeta.setContributors(transientHealthMetaComponent.getContributors());
            healthMeta.setCommitFrequencyWeekly(transientHealthMetaComponent.getCommitFrequencyWeekly());
            healthMeta.setOpenIssues(transientHealthMetaComponent.getOpenIssues());
            healthMeta.setOpenPRs(transientHealthMetaComponent.getOpenPRs());
            healthMeta.setLastCommit(transientHealthMetaComponent.getLastCommit());
            healthMeta.setBusFactor(transientHealthMetaComponent.getBusFactor());
            healthMeta.setHasReadme(transientHealthMetaComponent.getHasReadme());
            healthMeta.setHasCodeOfConduct(transientHealthMetaComponent.getHasCodeOfConduct());
            healthMeta.setHasSecurityPolicy(transientHealthMetaComponent.getHasSecurityPolicy());
            healthMeta.setDependents(transientHealthMetaComponent.getDependents());
            healthMeta.setFiles(transientHealthMetaComponent.getFiles());
            healthMeta.setRepoArchived(transientHealthMetaComponent.getRepoArchived());
            healthMeta.setScorecardScore(transientHealthMetaComponent.getScorecardScore());
            healthMeta.setScorecardReferenceVersion(transientHealthMetaComponent.getScorecardReferenceVersion());
            healthMeta.setScorecardTimestamp(transientHealthMetaComponent.getScorecardTimestamp());
            healthMeta.setScorecardChecksJson(transientHealthMetaComponent.getScorecardChecksJson());
            healthMeta.setStatus(transientHealthMetaComponent.getStatus());
            healthMeta.setLastFetch(Date.from(Instant.now()));
            healthMeta.setAvgIssueAgeDays(transientHealthMetaComponent.getAvgIssueAgeDays());
            return persist(healthMeta);
        } else {
            LOGGER.debug("No record found in HealthMetaComponent for purl " + transientHealthMetaComponent.getPurl());
            return null;
        }
    }

    @Override
    public HealthMetaComponent createHealthMetaComponent(HealthMetaComponent healthMetaComponent) {
        return persist(healthMetaComponent);
    }
}
