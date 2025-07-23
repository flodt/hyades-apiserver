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

package org.dependencytrack.policy.cel.persistence;

import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.proto.policy.v1.HealthMeta;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class CelPolicyHealthMetaRowMapper implements RowMapper<HealthMeta> {
    @Override
    public HealthMeta map(ResultSet rs, StatementContext ctx) throws SQLException {
        final HealthMeta.Builder builder = HealthMeta.newBuilder();
        maybeSet(rs, "purlCoordinates", ResultSet::getString, builder::setPurlCoordinates);
        maybeSet(rs, "stars", ResultSet::getInt, builder::setStars);
        maybeSet(rs, "forks", ResultSet::getInt, builder::setForks);
        maybeSet(rs, "contributors", ResultSet::getInt, builder::setContributors);
        maybeSet(rs, "commitFrequencyWeekly", ResultSet::getFloat, builder::setCommitFrequencyWeekly);
        maybeSet(rs, "openIssues", ResultSet::getInt, builder::setOpenIssues);
        maybeSet(rs, "openPRs", ResultSet::getInt, builder::setOpenPRs);
        maybeSet(rs, "lastCommitDate", RowMapperUtil::nullableTimestamp, builder::setLastCommitDate);
        maybeSet(rs, "busFactor", ResultSet::getInt, builder::setBusFactor);
        maybeSet(rs, "hasReadme", ResultSet::getBoolean, builder::setHasReadme);
        maybeSet(rs, "hasCodeOfConduct", ResultSet::getBoolean, builder::setHasCodeOfConduct);
        maybeSet(rs, "hasSecurityPolicy", ResultSet::getBoolean, builder::setHasSecurityPolicy);
        maybeSet(rs, "dependents", ResultSet::getInt, builder::setDependents);
        maybeSet(rs, "files", ResultSet::getInt, builder::setFiles);
        maybeSet(rs, "isRepoArchived", ResultSet::getBoolean, builder::setIsRepoArchived);
        maybeSet(rs, "scoreCardScore", ResultSet::getFloat, builder::setScoreCardScore);
        maybeSet(rs, "scoreCardReferenceVersion", ResultSet::getString, builder::setScoreCardReferenceVersion);
        maybeSet(rs, "scoreCardTimestamp", RowMapperUtil::nullableTimestamp, builder::setScoreCardTimestamp);
        maybeSet(rs, "avgIssueAgeDays", ResultSet::getFloat, builder::setAvgIssueAgeDays);
        return builder.build();
    }
}
