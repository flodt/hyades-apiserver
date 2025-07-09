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

package org.dependencytrack.policy.cel.mapping;

import java.util.Date;

public class HealthMetaProjection {
    public String purl;

    @MappedField(protoFieldName = "health_meta.stars", sqlColumnName = "STARS")
    public Integer stars;

    @MappedField(protoFieldName = "health_meta.forks", sqlColumnName = "FORKS")
    public Integer forks;

    @MappedField(protoFieldName = "health_meta.contributors", sqlColumnName = "CONTRIBUTORS")
    public Integer contributors;

    @MappedField(protoFieldName = "health_meta.commitFrequency", sqlColumnName = "COMMIT_FREQUENCY")
    public Float commitFrequency;

    @MappedField(protoFieldName = "health_meta.openIssues", sqlColumnName = "OPEN_ISSUES")
    public Integer openIssues;

    @MappedField(protoFieldName = "health_meta.openPRs", sqlColumnName = "OPEN_PRS")
    public Integer openPRs;

    @MappedField(protoFieldName = "health_meta.lastCommit", sqlColumnName = "LAST_COMMIT")
    public Date lastCommit;

    @MappedField(protoFieldName = "health_meta.busFactor", sqlColumnName = "BUS_FACTOR")
    public Integer busFactor;

    @MappedField(protoFieldName = "health_meta.hasReadme", sqlColumnName = "HAS_README")
    public Boolean hasReadme;

    @MappedField(protoFieldName = "health_meta.hasCodeOfConduct", sqlColumnName = "HAS_CODE_OF_CONDUCT")
    public Boolean hasCodeOfConduct;

    @MappedField(protoFieldName = "health_meta.hasSecurityPolicy", sqlColumnName = "HAS_SECURITY_POLICY")
    public Boolean hasSecurityPolicy;

    @MappedField(protoFieldName = "health_meta.dependents", sqlColumnName = "DEPENDENTS")
    public Integer dependents;

    @MappedField(protoFieldName = "health_meta.files", sqlColumnName = "FILES")
    public Integer files;

    @MappedField(protoFieldName = "health_meta.isRepoArchived", sqlColumnName = "IS_REPO_ARCHIVED")
    public Boolean isRepoArchived;

    @MappedField(protoFieldName = "health_meta.scorecardScore", sqlColumnName = "SCORECARD_SCORE")
    public Float scorecardScore;

    @MappedField(protoFieldName = "health_meta.scorecardReferenceVersion", sqlColumnName = "SCORECARD_REF_VERSION")
    public String scorecardReferenceVersion;

    @MappedField(protoFieldName = "health_meta.scorecardTimestamp", sqlColumnName = "SCORECARD_TIMESTAMP")
    public Date scorecardTimestamp;

    @MappedField(protoFieldName = "health_meta.lastFetch", sqlColumnName = "LAST_FETCH")
    public Date lastFetch;
}
