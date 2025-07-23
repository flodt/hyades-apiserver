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
    @MappedField(protoFieldName = "purlCoordinates", sqlColumnName = "PURL_COORDINATES")
    public String purlCoordinates;
    
    @MappedField(protoFieldName = "stars", sqlColumnName = "STARS")
    public Integer stars;

    @MappedField(protoFieldName = "forks", sqlColumnName = "FORKS")
    public Integer forks;

    @MappedField(protoFieldName = "contributors", sqlColumnName = "CONTRIBUTORS")
    public Integer contributors;

    @MappedField(protoFieldName = "commitFrequencyWeekly", sqlColumnName = "COMMIT_FREQUENCY_WEEKLY")
    public Float commitFrequencyWeekly;

    @MappedField(protoFieldName = "openIssues", sqlColumnName = "OPEN_ISSUES")
    public Integer openIssues;

    @MappedField(protoFieldName = "openPRs", sqlColumnName = "OPEN_PRS")
    public Integer openPRs;

    @MappedField(protoFieldName = "lastCommitDate", sqlColumnName = "LAST_COMMIT")
    public Date lastCommit;

    @MappedField(protoFieldName = "busFactor", sqlColumnName = "BUS_FACTOR")
    public Integer busFactor;

    @MappedField(protoFieldName = "hasReadme", sqlColumnName = "HAS_README")
    public Boolean hasReadme;

    @MappedField(protoFieldName = "hasCodeOfConduct", sqlColumnName = "HAS_CODE_OF_CONDUCT")
    public Boolean hasCodeOfConduct;

    @MappedField(protoFieldName = "hasSecurityPolicy", sqlColumnName = "HAS_SECURITY_POLICY")
    public Boolean hasSecurityPolicy;

    @MappedField(protoFieldName = "dependents", sqlColumnName = "DEPENDENTS")
    public Integer dependents;

    @MappedField(protoFieldName = "files", sqlColumnName = "FILES")
    public Integer files;

    @MappedField(protoFieldName = "isRepoArchived", sqlColumnName = "IS_REPO_ARCHIVED")
    public Boolean isRepoArchived;

    @MappedField(protoFieldName = "scoreCardScore", sqlColumnName = "SCORECARD_SCORE")
    public Float scorecardScore;

    @MappedField(protoFieldName = "scoreCardReferenceVersion", sqlColumnName = "SCORECARD_REF_VERSION")
    public String scorecardReferenceVersion;

    @MappedField(protoFieldName = "scoreCardTimestamp", sqlColumnName = "SCORECARD_TIMESTAMP")
    public Date scorecardTimestamp;

    @MappedField(protoFieldName = "avgIssueAgeDays", sqlColumnName = "AVG_ISSUE_AGE_DAYS")
    public Float avgIssueAgeDays;

    // Special case: we want those unpacked, so they don't get directly mapped to a proto field name.
    @MappedField(sqlColumnName = "SCORECARD_CHECKS_JSON")
    public String scoreCardChecksJson;
}
