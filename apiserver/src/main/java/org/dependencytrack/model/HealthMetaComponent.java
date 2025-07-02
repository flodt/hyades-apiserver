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

package org.dependencytrack.model;

import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.github.packageurl.validator.PackageURL;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

/**
 * Tracks health metadata about components sourced from external repositories
 */
@PersistenceCapable(table = "HEALTH_META_COMPONENT")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HealthMetaComponent implements Serializable {
    @Serial
    private static final long serialVersionUID = -671880241057005336L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "PURL", allowsNull = "false", jdbcType = "VARCHAR", length = 1024)
    @Index(name = "PURL_IDX")
    @Size(max = 1024)
    @PackageURL
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Unique
    @NotNull
    private String purl;

    @Persistent
    @Column(name = "STARS")
    private Integer stars;

    @Persistent
    @Column(name = "FORKS")
    private Integer forks;

    @Persistent
    @Column(name = "CONTRIBUTORS")
    private Integer contributors;

    @Persistent
    @Column(name = "COMMIT_FREQUENCY")
    private Float commitFrequency;

    @Persistent
    @Column(name = "OPEN_ISSUES")
    private Integer openIssues;

    @Persistent
    @Column(name = "OPEN_PRS")
    private Integer openPRs;

    @Persistent
    @Column(name = "LAST_COMMIT_DATE")
    private String lastCommitDate;

    @Persistent
    @Column(name = "BUS_FACTOR")
    private Integer busFactor;

    @Persistent
    @Column(name = "HAS_README")
    private Boolean hasReadme;

    @Persistent
    @Column(name = "HAS_CODE_OF_CONDUCT")
    private Boolean hasCodeOfConduct;

    @Persistent
    @Column(name = "HAS_SECURITY_POLICY")
    private Boolean hasSecurityPolicy;

    @Persistent
    @Column(name = "DEPENDENTS")
    private Integer dependents;

    @Persistent
    @Column(name = "FILES")
    private Integer files;

    @Persistent
    @Column(name = "IS_REPO_ARCHIVED")
    private Boolean isRepoArchived;

    @Persistent
    @Column(name = "SCORECARD_SCORE")
    private Float scorecardScore;

    @Persistent
    @Column(name = "SCORECARD_REF_VERSION")
    private String scorecardReferenceVersion;

    @Persistent
    @Column(name = "SCORECARD_TIMESTAMP")
    private Date scorecardTimestamp;

    /**
     * We're not storing the Scorecard Checks in the DB directly to avoid overcomplicating the schema.
     */
    @Persistent
    @Column(name = "SCORECARD_CHECKS_JSON", jdbcType = "CLOB")
    private String scorecardChecksJson;

    @Persistent
    @Column(name = "LAST_FETCH")
    private Date lastFetch;

    @Persistent
    @Column(name = "STATUS", allowsNull = "false")
    private FetchStatus status;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    @Schema(description = "Number of stars of the component's source code repository")
    public Integer getStars() {
        return stars;
    }

    public void setStars(Integer stars) {
        this.stars = stars;
    }

    @Schema(description = "Number of forks of the component's source code repository")
    public Integer getForks() {
        return forks;
    }

    public void setForks(Integer forks) {
        this.forks = forks;
    }

    @Schema(description = "Number of contributors of the component's source code repository")
    public Integer getContributors() {
        return contributors;
    }

    public void setContributors(Integer contributors) {
        this.contributors = contributors;
    }

    @Schema(description = "Commit frequency in component's source code repository")
    public Float getCommitFrequency() {
        return commitFrequency;
    }

    public void setCommitFrequency(Float commitFrequency) {
        this.commitFrequency = commitFrequency;
    }

    @Schema(description = "Number of open issues of the component's source code repository")
    public Integer getOpenIssues() {
        return openIssues;
    }

    public void setOpenIssues(Integer openIssues) {
        this.openIssues = openIssues;
    }

    @Schema(description = "Number of open pull requests of the component's source code repository")
    public Integer getOpenPRs() {
        return openPRs;
    }

    public void setOpenPRs(Integer openPRs) {
        this.openPRs = openPRs;
    }

    @Schema(description = "Date of last commit in component's source code repository")
    public String getLastCommitDate() {
        return lastCommitDate;
    }

    public void setLastCommitDate(String lastCommitDate) {
        this.lastCommitDate = lastCommitDate;
    }

    @Schema(description = "Bus Factor of contributors in the component's source code repository")
    public Integer getBusFactor() {
        return busFactor;
    }

    public void setBusFactor(Integer busFactor) {
        this.busFactor = busFactor;
    }

    @Schema(description = "Whether the repository has a README file")
    public Boolean getHasReadme() {
        return hasReadme;
    }

    public void setHasReadme(Boolean hasReadme) {
        this.hasReadme = hasReadme;
    }

    @Schema(description = "Whether the repository has a code of conduct")
    public Boolean getHasCodeOfConduct() {
        return hasCodeOfConduct;
    }

    public void setHasCodeOfConduct(Boolean hasCodeOfConduct) {
        this.hasCodeOfConduct = hasCodeOfConduct;
    }

    @Schema(description = "Whether the repository has a security policy")
    public Boolean getHasSecurityPolicy() {
        return hasSecurityPolicy;
    }

    public void setHasSecurityPolicy(Boolean hasSecurityPolicy) {
        this.hasSecurityPolicy = hasSecurityPolicy;
    }

    @Schema(description = "Number of other packages in repositories that depend on this package")
    public Integer getDependents() {
        return dependents;
    }

    public void setDependents(Integer dependents) {
        this.dependents = dependents;
    }

    @Schema(description = "Number of files in the component's source code repository")
    public Integer getFiles() {
        return files;
    }

    public void setFiles(Integer files) {
        this.files = files;
    }

    @Schema(description = "Whether the component's source code repository is archived")
    public Boolean getRepoArchived() {
        return isRepoArchived;
    }

    public void setRepoArchived(Boolean repoArchived) {
        isRepoArchived = repoArchived;
    }

    @Schema(description = "Overall OpenSSF Scorecard score of this component")
    public Float getScorecardScore() {
        return scorecardScore;
    }

    public void setScorecardScore(Float scorecardScore) {
        this.scorecardScore = scorecardScore;
    }

    @Schema(description = "Version of this component the OpenSSF Scorecard evaluation is based on")
    public String getScorecardReferenceVersion() {
        return scorecardReferenceVersion;
    }

    public void setScorecardReferenceVersion(String scorecardReferenceVersion) {
        this.scorecardReferenceVersion = scorecardReferenceVersion;
    }

    @Schema(description = "Evaluation timestamp of the OpenSSF Scorecard data")
    public Date getScorecardTimestamp() {
        return scorecardTimestamp;
    }

    public void setScorecardTimestamp(Date scorecardTimestamp) {
        this.scorecardTimestamp = scorecardTimestamp;
    }

    @Schema(description = "Full OpenSSF Scorecard check results")
    public String getScorecardChecksJson() {
        return scorecardChecksJson;
    }

    public void setScorecardChecksJson(String scorecardChecksJson) {
        this.scorecardChecksJson = scorecardChecksJson;
    }

    @Schema(description = "The last time health metadata was fetched")
    public Date getLastFetch() {
        return lastFetch;
    }

    public void setLastFetch(Date lastFetch) {
        this.lastFetch = lastFetch;
    }

    public FetchStatus getStatus() {
        return status;
    }

    public void setStatus(FetchStatus status) {
        this.status = status;
    }
}
