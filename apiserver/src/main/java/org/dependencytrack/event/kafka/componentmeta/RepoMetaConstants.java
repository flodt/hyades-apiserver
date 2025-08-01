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

import com.github.packageurl.PackageURL;

import java.util.List;

public class RepoMetaConstants {

    // 1 hour
    public static final long TIME_SPAN_INTEGRITY_META = 60 * 60 * 1000L;

    // 10 days
    public static final long TIME_SPAN_HEALTH_META = 10 * 24 * 60 * 60 * 1000L;

    public static final List<String> SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK = List.of(
            PackageURL.StandardTypes.MAVEN,
            PackageURL.StandardTypes.NPM,
            PackageURL.StandardTypes.PYPI
    );

    /**
     * We can only support packages from sources that are supported by deps.dev.
     * These are as of 02-07-2025: npm, Go, Maven, PyPI, NuGet, Cargo, RubyGems
     */
    public static final List<String> SUPPORTED_PACKAGE_URLS_FOR_HEALTH_CHECK = List.of(
            PackageURL.StandardTypes.NPM,
            PackageURL.StandardTypes.GOLANG,
            PackageURL.StandardTypes.MAVEN,
            PackageURL.StandardTypes.PYPI,
            PackageURL.StandardTypes.NUGET,
            PackageURL.StandardTypes.CARGO,
            PackageURL.StandardTypes.GEM
    );
}