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

package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ComponentHealthResourceTest extends ResourceTest {
    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ComponentHealthResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
    );

    @Test
    public void testGetHealthByValidUuid() {
        final float TEST_SCORECARD_SCORE = 10.0f;
        final int TEST_STARS = 39;
        final int TEST_FORKS = 12;

        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurlCoordinates("pkg:maven/org.http4s/blaze-core_2.12");
        component = qm.createComponent(component, false);

        HealthMetaComponent healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(component.getPurlCoordinates().toString());
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardScore(TEST_SCORECARD_SCORE);
        healthMeta.setStars(TEST_STARS);
        healthMeta.setForks(TEST_FORKS);
        qm.createHealthMetaComponent(healthMeta);

        Response response = jersey
                .target(V1_COMPONENT + "/" + component.getUuid() + "/health")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("purlCoordinates")).isEqualTo(component.getPurlCoordinates().toString());
        assertThat(json.getJsonNumber("scorecardScore").doubleValue()).isEqualTo(TEST_SCORECARD_SCORE);
        assertThat(json.getJsonNumber("stars").intValue()).isEqualTo(TEST_STARS);
        assertThat(json.getJsonNumber("forks").intValue()).isEqualTo(TEST_FORKS);
    }

    @Test
    public void testGetHealthByNonExistentUuid() {
        UUID uuid = UUID.randomUUID();

        Response response = jersey
                .target(V1_COMPONENT + "/" + uuid + "/health")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.readEntity(String.class)).isEqualTo("The component could not be found");
    }

    @Test
    public void testGetHealthByValidUuidButNoHealthMeta() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurlCoordinates("pkg:maven/org.http4s/blaze-core_2.12");
        component = qm.createComponent(component, false);

        Response response = jersey
                .target(V1_COMPONENT + "/" + component.getUuid() + "/health")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.readEntity(String.class))
                .isEqualTo("The component's health metadata could not be found");
    }

    @Test
    public void testGetHealthByValidUuidAcl() {
        enablePortfolioAccessControl();

        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurlCoordinates("pkg:maven/org.http4s/blaze-core_2.12");
        component = qm.createComponent(component, false);

        HealthMetaComponent healthMeta = new HealthMetaComponent();
        healthMeta.setPurlCoordinates(component.getPurlCoordinates().toString());
        healthMeta.setStatus(FetchStatus.PROCESSED);
        healthMeta.setScorecardScore(10.0f);
        healthMeta.setStars(39);
        healthMeta.setForks(12);
        qm.createHealthMetaComponent(healthMeta);

        final Component finalComponent = component;
        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + finalComponent.getUuid() + "/health")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response noPermResponse = responseSupplier.get();
        assertThat(noPermResponse.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(noPermResponse)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        Response allowedResponse = responseSupplier.get();
        assertThat(allowedResponse.getStatus()).isEqualTo(200);
    }
}