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

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.HealthMetaComponent;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

/**
 * Endpoints for retrieving health metadata.
 */
@Path("/v1/component/{uuid}/health")
@Tag(name = "componentHealth")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ComponentHealthResource extends AbstractConfigPropertyResource {
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns health metadata for the specified component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Health metadata for the specified component",
                    content = @Content(schema = @Schema(implementation = HealthMetaComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found")

    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getHealth(
            @Parameter(
                    description = "The UUID of the component to retrieve health metadata for",
                    schema = @Schema(type = "string", format = "uuid"),
                    required = true
            )
            @PathParam("uuid")
            @ValidUuid
            String uuid
    ) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null && component.getPurl() != null) {
                requireAccess(qm, component.getProject());

                HealthMetaComponent healthMetaComponent = qm.getHealthMetaComponent(component.getPurlCoordinates().toString());

                if (healthMetaComponent != null) {
                    return Response.ok(healthMetaComponent).build();
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The component's health metadata could not be found")
                            .build();
                }
            } else {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The component could not be found")
                        .build();
            }
        }
    }
}
