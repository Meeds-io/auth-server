/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package io.meeds.oauth2.server.rest;

import java.security.Principal;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.service.OAuthConsentService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
@RequestMapping("/rest/consents")
public class OAuthConsentRest {

  @Autowired
  private OAuthConsentService oAuthConsentService;

  @GetMapping
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve consented OAuth clients by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public List<OAuthConsent> getConsents(Principal principal) {
    return oAuthConsentService.getConsentsByUser(principal.getName());
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("users")
  @Operation(method = "DELETE", summary = "Delete all consented OAuth clients by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
  })
  public void deleteConsentsByUser(Principal principal) {
    oAuthConsentService.deleteConsentsByUser(principal.getName());
  }

  @DeleteMapping("/{clientId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("users")
  @Operation(method = "DELETE", summary = "Delete a previously consented OAuth client by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
  })
  public void deleteConsentByUserAndClient(Principal principal,
                                           @PathVariable("clientId")
                                           String clientId) {
    oAuthConsentService.deleteConsentByUserAndClient(principal.getName(), clientId);
  }

  @DeleteMapping("/{clientId}/all")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Delete all consented OAuth clients by all users.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
  })
  public void deleteConsentsByClient(
                                     @PathVariable("clientId")
                                     String clientId) {
    oAuthConsentService.deleteConsentsByClient(clientId);
  }

}
