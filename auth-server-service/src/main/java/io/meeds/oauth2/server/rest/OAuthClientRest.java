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

import static io.meeds.oauth2.server.rest.util.EntityBuilder.fromClientRestEntity;
import static io.meeds.oauth2.server.rest.util.EntityBuilder.toClientRestEntity;

import java.security.Principal;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import org.exoplatform.commons.ObjectAlreadyExistsException;
import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.rest.model.OAuthClientRestEntity;
import io.meeds.oauth2.server.rest.util.EntityBuilder;
import io.meeds.oauth2.server.service.OAuthClientService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
@RequestMapping("/rest/clients")
public class OAuthClientRest {

  @Autowired
  private OAuthClientService oAuthClientService;

  @GetMapping
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve OAuth Clients. Only administrators will be able to access disabled Clients for administration purpose.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
  })
  public List<OAuthClientRestEntity> getClients(Principal principal,
                                                @RequestParam(name = "all", required = false, defaultValue = "false")
                                                boolean includeAll) {
    try {
      return oAuthClientService.getClients(principal.getName(), includeAll)
                               .stream()
                               .map(EntityBuilder::toClientRestEntity)
                               .filter(Objects::nonNull)
                               .toList();
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @GetMapping("/{clientId}")
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve OAuth Client by its id. Only administrators will be able to access disabled Clients for administration purpose.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public OAuthClientRestEntity getClient(Principal principal,
                                         @PathVariable("clientId")
                                         String clientId,
                                         @RequestParam(name = "all", required = false, defaultValue = "false")
                                         boolean includeAll) {
    try {
      RegisteredClient client = oAuthClientService.getClient(clientId, includeAll, principal.getName());
      OAuthClientRestEntity clientRestEntity = toClientRestEntity(client);
      if (clientRestEntity == null) {
        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
      } else {
        return clientRestEntity;
      }
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @GetMapping("by-param")
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve OAuth Client by its id in a query param when the path param can't be used such as with CIMD Client Id using URL format. Only administrators will be able to access disabled Clients for administration purpose.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public OAuthClientRestEntity getClientByParam(Principal principal,
                                                @RequestParam("clientId")
                                                String clientId,
                                                @RequestParam(name = "all", required = false, defaultValue = "false")
                                                boolean includeAll) {
    return getClient(principal, clientId, includeAll);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "POST", summary = "Creates a new OAuth Client")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
    @ApiResponse(responseCode = "409", description = "Conflict"),
  })
  public OAuthClientRestEntity createClient(
                                            @RequestBody
                                            OAuthClientRestEntity oAuthClient) {
    try {
      RegisteredClient client = fromClientRestEntity(oAuthClient);
      RegisteredClient createdClient = oAuthClientService.createClient(client);
      return toClientRestEntity(createdClient);
    } catch (ObjectAlreadyExistsException e) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
    }
  }

  @DeleteMapping("/{clientId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Deletes an OAuth Client by its id")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void deleteClient(
                           @PathVariable("clientId")
                           String clientId) {
    try {
      oAuthClientService.deleteClient(clientId);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/name", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client name")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientRedirectName(
                                       @PathVariable("clientId")
                                       String clientId,
                                       @RequestParam("name")
                                       String name) {
    try {
      oAuthClientService.updateClientName(clientId, name);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/url", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client website url information")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientUrl(
                              @PathVariable("clientId")
                              String clientId,
                              @RequestParam("url")
                              String url) {
    try {
      oAuthClientService.updateClientUrl(clientId, url);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/logo-url", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client logo url information")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientLogoUrl(
                                  @PathVariable("clientId")
                                  String clientId,
                                  @RequestParam("logoUrl")
                                  String logoUrl) {
    try {
      oAuthClientService.updateClientLogoUrl(clientId, logoUrl);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/uris", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client redirect URIs")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientRedirectUris(
                                       @PathVariable("clientId")
                                       String clientId,
                                       @RequestParam("redirectUri")
                                       Set<String> redirectUris) {
    try {
      oAuthClientService.updateClientRedirectUris(clientId, redirectUris);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/scopes", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client enabled scopes")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientScopes(
                                 @PathVariable("clientId")
                                 String clientId,
                                 @RequestParam("scope")
                                 Set<String> scopes) {
    try {
      oAuthClientService.updateClientScopes(clientId, scopes);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/display", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client public visibility")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientVisibility(
                                     @PathVariable("clientId")
                                     String clientId,
                                     @RequestParam("displayed")
                                     boolean displayed) {
    try {
      oAuthClientService.updateClientVisibility(clientId, displayed);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

  @PatchMapping(path = "/{clientId}/enable", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Updates an OAuth Client enablement")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "204", description = "Request fulfilled"),
    @ApiResponse(responseCode = "403", description = "Forbidden"),
    @ApiResponse(responseCode = "404", description = "Not found"),
  })
  public void updateClientActivation(
                                     @PathVariable("clientId")
                                     String clientId,
                                     @RequestParam("enabled")
                                     boolean enabled) {
    try {
      oAuthClientService.updateClientActivation(clientId, enabled);
    } catch (ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
    } catch (IllegalAccessException e) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage());
    }
  }

}
