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

import static io.meeds.oauth2.server.rest.util.EntityBuilder.decodeBase64;

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
import org.springframework.web.server.ResponseStatusException;

import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.model.OAuthAccessToken;
import io.meeds.oauth2.server.service.OAuthTokenService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
@RequestMapping("/rest/tokens")
public class OAuthTokenRest {

  @Autowired
  private OAuthTokenService oAuthTokenService;

  @GetMapping
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve all OAuth Tokens for a given user")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public List<OAuthAccessToken> getTokens(Principal principal) {
    return oAuthTokenService.getTokensByUser(principal.getName());
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("users")
  @Operation(method = "DELETE", summary = "Delete an OAuth Token by id")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void deleteTokenById(Principal principal,
                              @PathVariable("id")
                              String tokenId) {
    try {
      oAuthTokenService.deleteTokenById(tokenId, principal.getName());
    } catch (IllegalAccessException | ObjectNotFoundException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
  }

  @DeleteMapping("/byClient/{clientId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Delete all OAuth Tokens for a given client")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void deleteTokensByClient(
                                   @PathVariable("clientId")
                                   String clientId) {
    oAuthTokenService.deleteTokensByClient(decodeBase64(clientId));
  }

  @DeleteMapping("/byClient/{clientId}/{username}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Delete all OAuth Tokens for a given client and user")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void deleteTokensByUserAndClient(
                                          @PathVariable("username")
                                          String username,
                                          @PathVariable("clientId")
                                          String clientId) {
    oAuthTokenService.deleteTokensByUserAndClient(username, decodeBase64(clientId));
  }

}
