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

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import io.meeds.oauth2.server.service.OAuthSettingService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
@RequestMapping("/rest/settings")
public class OAuthSettingRest {

  @Autowired
  private OAuthSettingService oAuthSettingService;

  @GetMapping("scopes")
  @Secured("users")
  @Operation(method = "GET", summary = "Retrieve available scopes from OAuth server")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public Set<String> getScopes() {
    return oAuthSettingService.getScopes();
  }

  @GetMapping("issuer-url")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Retrieve available OAuth server issuer URL")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public String getIssuerUrl() {
    return oAuthSettingService.getIssuerUrl();
  }

  @GetMapping("allowed-redirect-uris")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Retrieve OAuth server alllowed DCR Redirect URIs")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public List<String> getAllowedRedirectUris() {
    return oAuthSettingService.getAllowedRedirectUris();
  }

  @GetMapping("allowed-cimd-uris")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Retrieve OAuth server alllowed CIMD URIs")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public List<String> getAllowedCimdUris() {
    return oAuthSettingService.getAllowedCimdUris();
  }

  @GetMapping("allowed-origins")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Retrieve OAuth server alllowed HTTP Cors Origin Header")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public List<String> getAllowedOrigins() {
    return oAuthSettingService.getAllowedOrigins();
  }

  @GetMapping("allowed-redirect-uris/all")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Return 'true' if the OAuth server allows all DCR Redirect URIs, else 'false'")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public boolean isAllowAllRedirectUris() {
    return oAuthSettingService.isAllowAllRedirectUris();
  }

  @GetMapping("allowed-cimd-uris/all")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Return 'true' if the OAuth server allows all CIMD URIs, else 'false'")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public boolean isAllowAllCimdUris() {
    return oAuthSettingService.isAllowAllCimdUris();
  }

  @GetMapping("allowed-origins/all")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Return 'true' if the OAuth server allows all Cors HTTP Origin URLs, else 'false'")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public boolean isAllowAllOrigins() {
    return oAuthSettingService.isAllowAllOrigins();
  }

  @GetMapping("public-client-settings")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Return OAuth server default public client settings")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public ClientSettings getPublicClientSettings() {
    return oAuthSettingService.getPublicClientSettings();
  }

  @GetMapping("public-token-settings")
  @Secured("administrators")
  @Operation(method = "GET", summary = "Return OAuth server default public client token settings")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public TokenSettings getPublicClientTokenSettings() {
    return oAuthSettingService.getPublicClientTokenSettings();
  }

  @PatchMapping(path = "allowed-redirect-uris/all", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Retrieve consented OAuth clients by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void setAllowAllRedirectUris(
                                      @RequestParam("allowAll")
                                      boolean allowAll) {
    oAuthSettingService.setAllowAllRedirectUris(allowAll);
  }

  @PatchMapping(path = "allowed-cimd-uris/all", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Retrieve consented OAuth clients by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void setAllowAllCimdUris(
                                  @RequestParam("allowAll")
                                  boolean allowAll) {
    oAuthSettingService.setAllowAllCimdUris(allowAll);
  }

  @PatchMapping(path = "allowed-origins/all", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "PATCH", summary = "Retrieve consented OAuth clients by current user.")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void setAllowAllOrigins(
                                 @RequestParam("allowAll")
                                 boolean allowAll) {
    oAuthSettingService.setAllowAllOrigins(allowAll);
  }

  @PostMapping(path = "allowed-redirect-uris", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "POST", summary = "Add a new Allowed DCR Client Redirect URI")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void addAllowedRedirectUri(
                                    @RequestParam("uri")
                                    String redirectUriPrefix) {
    try {
      oAuthSettingService.addAllowedRedirectUri(redirectUriPrefix);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @PostMapping(path = "allowed-cimd-uris", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "POST", summary = "Add a new Allowed CIMD URI")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void addAllowedCimdUri(
                                @RequestParam("uri")
                                String cimdUriPrefix) {
    try {
      oAuthSettingService.addAllowedCimdUri(cimdUriPrefix);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @PostMapping(path = "allowed-origins", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "POST", summary = "Add a new Allowed Cors Origin URL")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void addAllowedOrigin(
                               @RequestParam("origin")
                               String origin) {
    try {
      oAuthSettingService.addAllowedOrigin(origin);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @DeleteMapping(path = "allowed-redirect-uris", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Removes a previously allowed DCR Client Redirect URI")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void removeAllowedRedirectUri(
                                       @RequestParam("uri")
                                       String uri) {
    oAuthSettingService.removeAllowedRedirectUri(uri);
  }

  @DeleteMapping(path = "allowed-cimd-uris", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Removes a previously allowed CIMD URI")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void removeAllowedCimdUri(
                                   @RequestParam("uri")
                                   String uri) {
    oAuthSettingService.removeAllowedCimdUri(uri);
  }

  @DeleteMapping(path = "allowed-origins", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Secured("administrators")
  @Operation(method = "DELETE", summary = "Removes a previously allowed Cors Origin URL")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "Request fulfilled"),
  })
  public void removeAllowedOrigin(
                                  @RequestParam("origin")
                                  String origin) {
    oAuthSettingService.removeAllowedOrigin(origin);
  }

}
