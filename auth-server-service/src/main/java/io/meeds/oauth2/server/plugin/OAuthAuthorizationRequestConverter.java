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
package io.meeds.oauth2.server.plugin;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.service.OAuthClientService;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class OAuthAuthorizationRequestConverter implements AuthenticationConverter {

  private final AuthenticationConverter delegate = new OAuth2AuthorizationCodeRequestAuthenticationConverter();

  @Autowired
  private OAuthClientService            oAuthClientService;

  @Override
  public Authentication convert(HttpServletRequest request) {
    Authentication authentication = delegate.convert(request);
    if (!(authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token)) {
      return authentication;
    }
    Set<String> requestedScopes = token.getScopes();
    if (requestedScopes != null && !requestedScopes.isEmpty()) {
      return token;
    }
    RegisteredClient cClient = oAuthClientService.getClient(token.getClientId());
    if (cClient == null) {
      return token;
    }
    Set<String> defaultScopes = new LinkedHashSet<>(cClient.getScopes());
    return new OAuth2AuthorizationCodeRequestAuthenticationToken(token.getAuthorizationUri(),
                                                                 token.getClientId(),
                                                                 (Authentication) token.getPrincipal(),
                                                                 token.getRedirectUri(),
                                                                 token.getState(),
                                                                 defaultScopes,
                                                                 token.getAdditionalParameters());
  }

}
