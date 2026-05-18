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

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Override default in order to allow using DCR with empty scopes
 */
@Component
public class OAuthDcrHttpAuthenticationConverter {

  @Autowired
  private OAuthDcrHttpMessageConverter oAuthDcrHttpMessageConverter;

  public AuthenticationConverter converter() {
    return request -> {
      Authentication principal = SecurityContextHolder.getContext().getAuthentication();
      if ("POST".equals(request.getMethod())) {
        OidcClientRegistration clientRegistration;
        try {
          clientRegistration = this.oAuthDcrHttpMessageConverter.read(OidcClientRegistration.class,
                                                                      new ServletServerHttpRequest(request));
        } catch (Exception ex) {
          OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                                              "OpenID Client Registration Error: " + ex.getMessage(),
                                              "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError");
          throw new OAuth2AuthenticationException(error, ex);
        }
        return new OidcClientRegistrationAuthenticationToken(principal, clientRegistration);
      } else {
        MultiValueMap<String, String> parameters = getQueryParameters(request);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
          throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new OidcClientRegistrationAuthenticationToken(principal, clientId);
      }
    };
  }

  private MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
    Map<String, String[]> parameterMap = request.getParameterMap();
    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
    parameterMap.forEach((key, values) -> {
      String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
      if (queryString.contains(key) && values.length > 0) {
        for (String value : values) {
          parameters.add(key, value);
        }
      }
    });
    return parameters;
  }

}
