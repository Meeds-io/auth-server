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
package io.meeds.oauth2.server.service;

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Service;

import org.exoplatform.container.PortalContainer;

import io.meeds.oauth2.server.configuration.plugin.OAuthJwtAudienceProvider;
import io.meeds.oauth2.server.configuration.plugin.OAuthJwtAuthorityProvider;

import jakarta.annotation.PostConstruct;

@Service
public class OAuthJwtCustomizerService {

  @Autowired
  private PortalContainer                 portalContainer;

  private List<OAuthJwtAudienceProvider>  audienceProviders;

  private List<OAuthJwtAuthorityProvider> authorityProviders;

  @PostConstruct
  public void init() {
    this.audienceProviders = new ArrayList<>(portalContainer.getComponentInstancesOfType(OAuthJwtAudienceProvider.class));
    this.audienceProviders.sort((p1, p2) -> p1.getOrder() - p2.getOrder());
    this.authorityProviders = new ArrayList<>(portalContainer.getComponentInstancesOfType(OAuthJwtAuthorityProvider.class));
    this.authorityProviders.sort((p1, p2) -> p1.getOrder() - p2.getOrder());
  }

  public void addProvider(OAuthJwtAudienceProvider audienceProvider) {
    this.audienceProviders.add(audienceProvider);
    this.audienceProviders.sort((p1, p2) -> p1.getOrder() - p2.getOrder());
  }

  public void addProvider(OAuthJwtAuthorityProvider authorityProvider) {
    this.authorityProviders.add(authorityProvider);
    this.authorityProviders.sort((p1, p2) -> p1.getOrder() - p2.getOrder());
  }

  public void customizeAccessTokenClaims(JwtEncodingContext context) {
    if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      return;
    }
    RegisteredClient client = context.getRegisteredClient();
    boolean serviceToken = client.getClientSettings().getSetting(CLIENT_SERVICE_SETTING) != null
                           && Boolean.parseBoolean(client.getClientSettings()
                                                         .getSetting(CLIENT_SERVICE_SETTING)
                                                         .toString());

    JwtClaimsSet.Builder claims = context.getClaims();
    claims.claim("client_id", client.getClientId());
    claims.claim("azp", client.getClientId());
    claims.claim("grant_type", context.getAuthorizationGrantType().getValue());
    claims.claim("scope", context.getAuthorizedScopes());
    claims.claim("token_kind", serviceToken ? "service" : "user");
    if (context.getPrincipal() != null) {
      claims.subject(context.getPrincipal().getName());
    }
    Set<String> roles = computeJwtAuthorities(context);
    if (roles != null) {
      claims.claim("authorities", new HashSet<>(roles));
    }
    List<String> audiences = computeJwtAudiences(context);
    if (audiences != null) {
      claims.audience(new ArrayList<>(audiences));
    }
  }

  private List<String> computeJwtAudiences(JwtEncodingContext context) {
    return audienceProviders.stream()
                            .map(p -> p.provideAudiences(context))
                            .filter(CollectionUtils::isNotEmpty)
                            .findFirst()
                            .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                                                                                                 "No valid audience provided",
                                                                                                 null)));
  }

  private Set<String> computeJwtAuthorities(JwtEncodingContext context) {
    return authorityProviders.stream()
                             .map(p -> p.provideAuthorities(context))
                             .filter(CollectionUtils::isNotEmpty)
                             .findFirst()
                             .orElse(null);
  }

}
