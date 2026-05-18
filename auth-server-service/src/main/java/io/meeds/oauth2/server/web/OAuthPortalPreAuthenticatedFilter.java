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
package io.meeds.oauth2.server.web;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.authentication.jaas.JaasGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.jaas.UserPrincipal;

import io.meeds.oauth2.server.security.OAuthPortalAuthenticationProvider;

import jakarta.servlet.http.HttpServletRequest;

public class OAuthPortalPreAuthenticatedFilter extends AbstractPreAuthenticatedProcessingFilter {

  private static final String               PLACEHOLDER_PASSWORD = UUID.randomUUID().toString();

  private OAuthPortalAuthenticationProvider portalAuthenticationProvider;

  public OAuthPortalPreAuthenticatedFilter(OAuthPortalAuthenticationProvider portalAuthenticationProvider) {
    this.portalAuthenticationProvider = portalAuthenticationProvider;
  }

  @Override
  protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
    Identity identity = portalAuthenticationProvider.getCurrentIdentity(request);
    if (portalAuthenticationProvider.isAnonymousUser(identity)) {
      return null;
    } else {
      Principal userPrincipal = new UserPrincipal(identity.getUserId());
      List<GrantedAuthority> authorities = getAuthorities(identity, userPrincipal);
      authorities.add(FactorGrantedAuthority.withAuthority("FACTOR_PASSWORD")
                                            .issuedAt(Instant.now())
                                            .build());

      return new PreAuthenticatedAuthenticationToken(userPrincipal,
                                                     identity.getUserId(),
                                                     authorities);
    }
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return PLACEHOLDER_PASSWORD;
  }

  private List<GrantedAuthority> getAuthorities(Identity identity, Principal principal) {
    return identity.getRoles()
                   .stream()
                   .map(role -> (GrantedAuthority) new JaasGrantedAuthority(role, principal))
                   .collect(Collectors.toCollection(ArrayList::new));
  }

}
