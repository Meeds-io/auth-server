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

import java.util.UUID;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import org.exoplatform.services.security.Identity;

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
    Identity currentIdentity = portalAuthenticationProvider.getCurrentIdentity(request);
    if (portalAuthenticationProvider.isAnonymousUser(currentIdentity)) {
      return null;
    } else {
      return currentIdentity.getUserId();
    }
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return PLACEHOLDER_PASSWORD;
  }

}
