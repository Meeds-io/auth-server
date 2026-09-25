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
package io.meeds.oauth2.server.configuration.plugin;

import java.util.Set;

import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * Contributes the {@code authorities} claim of the access tokens the
 * authorization server issues. Providers are consulted in ascending
 * {@link #getOrder()}; the first non-empty answer becomes the claim and the
 * providers after it are not consulted. Refusing a token belongs to
 * {@link OAuthAccessTokenAudienceProvider}, whose providers are all consulted.
 */
@FunctionalInterface
public interface OAuthAccessTokenAuthorityProvider {

  /**
   * @param context the access token being issued
   * @return the authorities of the token, or null or empty to let another
   *         provider answer
   */
  Set<String> provideAuthorities(OAuth2TokenContext context);

  /**
   * @return this provider's position, lower values consulted first — the
   *         Spring {@link Ordered} convention
   */
  default int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

}
