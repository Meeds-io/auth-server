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

import java.util.List;

import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * Contributes the {@code aud} claim of the access tokens the authorization
 * server issues. Providers are consulted in ascending {@link #getOrder()}; the
 * first non-empty answer becomes the claim.
 */
@FunctionalInterface
public interface OAuthAccessTokenAudienceProvider {

  /**
   * @param context the access token being issued
   * @return the audiences of the token, or null or empty to let another
   *         provider answer
   * @throws org.springframework.security.oauth2.core.OAuth2AuthenticationException
   *           to refuse the token outright. Every provider is consulted for
   *           every token, so a refusal holds whatever the provider's order and
   *           whether or not another provider has already answered.
   */
  List<String> provideAudiences(OAuth2TokenContext context);

  /**
   * @return this provider's position, lower values consulted first — the
   *         Spring {@link Ordered} convention. It decides which answer becomes
   *         the claim, never whether a refusal is heard.
   */
  default int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

}
