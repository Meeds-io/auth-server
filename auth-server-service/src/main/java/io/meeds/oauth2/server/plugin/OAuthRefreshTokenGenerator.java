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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_DCR_SETTING;

import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.util.Utils;

@Component
public final class OAuthRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

  private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(),
                                                                                        96);

  @Value("${meeds.oauth.allow_public_refresh_tokens:true}")
  private boolean                  allowPublicRefreshTokens;

  @Override
  public OAuth2RefreshToken generate(OAuth2TokenContext context) {
    if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
      return null;
    }
    RegisteredClient client = context.getRegisteredClient();
    boolean isPublicClient = Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING), true)
                             || Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_DCR_SETTING), true)
                             || client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);
    if (isPublicClient && !allowPublicRefreshTokens) {
      return null;
    }

    if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())
        && context.getAuthorizedScopes().contains(Utils.OFFLINE_ACCESS_SCOPE)
        && client.getScopes()
                 .contains(Utils.OFFLINE_ACCESS_SCOPE)
        && client.getAuthorizationGrantTypes()
                 .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
      Instant issuedAt = Instant.now();
      Instant expiresAt = issuedAt.plus(client
                                              .getTokenSettings()
                                              .getRefreshTokenTimeToLive());

      return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(),
                                    issuedAt,
                                    expiresAt);
    } else {
      return null;
    }
  }

}
