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
package io.meeds.oauth2.server.configuration;

import java.time.Instant;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.meeds.oauth2.server.service.OAuthJwkService;
import io.meeds.oauth2.server.service.OAuthJwtCustomizerService;
import io.meeds.oauth2.server.util.Utils;

@Configuration
public class OAuthJwtConfiguration {

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
    encoder.setJwkSelector(jwks -> jwks.stream()
                                       .findFirst()
                                       .orElseThrow(() -> new IllegalStateException("No JWK available for JWT signing")));
    return encoder;
  }

  @Bean
  JWKSource<SecurityContext> jwkSource(OAuthJwkService oAuthJwkService) {
    return (jwkSelector, securityContext) -> jwkSelector.select(oAuthJwkService.getJwkSet());
  }

  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> jwtAccessTokenCustomizer(OAuthJwtCustomizerService oAuthJwtCustomizerService) {
    return oAuthJwtCustomizerService::customizeAccessTokenClaims;
  }

  @Bean
  OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) { // NOSONAR
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
    return new DelegatingOAuth2TokenGenerator(jwtGenerator,
                                              new OAuth2AccessTokenGenerator(),
                                              this::generateRefreshToken);
  }

  private OAuth2RefreshToken generateRefreshToken(OAuth2TokenContext context) {
    if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())
        && context.getAuthorizedScopes().contains(Utils.OFFLINE_ACCESS_SCOPE)
        && context.getRegisteredClient()
                  .getAuthorizationGrantTypes()
                  .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
      Instant issuedAt = Instant.now();
      Instant expiresAt = issuedAt.plus(context.getRegisteredClient()
                                               .getTokenSettings()
                                               .getRefreshTokenTimeToLive());

      String value = UUID.randomUUID() + "-" + UUID.randomUUID();
      return new OAuth2RefreshToken(value, issuedAt, expiresAt);
    } else {
      return null;
    }
  }

}
