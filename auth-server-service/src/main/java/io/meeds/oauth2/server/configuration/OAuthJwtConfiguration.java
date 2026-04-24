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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.exoplatform.commons.api.settings.SettingService;
import org.exoplatform.commons.api.settings.SettingValue;
import org.exoplatform.commons.api.settings.data.Context;
import org.exoplatform.commons.api.settings.data.Scope;
import org.exoplatform.web.security.codec.CodecInitializer;
import org.exoplatform.web.security.security.TokenServiceInitializationException;

import io.meeds.oauth2.server.service.OAuthJwtCustomizerService;

@Configuration
public class OAuthJwtConfiguration {

  private static final Context JWKS_CONTEXT = Context.GLOBAL.id("meeds.oauth2.jwks");

  private static final Scope   JWKS_SCOPE   = Scope.GLOBAL.id("jwks");

  private static final String  JWKS_KEY     = "jwks-v1";

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  JWKSource<SecurityContext> jwkSource(SettingService settingService,
                                       CodecInitializer codecInitializer,
                                       @Value("${meeds.oauth2.jwks.key-size:3072}")
                                       int keySize) throws TokenServiceInitializationException,
                                                    ParseException,
                                                    NoSuchAlgorithmException {
    SettingValue<?> settingValue = settingService.get(JWKS_CONTEXT, JWKS_SCOPE, JWKS_KEY);

    JWKSet jwkSet;
    if (settingValue != null && settingValue.getValue() != null) {
      String jwksJson = codecInitializer.getCodec().decode(settingValue.getValue().toString());
      jwkSet = JWKSet.parse(jwksJson);
    } else {
      jwkSet = generate(keySize);
      String jwksJson = jwkSet.toString(false);
      settingService.set(JWKS_CONTEXT,
                         JWKS_SCOPE,
                         JWKS_KEY,
                         SettingValue.create(codecInitializer.getCodec().encode(jwksJson)));
    }
    return new ImmutableJWKSet<>(jwkSet);
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

  private JWKSet generate(int keysize) throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keysize);
    KeyPair keyPair = generator.generateKeyPair();
    RSAKey.Builder rsaKeyBuilder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic());
    RSAKey rsaKey = rsaKeyBuilder.privateKey((RSAPrivateKey) keyPair.getPrivate())
                                 .keyUse(KeyUse.SIGNATURE)
                                 .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                                 .keyID("sig-" + UUID.randomUUID())
                                 .build();
    return new JWKSet(rsaKey);
  }

  private OAuth2RefreshToken generateRefreshToken(OAuth2TokenContext context) {
    if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
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
