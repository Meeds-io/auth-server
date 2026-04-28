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
package io.meeds.oauth2.server.util;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.collections4.MapUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings.Builder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import io.meeds.oauth2.server.entity.OAuthClientEntity;
import io.meeds.oauth2.server.entity.OAuthConsentEntity;
import io.meeds.oauth2.server.entity.OAuthTokenEntity;
import io.meeds.oauth2.server.model.OAuthAccessToken;
import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.model.OauthClientType;

import lombok.SneakyThrows;

public class EntityMapper {

  public static final String       CLIENT_URI_SETTING        = "client_uri";

  public static final String       CLIENT_UUID_SETTING       = "client_uuid";

  public static final String       CLIENT_LOGO_URI_SETTING   = "logo_uri";

  public static final String       CLIENT_POLICY_URI_SETTING = "policy_uri";

  public static final String       CLIENT_DISPLAYED_SETTING  = "displayed";

  public static final String       CLIENT_ENABLED_SETTING    = "enabled";

  public static final String       CLIENT_SYSTEM_SETTING     = "system";

  public static final String       CLIENT_SERVICE_SETTING    = "is_service";

  public static final String       CLIENT_IS_DCR_SETTING     = "is_dcr";

  public static final String       CLIENT_IS_CIMD_SETTING    = "is_cimd";

  public static final String       CLIENT_CREATION_DATE      = "creation_date";

  private static final String      TOKEN_NAME_SETTING        = "token_name";

  public static final List<String> CUSTOM_CLIENT_METADATA    = List.of(CLIENT_LOGO_URI_SETTING,
                                                                       CLIENT_URI_SETTING,
                                                                       CLIENT_POLICY_URI_SETTING,
                                                                       "application_type",
                                                                       "initiate_login_uri",
                                                                       "request_uris",
                                                                       "tos_uri",
                                                                       "contacts");

  private EntityMapper() {
    // Util
  }

  public static RegisteredClient toObject(OAuthClientEntity entity) {
    boolean displayed = entity.getClientSettings().containsKey(CLIENT_DISPLAYED_SETTING)
                        && Boolean.parseBoolean(entity.getClientSettings()
                                                      .get(CLIENT_DISPLAYED_SETTING)
                                                      .toString());
    boolean system = entity.getClientSettings().containsKey(CLIENT_SYSTEM_SETTING)
                     && Boolean.parseBoolean(entity.getClientSettings()
                                                   .get(CLIENT_SYSTEM_SETTING)
                                                   .toString());
    Builder clientSettingsBuilder = ClientSettings.withSettings(entity.getClientSettings())
                                                  .setting(CLIENT_ENABLED_SETTING,
                                                           entity.isEnabled())
                                                  .setting(CLIENT_DISPLAYED_SETTING, displayed)
                                                  .setting(CLIENT_SYSTEM_SETTING, system)
                                                  .setting(CLIENT_UUID_SETTING, entity.getClientId())
                                                  .setting(CLIENT_CREATION_DATE, entity.getCreatedDate().toString())
                                                  .requireAuthorizationConsent(true)
                                                  .requireProofKey(true);
    RegisteredClient.Builder builder = RegisteredClient.withId(entity.getRegisteredClientId())
                                                       .clientId(entity.getRegisteredClientId())
                                                       .clientName(entity.getClientName())
                                                       .clientIdIssuedAt(entity.getClientIssuedAt())
                                                       .clientAuthenticationMethods(m -> m.addAll(toClientAuthenticationMethods(entity.getClientAuthenticationMethods())))
                                                       .clientSettings(clientSettingsBuilder.build())
                                                       .tokenSettings(TokenSettings.withSettings(entity.getTokenSettings())
                                                                                   .build());
    if (entity.getClientSecret() != null && !entity.getClientSecret().isBlank()) {
      builder.clientSecret(entity.getClientSecret());
    }
    if (entity.getGrantTypes() != null) {
      entity.getGrantTypes()
            .forEach(gt -> builder.authorizationGrantType(new AuthorizationGrantType(gt)));
    }
    if (entity.getScopes() != null) {
      entity.getScopes()
            .forEach(builder::scope);
    }
    if (entity.getRedirectUris() != null) {
      entity.getRedirectUris()
            .forEach(builder::redirectUri);
    }
    return builder.build();
  }

  public static void toEntity(RegisteredClient registeredClient, OAuthClientEntity entity) {
    entity.setRegisteredClientId(registeredClient.getClientId());
    if (registeredClient.getClientSettings().getSetting(CLIENT_UUID_SETTING) != null) {
      entity.setClientId(registeredClient.getClientSettings().getSetting(CLIENT_UUID_SETTING));
    } else if (registeredClient.getClientId().contains("/")) {
      entity.setClientId(UUID.randomUUID().toString());
    } else {
      entity.setClientId(registeredClient.getClientId());
    }
    entity.setClientSecret(registeredClient.getClientSecret());
    entity.setClientName(registeredClient.getClientName());
    entity.setClientIssuedAt(Objects.requireNonNullElseGet(registeredClient.getClientIdIssuedAt(), Instant::now));
    entity.setClientAuthenticationMethods(registeredClient.getClientAuthenticationMethods()
                                                          .stream()
                                                          .map(ClientAuthenticationMethod::getValue)
                                                          .collect(Collectors.toSet()));
    entity.setGrantTypes(registeredClient.getAuthorizationGrantTypes()
                                         .stream()
                                         .map(AuthorizationGrantType::getValue)
                                         .collect(Collectors.toSet()));
    entity.setScopes(registeredClient.getScopes());
    entity.setClientSettings(registeredClient.getClientSettings().getSettings());
    entity.setTokenSettings(registeredClient.getTokenSettings().getSettings());
    Boolean enabled = registeredClient.getClientSettings()
                                      .getSetting(CLIENT_ENABLED_SETTING);
    entity.setEnabled(enabled == null || enabled.booleanValue());
    boolean publicClient = registeredClient.getClientAuthenticationMethods()
                                           .contains(ClientAuthenticationMethod.NONE);
    entity.setClientType(publicClient ? OauthClientType.PUBLIC : OauthClientType.CONFIDENTIAL);
    entity.setRedirectUris(registeredClient.getRedirectUris());
  }

  @SneakyThrows
  public static OAuth2Authorization toObject(OAuthTokenEntity entity) {
    RegisteredClient registeredClient = RegisteredClient.withId(entity.getRegisteredClientId())
                                                        .clientId(entity.getRegisteredClientId())
                                                        .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                                                        .redirectUri("")
                                                        .build();
    OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                                                             .id(entity.getId())
                                                             .principalName(entity.getPrincipalName())
                                                             .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                                                             .authorizedScopes(entity.getAuthorizedScopes());
    entity.getAttributes().forEach(builder::attribute);

    if (entity.getState() != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
    }

    if (entity.getAuthorizationCodeValue() != null) {
      OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(entity.getAuthorizationCodeValue(),
                                                                 entity.getAuthorizationCodeIssuedAt(),
                                                                 entity.getAuthorizationCodeExpiresAt());
      builder.token(code, metadataConsumer -> metadataConsumer.putAll(entity.getAuthorizationCodeMetadata()));
    }

    if (entity.getAccessTokenValue() != null) {
      OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                                                            entity.getAccessTokenValue(),
                                                            entity.getAccessTokenIssuedAt(),
                                                            entity.getAccessTokenExpiresAt(),
                                                            entity.getAccessTokenScopes());

      builder.token(accessToken, metadataConsumer -> {
        metadataConsumer.putAll(entity.getAccessTokenMetadata());
        Map<String, Object> claims = entity.getAccessTokenClaims();
        if (MapUtils.isNotEmpty(claims)) {
          metadataConsumer.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
        }
      });
    }

    if (entity.getRefreshTokenValue() != null) {
      OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(entity.getRefreshTokenValue(),
                                                               entity.getRefreshTokenIssuedAt(),
                                                               entity.getRefreshTokenExpiresAt());
      builder.token(refreshToken, metadataConsumer -> metadataConsumer.putAll(entity.getRefreshTokenMetadata()));
    }

    if (entity.getOidcIdTokenValue() != null) {
      OidcIdToken idToken = new OidcIdToken(entity.getOidcIdTokenValue(),
                                            entity.getOidcIdTokenIssuedAt(),
                                            entity.getOidcIdTokenExpiresAt(),
                                            entity.getOidcIdTokenClaims());
      builder.token(idToken, metadataConsumer -> metadataConsumer.putAll(entity.getOidcIdTokenMetadata()));
    }

    return builder.build();
  }

  public static OAuthAccessToken toSimplifiedObject(OAuthTokenEntity entity) {
    return new OAuthAccessToken(entity.getId(),
                                (String) entity.getAccessTokenMetadata().get(TOKEN_NAME_SETTING),
                                entity.getRegisteredClientId(),
                                entity.getPrincipalName(),
                                entity.getAuthorizationGrantType(),
                                entity.getAccessTokenScopes(),
                                entity.getAccessTokenIssuedAt(),
                                entity.getAccessTokenExpiresAt());
  }

  @SneakyThrows
  public static OAuthTokenEntity toEntity(OAuth2Authorization authorization, String hmacKey) {
    OAuthTokenEntity entity = new OAuthTokenEntity();
    entity.setId(authorization.getId());
    entity.setRegisteredClientId(authorization.getRegisteredClientId());
    entity.setPrincipalName(authorization.getPrincipalName());
    entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
    entity.setAuthorizedScopes(authorization.getAuthorizedScopes());
    entity.setAttributes(authorization.getAttributes());

    String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
    if (state != null) {
      entity.setState(state);
      entity.setStateHash(hashToken(state, hmacKey));
    }

    OAuth2Authorization.Token<OAuth2AuthorizationCode> code = authorization.getToken(OAuth2AuthorizationCode.class);
    if (code != null) {
      entity.setAuthorizationCodeValue(code.getToken().getTokenValue());
      entity.setAuthorizationCodeHash(hashToken(code.getToken().getTokenValue(), hmacKey));
      entity.setAuthorizationCodeIssuedAt(code.getToken().getIssuedAt());
      entity.setAuthorizationCodeExpiresAt(code.getToken().getExpiresAt());
      entity.setAuthorizationCodeMetadata(code.getMetadata());
    }

    OAuth2Authorization.Token<OAuth2AccessToken> access = authorization.getAccessToken();
    if (access != null) {
      entity.setAccessTokenValue(access.getToken().getTokenValue());
      entity.setAccessTokenHash(hashToken(access.getToken().getTokenValue(), hmacKey));
      entity.setAccessTokenIssuedAt(access.getToken().getIssuedAt());
      entity.setAccessTokenExpiresAt(access.getToken().getExpiresAt());
      entity.setAccessTokenType(access.getToken().getTokenType().getValue());
      entity.setAccessTokenScopes(access.getToken().getScopes());
      entity.setAccessTokenMetadata(access.getMetadata());
      Map<String, Object> claims = access.getClaims();
      if (MapUtils.isNotEmpty(claims)) {
        entity.setAccessTokenClaims(claims);
      }
    }

    OAuth2Authorization.Token<OAuth2RefreshToken> refresh = authorization.getRefreshToken();
    if (refresh != null) {
      entity.setRefreshTokenValue(refresh.getToken().getTokenValue());
      entity.setRefreshTokenHash(hashToken(refresh.getToken().getTokenValue(), hmacKey));
      entity.setRefreshTokenIssuedAt(refresh.getToken().getIssuedAt());
      entity.setRefreshTokenExpiresAt(refresh.getToken().getExpiresAt());
      entity.setRefreshTokenMetadata(refresh.getMetadata());
    }

    OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
    if (idToken != null) {
      entity.setOidcIdTokenValue(idToken.getToken().getTokenValue());
      entity.setOidcIdTokenHash(hashToken(idToken.getToken().getTokenValue(), hmacKey));
      entity.setOidcIdTokenIssuedAt(idToken.getToken().getIssuedAt());
      entity.setOidcIdTokenExpiresAt(idToken.getToken().getExpiresAt());
      entity.setOidcIdTokenMetadata(idToken.getMetadata());
      entity.setOidcIdTokenClaims(idToken.getClaims());
    }

    return entity;
  }

  public static OAuth2AuthorizationConsent toObject(OAuthConsentEntity entity) {
    return OAuth2AuthorizationConsent.withId(entity.getRegisteredClientId(),
                                             entity.getPrincipalName())
                                     .authorities(a -> entity.getAuthorities()
                                                             .stream()
                                                             .map(SimpleGrantedAuthority::new)
                                                             .forEach(a::add))
                                     .build();
  }

  public static OAuthConsent toSimplifiedObject(OAuthConsentEntity entity) {
    return new OAuthConsent(entity.getRegisteredClientId(),
                            entity.getPrincipalName(),
                            entity.getAuthorities(),
                            entity.getCreatedDate());
  }

  public static void toEntity(OAuth2AuthorizationConsent authorizationConsent, OAuthConsentEntity entity) {
    entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
    entity.setPrincipalName(authorizationConsent.getPrincipalName());
    entity.setAuthorities(authorizationConsent.getAuthorities()
                                              .stream()
                                              .map(GrantedAuthority::getAuthority)
                                              .collect(Collectors.toSet()));
  }

  /**
   * Encryption can be randomized, thus use deterministic Hash for lookup with a
   * fixed secret HMAC key switch platform (CodecInitializer Key encrypted constant)
   * 
   * @param hmacKey Secret key for MAC
   * @param token Token to hash
   * @return Deterministically hashed value used for lookup
   */
  public static String hashToken(String token, String hmacKey) {
    return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, hmacKey).hmacHex(token);
  }

  private static Set<ClientAuthenticationMethod> toClientAuthenticationMethods(Set<String> values) {
    return values.stream()
                 .map(ClientAuthenticationMethod::valueOf)
                 .collect(Collectors.toSet());
  }

}
