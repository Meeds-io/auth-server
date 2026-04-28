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
package io.meeds.oauth2.server.entity;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import io.meeds.oauth2.server.util.JsonEncryptedMapConverter;
import io.meeds.oauth2.server.util.JsonSetConverter;
import io.meeds.oauth2.server.util.StringEncryptedConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity(name = "OAuthToken")
@Table(name = "AUTH_SERVER_AUTHORIZATION")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthTokenEntity {

  @Id
  @Column(name = "ID", nullable = false, length = 100)
  private String              id;

  @Column(name = "REGISTERED_CLIENT_ID", nullable = false, length = 100)
  private String              registeredClientId;

  @Column(name = "PRINCIPAL_NAME", nullable = false, length = 200)
  private String              principalName;

  @Column(name = "AUTHORIZATION_GRANT_TYPE", nullable = false, length = 100)
  private String              authorizationGrantType;

  @Column(name = "AUTHORIZED_SCOPES")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         authorizedScopes;

  @Column(name = "ATTRIBUTES")
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> attributes;

  @Column(name = "STATE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              state;

  @Column(name = "STATE_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              stateHash;

  @Column(name = "AUTHORIZATION_CODE_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              authorizationCodeValue;

  @Column(name = "AUTHORIZATION_CODE_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              authorizationCodeHash;

  @Column(name = "AUTHORIZATION_CODE_ISSUED_AT")
  private Instant             authorizationCodeIssuedAt;

  @Column(name = "AUTHORIZATION_CODE_EXPIRES_AT")
  private Instant             authorizationCodeExpiresAt;

  @Column(name = "AUTHORIZATION_CODE_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> authorizationCodeMetadata;

  @Column(name = "ACCESS_TOKEN_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              accessTokenValue;

  @Column(name = "ACCESS_TOKEN_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              accessTokenHash;

  @Column(name = "ACCESS_TOKEN_ISSUED_AT")
  private Instant             accessTokenIssuedAt;

  @Column(name = "ACCESS_TOKEN_EXPIRES_AT")
  private Instant             accessTokenExpiresAt;

  @Column(name = "ACCESS_TOKEN_TYPE")
  private String              accessTokenType;

  @Column(name = "ACCESS_TOKEN_SCOPES")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         accessTokenScopes;

  @Column(name = "ACCESS_TOKEN_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> accessTokenMetadata;

  @Column(name = "ACCESS_TOKEN_CLAIMS")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> accessTokenClaims;

  @Column(name = "REFRESH_TOKEN_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              refreshTokenValue;

  @Column(name = "REFRESH_TOKEN_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              refreshTokenHash;

  @Column(name = "REFRESH_TOKEN_ISSUED_AT")
  private Instant             refreshTokenIssuedAt;

  @Column(name = "REFRESH_TOKEN_EXPIRES_AT")
  private Instant             refreshTokenExpiresAt;

  @Column(name = "REFRESH_TOKEN_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> refreshTokenMetadata;

  @Column(name = "OIDC_ID_TOKEN_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              oidcIdTokenValue;

  @Column(name = "OIDC_ID_TOKEN_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              oidcIdTokenHash;

  @Column(name = "OIDC_ID_TOKEN_ISSUED_AT")
  private Instant             oidcIdTokenIssuedAt;

  @Column(name = "OIDC_ID_TOKEN_EXPIRES_AT")
  private Instant             oidcIdTokenExpiresAt;

  @Column(name = "OIDC_ID_TOKEN_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> oidcIdTokenMetadata;

  @Column(name = "OIDC_ID_TOKEN_CLAIMS")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> oidcIdTokenClaims;

  @Column(name = "USER_CODE_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              userCodeValue;

  @Column(name = "USER_CODE_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              userCodeHash;

  @Column(name = "USER_CODE_ISSUED_AT")
  private Instant             userCodeIssuedAt;

  @Column(name = "USER_CODE_EXPIRES_AT")
  private Instant             userCodeExpiresAt;

  @Column(name = "USER_CODE_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> userCodeMetadata;

  @Column(name = "DEVICE_CODE_VALUE")
  @Convert(converter = StringEncryptedConverter.class)
  private String              deviceCodeValue;

  @Column(name = "DEVICE_CODE_HASH")
  // INFO: Encryption Algorithm can be randomized, so it cannot be used for
  // lookup. Thus this field is used for lookup only
  private String              deviceCodeHash;

  @Column(name = "DEVICE_CODE_ISSUED_AT")
  private Instant             deviceCodeIssuedAt;

  @Column(name = "DEVICE_CODE_EXPIRES_AT")
  private Instant             deviceCodeExpiresAt;

  @Column(name = "DEVICE_CODE_METADATA")
  // INFO: Encrypted Value in DB
  @Convert(converter = JsonEncryptedMapConverter.class)
  private Map<String, Object> deviceCodeMetadata;

}
