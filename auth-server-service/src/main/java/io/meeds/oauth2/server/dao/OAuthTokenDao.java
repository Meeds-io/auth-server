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
package io.meeds.oauth2.server.dao;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.meeds.oauth2.server.entity.OAuthTokenEntity;

public interface OAuthTokenDao extends JpaRepository<OAuthTokenEntity, String> {

  Optional<OAuthTokenEntity> findByStateHash(String state);

  Optional<OAuthTokenEntity> findByAuthorizationCodeHash(String token);

  Optional<OAuthTokenEntity> findByAccessTokenHash(String token);

  Optional<OAuthTokenEntity> findByRefreshTokenHash(String token);

  Optional<OAuthTokenEntity> findByOidcIdTokenHash(String token);

  Optional<OAuthTokenEntity> findByUserCodeHash(String token);

  Optional<OAuthTokenEntity> findByDeviceCodeHash(String token);

  @Query("""
      SELECT t from OAuthToken t
      WHERE t.stateHash = :hash
      OR t.authorizationCodeHash = :hash
      OR t.accessTokenHash = :hash
      OR t.refreshTokenHash = :hash
      OR t.oidcIdTokenHash = :hash
      OR t.userCodeHash = :hash
      OR t.deviceCodeHash = :hash
      """)
  Optional<OAuthTokenEntity> findByTokenHash(
                                             @Param("hash")
                                             String hash);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndPrincipalNameAndRegisteredClientId(String userName, String clientId);

  List<OAuthTokenEntity> findByPrincipalNameAndRegisteredClientId(String userName, String clientId);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndRegisteredClientId(String clientId);

  List<OAuthTokenEntity> findByRegisteredClientId(String clientId);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndPrincipalName(String username);

  List<OAuthTokenEntity> findByPrincipalName(String username);

  @Query("""
      SELECT t from OAuthToken t
      WHERE (t.authorizationCodeExpiresAt IS NULL OR t.authorizationCodeExpiresAt < :dateNow)
      AND (t.accessTokenExpiresAt IS NULL OR t.accessTokenExpiresAt < :dateNow)
      AND (t.refreshTokenExpiresAt IS NULL OR t.refreshTokenExpiresAt < :dateNow)
      AND (t.oidcIdTokenExpiresAt IS NULL OR t.oidcIdTokenExpiresAt < :dateNow)
      AND (t.userCodeExpiresAt IS NULL OR t.userCodeExpiresAt < :dateNow)
      AND (t.deviceCodeExpiresAt IS NULL OR t.deviceCodeExpiresAt < :dateNow)
      """)
  List<OAuthTokenEntity> findExpiredTokens(
                                           @Param("dateNow")
                                           Instant now);

}
