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

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.meeds.oauth2.server.entity.OAuthTokenEntity;

public interface OAuthTokenDao extends JpaRepository<OAuthTokenEntity, String> {

  Optional<OAuthTokenEntity> findByState(String state);

  Optional<OAuthTokenEntity> findByAuthorizationCodeValue(String token);

  Optional<OAuthTokenEntity> findByAccessTokenValue(String token);

  Optional<OAuthTokenEntity> findByRefreshTokenValue(String token);

  Optional<OAuthTokenEntity> findByOidcIdTokenValue(String token);

  Optional<OAuthTokenEntity> findByUserCodeValue(String token);

  Optional<OAuthTokenEntity> findByDeviceCodeValue(String token);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndPrincipalNameAndRegisteredClientId(String userName, String clientId);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndRegisteredClientId(String clientId);

  List<OAuthTokenEntity> findByAccessTokenValueNotNullAndPrincipalName(String username);

}
