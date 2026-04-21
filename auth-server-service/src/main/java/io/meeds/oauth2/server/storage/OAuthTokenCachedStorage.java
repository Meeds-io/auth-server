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
package io.meeds.oauth2.server.storage;

import static io.meeds.oauth2.server.util.EntityMapper.toEntity;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_CREATED;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_DELETED;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_UPDATED;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.dao.OAuthTokenDao;
import io.meeds.oauth2.server.entity.OAuthTokenEntity;
import io.meeds.oauth2.server.util.EntityMapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class OAuthTokenCachedStorage {

  public static final String CACHE_NAME          = "oauth.tokens";

  public static final String ACCESS_TOKEN_VALUE  = "access_token";

  public static final String REFRESH_TOKEN_VALUE = "refresh_token";

  @Autowired
  private OAuthTokenDao      dao;

  @Autowired
  private ListenerService    listenerService;

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void save(OAuth2Authorization authorization) {
    OAuth2Authorization existingOAuth2Authorization = findById(authorization.getId());
    OAuthTokenEntity savedEntity = dao.save(toEntity(authorization));
    if (existingOAuth2Authorization == null) {
      listenerService.broadcast(TOKEN_CREATED, existingOAuth2Authorization, EntityMapper.toObject(savedEntity));
    } else {
      listenerService.broadcast(TOKEN_UPDATED, existingOAuth2Authorization, EntityMapper.toObject(savedEntity));
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void remove(OAuth2Authorization authorization) {
    OAuth2Authorization existingOAuth2Authorization = findById(authorization.getId());
    if (existingOAuth2Authorization != null) {
      dao.deleteById(authorization.getId());
      listenerService.broadcast(TOKEN_DELETED, existingOAuth2Authorization, existingOAuth2Authorization);
    }
  }

  @Cacheable(CACHE_NAME)
  public OAuth2Authorization findById(String id) {
    return dao.findById(id)
              .map(EntityMapper::toObject)
              .orElse(null);
  }

  @Cacheable(cacheNames = CACHE_NAME, key = "{#root.args[0], #root.args[1]}")
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    if (token == null) {
      return null;
    } else {
      if (tokenType == null) {
        return dao.findByState(token)
                  .or(() -> dao.findByAuthorizationCodeValue(token))
                  .or(() -> dao.findByAccessTokenValue(token))
                  .or(() -> dao.findByRefreshTokenValue(token))
                  .or(() -> dao.findByOidcIdTokenValue(token))
                  .or(() -> dao.findByUserCodeValue(token))
                  .or(() -> dao.findByDeviceCodeValue(token))
                  .map(EntityMapper::toObject)
                  .orElse(null);
      } else {
        return switch (tokenType.getValue()) {
        case OAuth2ParameterNames.CODE -> dao.findByAuthorizationCodeValue(token).map(EntityMapper::toObject).orElse(null);
        case ACCESS_TOKEN_VALUE -> dao.findByAccessTokenValue(token).map(EntityMapper::toObject).orElse(null);
        case REFRESH_TOKEN_VALUE -> dao.findByRefreshTokenValue(token).map(EntityMapper::toObject).orElse(null);
        case OidcParameterNames.ID_TOKEN -> dao.findByOidcIdTokenValue(token).map(EntityMapper::toObject).orElse(null);
        case OAuth2ParameterNames.STATE -> dao.findByState(token).map(EntityMapper::toObject).orElse(null);
        case OAuth2ParameterNames.USER_CODE -> dao.findByUserCodeValue(token).map(EntityMapper::toObject).orElse(null);
        case OAuth2ParameterNames.DEVICE_CODE -> dao.findByDeviceCodeValue(token).map(EntityMapper::toObject).orElse(null);
        default -> null;
        };
      }
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void evictCache() {
    log.debug("Evict all Cache Entries {}", CACHE_NAME);
  }

}
