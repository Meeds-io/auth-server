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

import static io.meeds.oauth2.server.util.EntityMapper.hashToken;
import static io.meeds.oauth2.server.util.EntityMapper.toEntity;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_CREATED;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_DELETED;
import static io.meeds.oauth2.server.util.OAuthEventType.TOKEN_UPDATED;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;
import org.exoplatform.web.security.codec.CodecInitializer;

import io.meeds.oauth2.server.dao.OAuthTokenDao;
import io.meeds.oauth2.server.entity.OAuthTokenEntity;
import io.meeds.oauth2.server.util.EntityMapper;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class OAuthTokenCachedStorage {

  public static final String CACHE_NAME = "oauth.tokens";

  @Autowired
  private OAuthTokenDao      dao;

  @Autowired
  private CodecInitializer   codecInitializer;

  @Autowired
  private ListenerService    listenerService;

  private String             hmacKey;

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void save(OAuth2Authorization authorization) { // NOSONAR
    OAuthTokenEntity existingEntity = dao.findById(authorization.getId())
                                         .orElse(null);
    OAuthTokenEntity entityToSave = toEntity(authorization, getHmacKey());

    OAuthTokenEntity savedEntity = dao.save(entityToSave);
    if (existingEntity == null) {
      listenerService.broadcast(TOKEN_CREATED,
                                null,
                                EntityMapper.toObject(savedEntity));
    } else {
      listenerService.broadcast(TOKEN_UPDATED,
                                EntityMapper.toObject(existingEntity),
                                EntityMapper.toObject(savedEntity));
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
  @SneakyThrows
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    if (token == null) {
      return null;
    } else {
      // Encryption can be randomized, thus use deterministic Hash for lookup
      // with a fixed secret HMAC key switch platform (Codec Initialize Key encrypted
      // constant)
      String tokenHash = hashToken(token, getHmacKey());
      if (tokenType == null) {
        return dao.findByTokenHash(tokenHash)
                  .map(EntityMapper::toObject)
                  .orElse(null);
      } else {
        Optional<OAuthTokenEntity> entityOptional = switch (tokenType.getValue()) {
        case OAuth2ParameterNames.STATE -> dao.findByStateHash(tokenHash);
        case OAuth2ParameterNames.CODE -> dao.findByAuthorizationCodeHash(tokenHash);
        case OAuth2ParameterNames.ACCESS_TOKEN -> dao.findByAccessTokenHash(tokenHash);
        case OAuth2ParameterNames.REFRESH_TOKEN -> dao.findByRefreshTokenHash(tokenHash);
        case OidcParameterNames.ID_TOKEN -> dao.findByOidcIdTokenHash(tokenHash);
        case OAuth2ParameterNames.USER_CODE -> dao.findByUserCodeHash(tokenHash);
        case OAuth2ParameterNames.DEVICE_CODE -> dao.findByDeviceCodeHash(tokenHash);
        default -> Optional.empty();
        };
        return entityOptional.map(EntityMapper::toObject)
                             .orElse(null);
      }
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void evictCache() {
    log.debug("Evict all Cache Entries {}", CACHE_NAME);
  }

  @SneakyThrows
  public String getHmacKey() {
    if (hmacKey == null) {
      hmacKey = codecInitializer.getCodec().encode("platform-based-key-to-hash-v1");
    }
    return hmacKey;
  }
}
