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
import static io.meeds.oauth2.server.util.OAuthEventType.CONSENT_CREATED;
import static io.meeds.oauth2.server.util.OAuthEventType.CONSENT_DELETED;
import static io.meeds.oauth2.server.util.OAuthEventType.CONSENT_UPDATED;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.dao.OAuthConsentDao;
import io.meeds.oauth2.server.entity.OAuthConsentEntity;
import io.meeds.oauth2.server.util.EntityMapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class OAuthConsentCachedStorage {

  public static final String CACHE_NAME = "oauth.consents";

  @Autowired
  private OAuthClientStorage oAuthClientStorage;

  @Autowired
  private OAuthConsentDao    dao;

  @Autowired
  private ListenerService    listenerService;

  @Cacheable(cacheNames = CACHE_NAME, key = "{#root.args[0], #root.args[1]}")
  public OAuth2AuthorizationConsent findById(String clientId, String username) {
    clientId = getClientId(clientId);
    return dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
              .map(EntityMapper::toObject)
              .orElse(null);
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    String clientId = getClientId(authorizationConsent.getRegisteredClientId());
    String username = authorizationConsent.getPrincipalName();
    OAuth2AuthorizationConsent existingClientAuthorization = dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
                                                                .map(EntityMapper::toObject)
                                                                .orElse(null);
    OAuthConsentEntity entity = dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
                                   .orElseGet(OAuthConsentEntity::new);
    boolean isNew = entity.getId() == null;
    toEntity(authorizationConsent, entity);
    dao.save(entity);
    if (isNew) {
      listenerService.broadcast(CONSENT_CREATED, existingClientAuthorization, authorizationConsent);
    } else {
      listenerService.broadcast(CONSENT_UPDATED, existingClientAuthorization, authorizationConsent);
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    String clientId = getClientId(authorizationConsent.getRegisteredClientId());
    String username = authorizationConsent.getPrincipalName();
    OAuthConsentEntity entity = dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
                                   .orElse(null);
    if (entity != null) {
      dao.delete(entity);
      listenerService.broadcast(CONSENT_DELETED, EntityMapper.toObject(entity), authorizationConsent);
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void evictCache() {
    log.debug("Evict all Cache Entries {}", CACHE_NAME);
  }

  private String getClientId(String clientId) {
    RegisteredClient client = oAuthClientStorage.findByClientId(clientId);
    if (client != null) {
      return client.getClientId();
    } else {
      return clientId;
    }
  }

}
