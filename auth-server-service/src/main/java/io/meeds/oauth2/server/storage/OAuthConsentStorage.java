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
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_AUTHORIZATION_CREATED;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_AUTHORIZATION_DELETED;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_AUTHORIZATION_UPDATED;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.dao.OAuthConsentDao;
import io.meeds.oauth2.server.entity.OAuthConsentEntity;
import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.util.EntityMapper;

@Component
public class OAuthConsentStorage implements OAuth2AuthorizationConsentService {

  public static final String CACHE_NAME = "oauth.consents";

  @Autowired
  private OAuthConsentDao    dao;

  @Autowired
  private ListenerService    listenerService;

  @Override
  @Cacheable(cacheNames = CACHE_NAME, key = "{#root.args[0], #root.args[1]}")
  public OAuth2AuthorizationConsent findById(String clientId, String username) {
    return dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
              .map(EntityMapper::toObject)
              .orElse(null);
  }

  @Override
  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    OAuthConsent existingClientAuthorization = findByUserAndClientId(authorizationConsent.getPrincipalName(),
                                                                     authorizationConsent.getRegisteredClientId());
    OAuthConsentEntity entity = dao.findByPrincipalNameAndRegisteredClientId(authorizationConsent.getPrincipalName(),
                                                                             authorizationConsent.getRegisteredClientId())
                                   .orElseGet(OAuthConsentEntity::new);
    boolean isNew = entity.getId() == null;
    toEntity(authorizationConsent, entity);
    dao.save(entity);
    if (isNew) {
      listenerService.broadcast(CLIENT_AUTHORIZATION_CREATED, existingClientAuthorization, authorizationConsent);
    } else {
      listenerService.broadcast(CLIENT_AUTHORIZATION_UPDATED, existingClientAuthorization, authorizationConsent);
    }
  }

  @Override
  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    deleteByUserAndClientId(authorizationConsent.getPrincipalName(), authorizationConsent.getRegisteredClientId());
  }

  public OAuthConsent findByUserAndClientId(String username, String clientId) {
    return dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
              .map(this::toSimplifiedObject)
              .orElse(null);
  }

  public List<OAuthConsent> findByUser(String username) {
    return dao.findByPrincipalName(username)
              .stream()
              .map(this::toSimplifiedObject)
              .toList();
  }

  public List<OAuthConsent> findByClientId(String clientId) {
    return dao.findByRegisteredClientId(clientId)
              .stream()
              .map(this::toSimplifiedObject)
              .toList();
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void deleteByUserAndClientId(String username, String clientId) {
    OAuthConsent existingClientAuthorization = findByUserAndClientId(username, clientId);
    dao.deleteByPrincipalNameAndRegisteredClientId(username, clientId);
    listenerService.broadcast(CLIENT_AUTHORIZATION_DELETED, existingClientAuthorization, null);
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void deleteByClientId(String clientId) {
    dao.findByRegisteredClientId(clientId)
       .stream()
       .forEach(a -> deleteByUserAndClientId(a.getPrincipalName(), a.getRegisteredClientId()));
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void deleteByUser(String username) {
    dao.findByPrincipalName(username)
       .stream()
       .forEach(a -> deleteByUserAndClientId(a.getPrincipalName(), a.getRegisteredClientId()));
  }

  private OAuthConsent toSimplifiedObject(OAuthConsentEntity ac) {
    return EntityMapper.toSimplifiedObject(ac);
  }

}
