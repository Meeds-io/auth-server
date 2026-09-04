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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_DISPLAYED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.toEntity;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_CREATED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DELETED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DISABLED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DISPLAYED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_ENABLED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_HIDDEN_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_UPDATED_EVENT;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import org.exoplatform.commons.exception.ObjectNotFoundException;
import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.dao.OAuthClientAppDao;
import io.meeds.oauth2.server.entity.OAuthClientEntity;
import io.meeds.oauth2.server.util.EntityMapper;

@Component
public class OAuthClientStorage implements RegisteredClientRepository {

  private static final String CLIENT_NOT_FOUND_MSG = "Client with Id %s not found";

  public static final String  CACHE_NAME           = "oauth.clients";

  @Autowired
  private OAuthClientAppDao   dao;

  @Autowired
  private ListenerService     listenerService;

  @Override
  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void save(RegisteredClient registeredClient) {
    OAuthClientEntity entity = dao.findByClientId(registeredClient.getClientId())
                                  .orElseGet(OAuthClientEntity::new);
    boolean isNew = entity.getId() == null;
    toEntity(registeredClient, entity);
    entity = dao.save(entity);
    if (isNew) {
      listenerService.broadcast(CLIENT_CREATED_EVENT, registeredClient.getClientId(), EntityMapper.toObject(entity));
    } else {
      listenerService.broadcast(CLIENT_UPDATED_EVENT, registeredClient.getClientId(), EntityMapper.toObject(entity));
    }
  }

  @Override
  @Cacheable(cacheNames = CACHE_NAME, unless = "#result == null")
  public RegisteredClient findById(String clientId) {
    return dao.findByClientIdAndEnabledTrue(clientId)
              .map(EntityMapper::toObject)
              .orElse(null);
  }

  @Override
  @Cacheable(cacheNames = CACHE_NAME, unless = "#result == null")
  public RegisteredClient findByClientId(String clientId) {
    return dao.findByClientIdAndEnabledTrue(clientId)
              .map(EntityMapper::toObject)
              .orElse(null);
  }

  @Cacheable(cacheNames = CACHE_NAME, key = "{#p0, #p1}", unless = "#result == null")
  public RegisteredClient getClient(String clientId, boolean includeDisabled) {
    if (includeDisabled) {
      return dao.findByClientId(clientId)
                .map(EntityMapper::toObject)
                .orElse(null);
    } else {
      return dao.findByClientIdAndEnabledTrue(clientId)
                .map(EntityMapper::toObject)
                .orElse(null);
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public void delete(String clientId) throws ObjectNotFoundException {
    OAuthClientEntity entity = dao.findByClientId(clientId)
                                  .orElseThrow(() -> new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId)));
    dao.delete(entity);
    listenerService.broadcast(CLIENT_DELETED_EVENT, clientId, EntityMapper.toObject(entity));
  }

  public List<RegisteredClient> findAll() {
    return dao.findAllSortByClientNameAsc()
              .stream()
              .map(EntityMapper::toObject)
              .toList();
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public boolean enable(String clientId) throws ObjectNotFoundException {
    OAuthClientEntity entity = dao.findByClientId(clientId)
                                  .orElseThrow(() -> new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId)));
    if (!entity.isEnabled()) {
      entity.setEnabled(true);
      entity = dao.save(entity);
      listenerService.broadcast(CLIENT_ENABLED_EVENT, clientId, EntityMapper.toObject(entity));
      return true;
    } else {
      return true;
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public boolean disable(String clientId) throws ObjectNotFoundException {
    OAuthClientEntity entity = dao.findByClientId(clientId)
                                  .orElseThrow(() -> new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId)));
    if (entity.isEnabled()) {
      entity.setEnabled(false);
      entity = dao.save(entity);
      listenerService.broadcast(CLIENT_DISABLED_EVENT, clientId, EntityMapper.toObject(entity));
      return true;
    } else {
      return true;
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public boolean display(String clientId) throws ObjectNotFoundException {
    OAuthClientEntity entity = dao.findByClientId(clientId)
                                  .orElseThrow(() -> new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId)));
    if (!entity.getClientSettings().containsKey(CLIENT_DISPLAYED_SETTING)
        || !entity.getClientSettings().get(CLIENT_DISPLAYED_SETTING).equals(true)) {
      entity.getClientSettings().put(CLIENT_DISPLAYED_SETTING, true);
      entity = dao.save(entity);
      listenerService.broadcast(CLIENT_DISPLAYED_EVENT, clientId, EntityMapper.toObject(entity));
      return true;
    } else {
      return true;
    }
  }

  @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
  public boolean hide(String clientId) throws ObjectNotFoundException {
    OAuthClientEntity entity = dao.findByClientId(clientId)
                                  .orElseThrow(() -> new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId)));
    if (entity.getClientSettings().containsKey(CLIENT_DISPLAYED_SETTING)
        && entity.getClientSettings().get(CLIENT_DISPLAYED_SETTING).equals(true)) {
      entity.getClientSettings().put(CLIENT_DISPLAYED_SETTING, false);
      entity = dao.save(entity);
      listenerService.broadcast(CLIENT_HIDDEN_EVENT, clientId, EntityMapper.toObject(entity));
      return true;
    } else {
      return true;
    }
  }
}
