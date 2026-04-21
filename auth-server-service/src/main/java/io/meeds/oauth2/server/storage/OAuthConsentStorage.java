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

import static io.meeds.oauth2.server.util.OAuthEventType.CONSENT_USED;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.dao.OAuthConsentDao;
import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.util.EntityMapper;

@Component
public class OAuthConsentStorage implements OAuth2AuthorizationConsentService {

  @Autowired
  private OAuthClientStorage        oAuthClientStorage;

  @Autowired
  private OAuthConsentCachedStorage cachedStorage;

  @Autowired
  private OAuthConsentDao           dao;

  @Autowired
  private ListenerService           listenerService;

  @Override
  public OAuth2AuthorizationConsent findById(String clientId, String username) {
    OAuth2AuthorizationConsent oAuth2AuthorizationConsent = cachedStorage.findById(clientId, username);
    if (oAuth2AuthorizationConsent != null) {
      listenerService.broadcast(CONSENT_USED, oAuth2AuthorizationConsent, null);
    }
    return oAuth2AuthorizationConsent;
  }

  @Override
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    cachedStorage.save(authorizationConsent);
  }

  @Override
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    cachedStorage.remove(authorizationConsent);
  }

  public OAuthConsent findByUserAndClientId(String username, String clientId) {
    clientId = getClientId(clientId);
    return dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
              .map(EntityMapper::toSimplifiedObject)
              .orElse(null);
  }

  public List<OAuthConsent> findByUser(String username) {
    return dao.findByPrincipalName(username)
              .stream()
              .map(EntityMapper::toSimplifiedObject)
              .toList();
  }

  public List<OAuthConsent> findByClientId(String clientId) {
    clientId = getClientId(clientId);
    return dao.findByRegisteredClientId(clientId)
              .stream()
              .map(EntityMapper::toSimplifiedObject)
              .toList();
  }

  public void deleteByUserAndClientId(String username, String clientId) {
    try {
      clientId = getClientId(clientId);
      dao.findByPrincipalNameAndRegisteredClientId(username, clientId)
         .stream()
         .map(EntityMapper::toObject)
         .forEach(this::remove);
    } finally {
      cachedStorage.evictCache();
    }
  }

  public void deleteByClientId(String clientId) {
    try {
      clientId = getClientId(clientId);
      dao.findByRegisteredClientId(clientId)
         .stream()
         .map(EntityMapper::toObject)
         .forEach(this::remove);
    } finally {
      cachedStorage.evictCache();
    }
  }

  public void deleteByUser(String username) {
    try {
      dao.findByPrincipalName(username)
         .stream()
         .map(EntityMapper::toObject)
         .forEach(this::remove);
    } finally {
      cachedStorage.evictCache();
    }
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
