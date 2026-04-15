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
package io.meeds.oauth2.server.listener;

import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DELETED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DISABLED_EVENT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.Event;
import org.exoplatform.services.listener.Listener;
import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.service.OAuthConsentService;

import jakarta.annotation.PostConstruct;

@Component
public class OauthClientAuthorizationCleanupListener extends Listener<String, RegisteredClient> {

  @Autowired
  private OAuthConsentService oAuthConsentService;

  @Autowired
  private ListenerService     listenerService;

  @PostConstruct
  public void init() {
    listenerService.addListener(CLIENT_DISABLED_EVENT, this);
    listenerService.addListener(CLIENT_DELETED_EVENT, this);
  }

  @Override
  public void onEvent(Event<String, RegisteredClient> event) throws Exception {
    String clientId = event.getSource();
    oAuthConsentService.deleteConsentsByClient(clientId);
  }

}
