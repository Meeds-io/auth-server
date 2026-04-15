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
package io.meeds.oauth2.server.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.storage.OAuthConsentStorage;

@Service
public class OAuthConsentService {

  @Autowired
  private OAuthTokenService   oAuthTokenService;

  @Autowired
  private OAuthConsentStorage storage;

  public List<OAuthConsent> getConsentsByUser(String username) {
    return storage.findByUser(username);
  }

  public List<OAuthConsent> getConsentsByClient(String clientId) {
    return storage.findByClientId(clientId);
  }

  public OAuthConsent getConsent(String username, String clientId) {
    return storage.findByUserAndClientId(username, clientId);
  }

  public void deleteConsentByUserAndClient(String username, String clientId) {
    oAuthTokenService.deleteTokensByUserAndClient(username, clientId);
    storage.deleteByUserAndClientId(username, clientId);
  }

  public void deleteConsentsByUser(String username) {
    oAuthTokenService.deleteTokensByUser(username);
    storage.deleteByUser(username);
  }

  public void deleteConsentsByClient(String clientId) {
    oAuthTokenService.deleteTokensByClient(clientId);
    storage.deleteByClientId(clientId);
  }

}
