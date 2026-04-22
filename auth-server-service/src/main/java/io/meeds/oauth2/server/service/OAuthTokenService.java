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
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import org.exoplatform.commons.exception.ObjectNotFoundException;
import org.exoplatform.portal.config.UserACL;

import io.meeds.oauth2.server.model.OAuthAccessToken;
import io.meeds.oauth2.server.storage.OAuthTokenStorage;

@Service
public class OAuthTokenService {

  @Autowired
  private UserACL           userAcl;

  @Autowired
  private OAuthTokenStorage storage;

  public void remove(OAuth2Authorization authorization) {
    storage.remove(authorization);
  }

  public OAuth2Authorization findById(String id) {
    return storage.findById(id);
  }

  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    return storage.findByToken(token, tokenType);
  }

  public List<OAuthAccessToken> getTokensByUserAndClient(String username, String clientId) {
    return storage.findByUserAndClientId(username, clientId);
  }

  public List<OAuthAccessToken> getTokensByUser(String username) {
    return storage.findByUser(username);
  }

  public List<OAuthAccessToken> getTokensByClient(String clientId) {
    return storage.findByClientId(clientId);
  }

  public void deleteTokensByUserAndClient(String username, String clientId) {
    storage.deleteByUserAndClientId(username, clientId);
  }

  public void deleteTokensByClient(String clientId) {
    storage.deleteByClientId(clientId);
  }

  public void deleteTokensByUser(String username) {
    storage.deleteByUser(username);
  }

  public void deleteTokenById(String tokenId, String username) throws IllegalAccessException, ObjectNotFoundException {
    OAuth2Authorization token = storage.findById(tokenId);
    if (token == null) {
      throw new ObjectNotFoundException("Token with Id %s doesn't exists");
    } else if (!token.getPrincipalName().equals(username)
               || !userAcl.isAdministrator(userAcl.getUserIdentity(username))) {
      throw new IllegalAccessException("Token with Id %s isn't managed by user");
    }
    storage.remove(token);
  }

  public int cleanExpiredTokens() {
    return storage.cleanExpiredTokens();
  }

}
