/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2024 Meeds Association contact@meeds.io
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
package io.meeds.oauth2.server.scheduling;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.meeds.common.ContainerTransactional;
import io.meeds.oauth2.server.service.OAuthTokenService;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class OAuthTokenCleanupJob {

  @Autowired
  private OAuthTokenService oAuthTokenService;

  @Scheduled(cron = "${meeds.oauth.token.clean.cron:0 0 * * * *}")
  @ContainerTransactional
  public void run() {
    try {
      int tokensCount = oAuthTokenService.cleanExpiredTokens();
      if (tokensCount > 0) {
        log.info("{} expired OAuth tokens cleaned", tokensCount);
      }
    } catch (Exception e) {
      log.warn("Error while cleaning expired OAuth Tokens", e);
    }
  }

}
