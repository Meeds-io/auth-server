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
package io.meeds.oauth2.server.plugin;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

@Component
public class OAuthDcrGrantTypeValidator implements OAuthDcrValidator {

  @Override
  public void validate(RegisteredClient client) {
    if (CollectionUtils.isEmpty(client.getAuthorizationGrantTypes())
        || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
      String clientValue = StringUtils.join(client.getAuthorizationGrantTypes()
                                                  .stream()
                                                  .map(AuthorizationGrantType::getValue)
                                                  .toList(),
                                            ", ");
      throw new IllegalStateException("[DCR] Self Registration Client '%s' rejected. Reason: 'authorization_code' is mandatory as grant types. Passed value = '%s'".formatted(client.getClientName(),
                                                                                                                                                                              clientValue));
    }
  }

}
