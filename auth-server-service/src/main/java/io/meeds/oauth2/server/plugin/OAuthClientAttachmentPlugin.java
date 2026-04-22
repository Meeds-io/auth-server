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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.exoplatform.commons.exception.ObjectNotFoundException;
import org.exoplatform.portal.config.UserACL;
import org.exoplatform.services.security.Identity;
import org.exoplatform.social.attachment.AttachmentPlugin;
import org.exoplatform.social.attachment.AttachmentService;

import jakarta.annotation.PostConstruct;

@Component
public class OAuthClientAttachmentPlugin extends AttachmentPlugin {

  public static final String OBJECT_TYPE = OAuthClientAclPlugin.OBJECT_TYPE;

  @Autowired
  private UserACL            userAcl;

  @Autowired
  private AttachmentService  attachmentService;

  @PostConstruct
  public void init() {
    attachmentService.addPlugin(this);
  }

  @Override
  public String getObjectType() {
    return OBJECT_TYPE;
  }

  @Override
  public boolean hasAccessPermission(Identity userIdentity, String settingName) throws ObjectNotFoundException {
    return userAcl.hasAccessPermission(OBJECT_TYPE, settingName, userIdentity.getUserId());
  }

  @Override
  public boolean hasEditPermission(Identity userIdentity, String settingName) throws ObjectNotFoundException {
    return userAcl.hasEditPermission(OBJECT_TYPE, settingName, userIdentity.getUserId());
  }

  @Override
  public long getAudienceId(String settingName) throws ObjectNotFoundException {
    return 0;
  }

  @Override
  public long getSpaceId(String settingName) throws ObjectNotFoundException {
    return 0;
  }

}
