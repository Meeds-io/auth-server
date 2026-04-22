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
package io.meeds.oauth2.server.util;

public class OAuthEventType {

  private OAuthEventType() {
    // Utils class
  }

  public static final String CLIENT_CREATED_EVENT                     = "oauth.clients.created";

  public static final String CLIENT_UPDATED_EVENT                     = "oauth.clients.updated";

  public static final String CLIENT_DELETED_EVENT                     = "oauth.clients.deleted";

  public static final String CLIENT_DISABLED_EVENT                    = "oauth.clients.disabled";

  public static final String CLIENT_ENABLED_EVENT                     = "oauth.clients.enabled";

  public static final String CLIENT_DISPLAYED_EVENT                   = "oauth.clients.displayed";

  public static final String CLIENT_HIDDEN_EVENT                      = "oauth.clients.hidden";

  public static final String CONSENT_CREATED                          = "oauth.consents.created";

  public static final String CONSENT_UPDATED                          = "oauth.consents.updated";

  public static final String CONSENT_DELETED                          = "oauth.consents.deleted";

  public static final String CONSENT_USED                             = "oauth.consents.used";

  public static final String TOKEN_CREATED                            = "oauth.tokens.created";

  public static final String TOKEN_UPDATED                            = "oauth.tokens.updated";

  public static final String TOKEN_DELETED                            = "oauth.tokens.deleted";

  public static final String TOKEN_USED                               = "oauth.tokens.used";

  public static final String ALLOWED_REDIRECT_URIS_ALL_MODIFIED_EVENT = "oauth.redirect-uri.all.modified";

  public static final String ALLOWED_REDIRECT_URI_ADDED_EVENT         = "oauth.redirect-uri.added";

  public static final String ALLOWED_REDIRECT_URI_REMOVED_EVENT       = "oauth.redirect-uri.removed";

  public static final String ALLOWED_CIMD_URIS_ALL_MODIFIED_EVENT     = "oauth.cimd-uri.all.modified";

  public static final String ALLOWED_CIMD_URI_ADDED_EVENT             = "oauth.cimd-uri.added";

  public static final String ALLOWED_CIMD_URI_REMOVED_EVENT           = "oauth.cimd-uri.removed";

  public static final String ALLOWED_ORIGINS_ALL_MODIFIED_EVENT       = "oauth.origin.all.modified";

  public static final String ALLOWED_ORIGIN_ADDED_EVENT               = "oauth.origin.added";

  public static final String ALLOWED_ORIGIN_REMOVED_EVENT             = "oauth.origin.removed";

}
