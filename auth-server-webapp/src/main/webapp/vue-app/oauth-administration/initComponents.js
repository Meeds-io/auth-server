/*
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import OAuthAdministration from './components/OAuthAdministration.vue';

import OauthAdministrationRedirectUris from './components/OauthAdministrationRedirectUris.vue';
import OauthAdministrationCorsOrigins from './components/OauthAdministrationCorsOrigins.vue';
import OauthAdministrationCimdUris from './components/OauthAdministrationCimdUris.vue';

import OauthAdministrationClients from './components/OauthAdministrationClients.vue';
import OauthAdministrationClient from './components/OauthAdministrationClient.vue';
import OauthAdministrationClientRedirectUris from './components/OauthAdministrationClientRedirectUris.vue';
import OauthAdministrationClientScopes from './components/OauthAdministrationClientScopes.vue';
import OauthAdministrationClientLogo from './components/OauthAdministrationClientLogo.vue';

import OauthAdministrationClientDrawer from './components/OauthAdministrationClientDrawer.vue';

const components = {
  'oauth-administration': OAuthAdministration,

  'oauth-administration-redirect-uris': OauthAdministrationRedirectUris,
  'oauth-administration-cimd-uris': OauthAdministrationCimdUris,
  'oauth-administration-cors-origins': OauthAdministrationCorsOrigins,

  'oauth-administration-clients': OauthAdministrationClients,

  'oauth-administration-client': OauthAdministrationClient,
  'oauth-administration-client-redirect-uris': OauthAdministrationClientRedirectUris,
  'oauth-administration-client-scopes': OauthAdministrationClientScopes,
  'oauth-administration-client-logo': OauthAdministrationClientLogo,

  'oauth-administration-client-drawer': OauthAdministrationClientDrawer,
};

for (const key in components) {
  Vue.component(key, components[key]);
}
