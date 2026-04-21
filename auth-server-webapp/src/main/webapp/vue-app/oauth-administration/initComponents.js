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

import OauthAdministrationDcrRedirectUris from './components/permissions/DcrRedirectUris.vue';
import OauthAdministrationCorsOrigins from './components/permissions/CorsOrigins.vue';
import OauthAdministrationCimdUris from './components/permissions/CimdUris.vue';

import OauthAdministrationDcrRedirectUrisDrawer from './components/permissions/drawer/DcrRedirectUrisDrawer.vue';
import OauthAdministrationCimdUrisDrawer from './components/permissions/drawer/CimdUrisDrawer.vue';
import OauthAdministrationOriginsDrawer from './components/permissions/drawer/OriginsDrawer.vue';

import OauthAdministrationClients from './components/clients/Clients.vue';
import OauthAdministrationClient from './components/clients/Client.vue';
import OauthAdministrationClientLogoInput from './components/clients/ClientLogoInput.vue';
import OauthAdministrationClientDrawer from './components/clients/drawer/ClientDrawer.vue';

const components = {
  'oauth-administration': OAuthAdministration,

  'oauth-administration-dcr-redirect-uris': OauthAdministrationDcrRedirectUris,
  'oauth-administration-cimd-uris': OauthAdministrationCimdUris,
  'oauth-administration-cors-origins': OauthAdministrationCorsOrigins,

  'oauth-administration-dcr-redirect-uris-drawer': OauthAdministrationDcrRedirectUrisDrawer,
  'oauth-administration-cimd-uris-drawer': OauthAdministrationCimdUrisDrawer,
  'oauth-administration-origins-drawer': OauthAdministrationOriginsDrawer,

  'oauth-administration-clients': OauthAdministrationClients,

  'oauth-administration-client': OauthAdministrationClient,
  'oauth-administration-client-logo-input': OauthAdministrationClientLogoInput,
  'oauth-administration-client-drawer': OauthAdministrationClientDrawer,
};

for (const key in components) {
  Vue.component(key, components[key]);
}
