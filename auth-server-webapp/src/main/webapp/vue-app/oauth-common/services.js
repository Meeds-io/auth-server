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

import * as oAuthClientService from './js/OAuthClientService.js';
import * as oAuthTokenService from './js/OAuthTokenService.js';
import * as oAuthConsentService from './js/OAuthConsentService.js';
import * as oAuthSettingService from './js/OAuthSettingService.js';

if (!Vue.prototype.$oAuthClientService) {
  window.Object.defineProperty(Vue.prototype, '$oAuthClientService', {
    value: oAuthClientService,
  });
}

if (!Vue.prototype.$oAuthTokenService) {
  window.Object.defineProperty(Vue.prototype, '$oAuthTokenService', {
    value: oAuthTokenService,
  });
}

if (!Vue.prototype.$oAuthConsentService) {
  window.Object.defineProperty(Vue.prototype, '$oAuthConsentService', {
    value: oAuthConsentService,
  });
}

if (!Vue.prototype.$oAuthSettingService) {
  window.Object.defineProperty(Vue.prototype, '$oAuthSettingService', {
    value: oAuthSettingService,
  });
}
