<!--
 This file is part of the Meeds project (https://meeds.io/).

 Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 3 of the License, or (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
-->
<template>
  <v-app class="application-body pa-5 border-box-sizing">
    <main v-if="initialized">
      <div class="text-title mb-4">
        {{ $t('oauth.administration.title') }}
      </div>
      <div class="text-header mb-2">
        {{ $t('oauth.administration.permissions') }}
      </div>
      <oauth-administration-dcr-redirect-uris
        :redirect-uris="redirectUris"
        :allow-all-redirect-uris="allowAllRedirectUris"
        @redirect-uris-updated="handleRedirectUrisUpdated" />
      <oauth-administration-cimd-uris
        :cimd-uris="cimdUris"
        :allow-all-cimd-uris="allowAllCimdUris"
        @cimd-uris-updated="handleCimdUrisUpdated" />
      <oauth-administration-cors-origins
        :origins="origins"
        :allow-all-origins="allowAllOrigins"
        :redirect-uris="redirectUris"
        :allow-all-redirect-uris="allowAllRedirectUris"
        :clients="clients"
        @origins-updated="handleOriginsUpdated" />
      <div class="text-header mt-4">
        {{ $t('oauth.administration.oAuthClients') }}
      </div>
      <oauth-administration-clients
        :clients="clients"
        :scopes="orderedScopes"
        @refresh="refreshClients" />
    </main>
  </v-app>
</template>
<script>
export default {
  data: () => ({
    loading: false,
    initialized: false,
    clients: null,
    scopes: null,
    redirectUris: null,
    cimdUris: null,
    allowAllRedirectUris: false,
    allowAllCimdUris: false,
    origins: null,
    allowAllOrigins: false,
    issuerUrl: null,
  }),
  computed: {
    orderedScopes() {
      return this.scopes?.slice?.()?.sort?.((a, b) => {
        if (a === 'openid') {
          return -1;
        } else if (b === 'openid') {
          return 1;
        } else if (a.includes('read') && !b.includes('read')) {
          return -1;
        } else if (b.includes('read') && !a.includes('read')) {
          return 1;
        } else {
          return a.localeCompare(b);
        }
      });
    },
  },
  watch: {
    initialized() {
      this.$root.$applicationLoaded();
    },
    loading() {
      if (this.loading) {
        document.dispatchEvent(new CustomEvent('displayTopBarLoading'));      
      } else {
        document.dispatchEvent(new CustomEvent('hideTopBarLoading'));      
      }
    },
  },
  async created() {
    await this.init();
  },
  methods: {
    async init() {
      this.loading = true;
      try {
        [
          this.clients,
          this.scopes,
          this.redirectUris,
          this.allowAllRedirectUris,
          this.cimdUris,
          this.allowAllCimdUris,
          this.origins,
          this.allowAllOrigins,
        ] = await Promise.all([
          this.$oAuthClientService.getClients(true),
          this.$oAuthSettingService.getScopes(),
          this.$oAuthSettingService.getAllowedRedirectUris(),
          this.$oAuthSettingService.isAllowAllRedirectUris(),
          this.$oAuthSettingService.getAllowedCimdUris(),
          this.$oAuthSettingService.isAllowAllCimdUris(),
          this.$oAuthSettingService.getAllowedOrigins(),
          this.$oAuthSettingService.isAllowAllOrigins(),
        ]);
      } finally {
        this.loading = false;
        this.initialized = true;
      }
    },
    async handleRedirectUrisUpdated() {
      this.loading = true;
      try {
        this.redirectUris = await this.$oAuthSettingService.getAllowedRedirectUris();
        this.allowAllOrigins = await this.$oAuthSettingService.isAllowAllOrigins();
        this.allowAllRedirectUris = await this.$oAuthSettingService.isAllowAllRedirectUris();
      } finally {
        this.loading = false;
      }
    },
    async handleCimdUrisUpdated() {
      this.loading = true;
      try {
        this.cimdUris = await this.$oAuthSettingService.getAllowedCimdUris();
        this.allowAllCimdUris = await this.$oAuthSettingService.isAllowAllCimdUris();
      } finally {
        this.loading = false;
      }
    },
    async handleOriginsUpdated() {
      this.loading = true;
      try {
        this.origins = await this.$oAuthSettingService.getAllowedOrigins();
        this.allowAllOrigins = await this.$oAuthSettingService.isAllowAllOrigins();
      } finally {
        this.loading = false;
      }
    },
    async refreshClients() {
      this.loading = true;
      try {
        this.clients = await this.$oAuthClientService.getClients(true);
      } finally {
        this.loading = false;
      }
    },
    async refreshClient(clientId) {
      this.loading = true;
      try {
        const client = await this.$oAuthClientService.getClient(clientId, true);
        const index = this.clients.findIndex(c => c.uuid === clientId || c.id === clientId);
        this.clients.splice(index, 1, client);
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
