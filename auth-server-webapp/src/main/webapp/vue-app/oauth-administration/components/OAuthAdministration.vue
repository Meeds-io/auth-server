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
  <v-app class="application-body px-5 border-box-sizing">
    <main v-if="initialized">
      <v-row class="ma-0">
        <v-col
          cols="12"
          md="6"
          lg="4"
          class="ps-0 py-0 pe-4">
          <oauth-administration-redirect-uris
            :redirect-uris="redirectUris"
            :allow-all-redirect-uris="allowAllRedirectUris"
            class="me-2 mt-5"
            @add-redirect-uri="addRedirectUri"
            @remove-redirect-uri="removeRedirectUri"
            @allow-all="changeAllowAllRedirectUris" />
        </v-col>
        <v-col
          cols="12"
          md="6"
          lg="4"
          class="ps-0 py-0 pe-4">
          <oauth-administration-cimd-uris
            :cimd-uris="cimdUris"
            :allow-all-cimd-uris="allowAllCimdUris"
            class="me-2 mt-5"
            @add-cimd-uri="addCimdUri"
            @remove-cimd-uri="removeCimdUri"
            @allow-all="changeAllowAllCimdUris" />
        </v-col>
        <v-col
          cols="12"
          md="6"
          lg="4"
          class="pa-0">
          <oauth-administration-cors-origins
            :origins="origins"
            :allow-all-origins="allowAllOrigins"
            :cimd-uris="cimdUris"
            :allow-all-cimd-uris="allowAllCimdUris"
            :clients="clients"
            class="mt-5"
            @add-origin="addOrigin"
            @remove-origin="removeOrigin"
            @allow-all="changeAllowAllOrigins" />
        </v-col>
      </v-row>
      <oauth-administration-clients
        :clients="clients"
        :scopes="orderedScopes"
        @create-client="$refs.drawer.open()"
        @refresh-client="refreshClient"
        @refresh-clients="refreshClients" />
      <oauth-administration-client-drawer
        ref="drawer"
        :scopes="orderedScopes"
        @refresh-clients="refreshClients" />
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
    async changeAllowAllRedirectUris(allowAll) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.setAllowAllRedirectUris(allowAll);
        this.allowAllRedirectUris = await this.$oAuthSettingService.isAllowAllRedirectUris();
        this.allowAllOrigins = await this.$oAuthSettingService.isAllowAllOrigins();
        this.$root.$emit('alert-message', this.$t(`oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.allowAny.${this.allowAllRedirectUris ? 'enabled' : 'disabled'}`), 'success');
      } finally {
        this.loading = false;
      }
    },
    async changeAllowAllCimdUris(allowAll) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.setAllowAllCimdUris(allowAll);
        this.allowAllCimdUris = await this.$oAuthSettingService.isAllowAllCimdUris();
        this.$root.$emit('alert-message', this.$t(`oauth.administration.clientsSelfRegistrationCIMD.allowAny.${this.allowAllCimdUris ? 'enabled' : 'disabled'}`), 'success');
      } finally {
        this.loading = false;
      }
    },
    async changeAllowAllOrigins(allowAll) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.setAllowAllOrigins(allowAll);
        this.allowAllOrigins = await this.$oAuthSettingService.isAllowAllOrigins();
        this.$root.$emit('alert-message', this.$t(`oauth.administration.clientsAllowedCorsOrigins.allowAny.${this.allowAllOrigins ? 'enabled' : 'disabled'}`), 'success');
      } finally {
        this.loading = false;
      }
    },
    async addRedirectUri(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.addAllowedRedirectUri(uri);
        this.redirectUris = await this.$oAuthSettingService.getAllowedRedirectUris();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.added'), 'success');
      } finally {
        this.loading = false;
      }
    },
    async addCimdUri(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.addAllowedCimdUri(uri);
        this.cimdUris = await this.$oAuthSettingService.getAllowedCimdUris();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationCIMD.added'), 'success');
      } finally {
        this.loading = false;
      }
    },
    async addOrigin(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.addAllowedOrigin(uri);
        this.origins = await this.$oAuthSettingService.getAllowedOrigins();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsAllowedCorsOrigins.added'), 'success');
      } finally {
        this.loading = false;
      }
    },
    async removeRedirectUri(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.removeAllowedRedirectUri(uri);
        this.redirectUris = await this.$oAuthSettingService.getAllowedRedirectUris();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.removed'), 'success');
      } finally {
        this.loading = false;
      }
    },
    async removeCimdUri(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.removeAllowedCimdUri(uri);
        this.cimdUris = await this.$oAuthSettingService.getAllowedCimdUris();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationCIMD.removed'), 'success');
      } finally {
        this.loading = false;
      }
    },
    async removeOrigin(uri) {
      this.loading = true;
      try {
        await this.$oAuthSettingService.removeAllowedOrigin(uri);
        this.origins = await this.$oAuthSettingService.getAllowedOrigins();
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsAllowedCorsOrigins.removed'), 'success');
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
