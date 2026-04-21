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
  <div>
    <div class="d-flex justify-space-between">
      <help-label
        label="oauth.administration.clientsAllowedCorsOrigins.title"
        tooltip="oauth.administration.clientsAllowedCorsOrigins.tooltip"
        class="py-2">
        <template #helpContent>
          <div class="paragraph">{{ description }}</div>
        </template>
      </help-label>
      <v-btn
        icon
        @click="$refs.drawer.open()">
        <v-icon size="18">fa-edit</v-icon>
      </v-btn>
    </div>
    <oauth-administration-origins-drawer
      ref="drawer"
      :origins="origins"
      :allow-all-origins="allowAllOrigins"
      :redirect-uris="redirectUris"
      :allow-all-redirect-uris="allowAllRedirectUris"
      :clients="clients"
      @saved="$emit('origins-updated')" />
  </div>
</template>
<script>
export default {
  props: {
    origins: {
      type: Array,
      default: null,
    },
    redirectUris: {
      type: Array,
      default: null,
    },
    clients: {
      type: Boolean,
      default: false,
    },
    allowAllOrigins: {
      type: Boolean,
      default: false,
    },
    allowAllRedirectUris: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    uri: null,
    allowAll: false,
  }),
  computed: {
    description() {
      return this.$t('oauth.administration.clientsAllowedCorsOrigins.description').replaceAll('\\n', '\n');
    },
    readonlyOrigins() {
      const origins = new Set();
      if (this.redirectUris?.length) {
        this.redirectUris.map(this.computeOrigin).filter(u => u).forEach(u => origins.add(u));
      }
      if (this.clients?.length) {
        this.clients.filter(c => c.enabled).map(c => c.redirectUris).forEach(redirectUris => {
          if (redirectUris?.length) {
            redirectUris.map(this.computeOrigin).filter(u => u).forEach(u => origins.add(u));
          }
        });
      }
      return Array.from(origins);
    },
  },
  watch: {
    allowAllOrigins: {
      immediate: true,
      handler() {
        this.allowAll = this.allowAllOrigins;
      },
    },
  },
  methods: {
    changeAllowAll() {
      this.$emit('allow-all', this.allowAll);
      this.uri = null;
    },
    addOrigin() {
      const origin = this.computeOrigin(this.uri);
      if (origin) {
        if (this.origins.includes(origin) || this.readonlyOrigins.includes(origin)) {
          this.$root.$emit('alert-message', this.$t('oauth.administration.clientsAllowedCorsOrigins.alreadyExists'), 'warning');
        } else {
          this.$emit('add-origin', origin);
          this.uri = null;
        }
      }
    },
    removeOrigin(uri) {
      this.$emit('remove-origin', uri);
    },
  },
};
</script>