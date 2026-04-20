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
    <div class="font-weight-bold">
      {{ $t('oauth.administration.client.redirectUris') }}
    </div>
    <v-text-field
      v-model="uri"
      :aria-label="$t('oauth.administration.client.redirectUris.inputTitle')"
      :placeholder="$t('oauth.administration.client.redirectUris.inputPlaceholder')"
      name="allowedRedirectUri"
      class="pt-2 mb-2 border-box-sizing"
      type="text"
      outlined
      dense
      solo
      flat
      @click:append="addRedirectUri"
      @keypress.enter="addRedirectUri">
      <template #append>
        <v-btn
          :disabled="loading"
          class="me-n2"
          icon
          @click="addRedirectUri">
          <v-icon
            color="primary"
            size="18">
            fa-plus
          </v-icon>
        </v-btn>
      </template>
    </v-text-field>
    <v-list class="pa-0" dense>
      <v-list-item
        v-for="u in redirectUris"
        :key="u"
        :title="u"
        class="ps-0 pe-2"
        dense>
        <v-list-item-title class="pb-1">
          {{ u }}
        </v-list-item-title>
        <v-list-item-action class="my-auto ms-1">
          <v-btn
            :title="$t('oauth.administration.client.redirectUris.delete')"
            :disabled="loading"
            icon
            @click="removeRedirectUri(u)">
            <v-icon
              color="primary"
              size="18">
              fa-minus
            </v-icon>
          </v-btn>
        </v-list-item-action>
      </v-list-item>
    </v-list>
  </div>
</template>
<script>
export default {
  props: {
    client: {
      type: Array,
      default: null,
    },
    create: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    uri: null,
    loading: false,
    clientRedirectUris: [],
  }),
  computed: {
    redirectUris() {
      return this.client?.redirectUris || this.clientRedirectUris;
    },
  },
  methods: {
    addRedirectUri() {
      if (this.uri?.trim?.()?.length) {
        if (this.redirectUris.includes(this.uri.trim())) {
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.urlAlreadyExists'), 'warning');
        } else if (!this.create) {
          this.updateRedirectUris([this.uri.trim(), ...this.redirectUris], true);
          this.uri = null;
        } else {
          this.clientRedirectUris.push(this.uri.trim());
          this.$emit('redirect-uris-updated', this.clientRedirectUris);
          this.uri = null;
        }
      }
    },
    removeRedirectUri(uri) {
      if (!this.create) {
        this.updateRedirectUris(this.redirectUris.filter(u => u !== uri));
      } else {
        this.clientRedirectUris = this.clientRedirectUris.filter(u => u !== uri);
        this.$emit('redirect-uris-updated', this.clientRedirectUris);
      }
    },
    async updateRedirectUris(uris, add) {
      this.loading = true;
      try {
        await this.$oAuthClientService.updateClientRedirectUris(this.client?.uuid, uris);
        this.$emit('refresh');
        this.$root.$emit('alert-message', add ? this.$t('oauth.administration.client.url.added') : this.$t('oauth.administration.client.url.removed'), 'success');
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>