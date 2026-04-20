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
    <help-label
      label="oauth.administration.clientsAllowedCorsOrigins.title"
      label-class="text-header"
      class="text-header"
      tooltip="oauth.administration.clientsAllowedCorsOrigins.tooltip">
      <template #helpContent>
        <div class="paragraph">{{ description }}</div>
      </template>
    </help-label>
    <v-tooltip :disabled="!allowAllRedirectUris" bottom>
      <template #activator="{on, attrs}">
        <div
          v-on="on"
          v-bind="attrs"
          class="d-flex align-center mt-4 mb-0">
          <v-switch
            v-model="allowAll"
            :label="$t('oauth.administration.clientsAllowedCorsOrigins.allowAny')"
            :disabled="allowAllRedirectUris"
            class="ma-0"
            @change="changeAllowAll" />
          <v-icon
            v-if="allowAllRedirectUris"
            size="18"
            color="primary"
            class="ms-2">
            fa-info-circle
          </v-icon>
        </div>
      </template>
      <span>{{ $t('oauth.administration.clientsAllowedCorsOrigins.input.disabled') }}</span>
    </v-tooltip>
    <v-card
      v-if="!allowAll"
      max-width="min(560px, 100%)"
      flat>
      <v-text-field
        v-model="uri"
        :aria-label="$t('oauth.administration.clientsAllowedCorsOrigins.inputTitle')"
        :placeholder="$t('oauth.administration.clientsAllowedCorsOrigins.inputPlaceholder')"
        name="allowedOrigin"
        class="pt-2 mb-2 border-box-sizing"
        type="text"
        outlined
        dense
        solo
        flat
        @click:append="addOrigin"
        @keypress.enter="addOrigin">
        <template #append>
          <v-btn
            class="me-n2"
            icon
            @click="addOrigin">
            <v-icon
              color="primary"
              size="18">
              fa-plus
            </v-icon>
          </v-btn>
        </template>
      </v-text-field>
      <v-list dense>
        <v-tooltip
          v-for="u in readonlyOrigins"
          :key="u"
          bottom>
          <template #activator="{on, attrs}">
            <v-list-item
              v-on="on"
              v-bind="attrs"
              :title="u"
              class="ps-0 pe-2"
              dense>
              <v-list-item-title class="disabled--text">
                {{ u }}
              </v-list-item-title>
            </v-list-item>
          </template>
          <span>{{ $t('oauth.administration.clientsAllowedCorsOrigins.readonlyOrigin') }}</span>
        </v-tooltip>
        <v-list-item
          v-for="u in origins"
          :key="u"
          :title="u"
          class="ps-0 pe-2"
          dense>
          <v-list-item-title>
            {{ u }}
          </v-list-item-title>
          <v-list-item-action class="my-auto">
            <v-btn
              :title="$t('oauth.administration.clientsAllowedCorsOrigins.delete')"
              icon
              @click="removeOrigin(u)">
              <v-icon
                color="primary"
                size="18"
                @click:append="removeOrigin">
                fa-minus
              </v-icon>
            </v-btn>
          </v-list-item-action>
        </v-list-item>
      </v-list>
    </v-card>
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
    originRegExp: new RegExp(/(https?:\/\/[^/]+(:\d{1,4})?)/g),
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
    computeOrigin(uri) {
      if (uri?.trim?.()?.length && this.originRegExp.test(uri)) {
        return uri.match(this.originRegExp)?.[0];
      }
    },
  },
};
</script>