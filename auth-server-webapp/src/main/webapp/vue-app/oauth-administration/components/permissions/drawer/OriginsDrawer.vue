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
  <exo-drawer
    id="OriginsDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    right
    allow-expand
    no-x-scroll>
    <template #title>
      {{ $t('oauth.administration.clientsAllowedCorsOrigins.drwerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <v-tooltip :disabled="!allowAllRedirectUris" bottom>
          <template #activator="{on, attrs}">
            <div
              v-on="on"
              v-bind="attrs"
              class="d-flex align-center">
              <v-switch
                v-model="allowAll"
                :label="$t('oauth.administration.clientsAllowedCorsOrigins.allowAny')"
                :disabled="allowAllRedirectUris"
                class="ma-0" />
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
          <v-form
            ref="form"
            v-model="isValid"
            @submit.prevent.stop="0">
            <v-text-field
              v-model="uri"
              :aria-label="$t('oauth.administration.clientsAllowedCorsOrigins.inputTitle')"
              :placeholder="$t('oauth.administration.clientsAllowedCorsOrigins.inputPlaceholder')"
              :rules="rules"
              name="allowedOrigin"
              class="mt-4 pt-0 border-box-sizing"
              type="text"
              outlined
              dense
              solo
              flat
              @click:append="addOrigin"
              @keypress.enter="addOrigin">
              <template v-if="uri && isValid" #append>
                <v-btn
                  :title="$t('oauth.administration.clientsAllowedCorsOrigins.buttonTooltip')"
                  class="me-n2"
                  icon
                  @click="addOrigin">
                  <v-icon
                    color="success"
                    size="18">
                    fa-check
                  </v-icon>
                </v-btn>
              </template>
            </v-text-field>
          </v-form>
          <v-list class="pa-0 mt-2" dense>
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
              v-for="u in uris"
              :key="u"
              class="ps-0 pe-2"
              dense>
              <v-list-item-title :title="u">
                {{ u }}
              </v-list-item-title>
              <v-list-item-action class="my-auto">
                <v-btn
                  :title="$t('oauth.administration.clientsAllowedCorsOrigins.deleteTooltip')"
                  icon
                  @click="removeOrigin(u)">
                  <v-icon
                    color="error"
                    size="18">
                    fa-minus
                  </v-icon>
                </v-btn>
              </v-list-item-action>
            </v-list-item>
          </v-list>
        </v-card>
      </div>
    </template>
    <template #footer>
      <div class="d-flex">
        <v-spacer />
        <v-btn
          class="btn"
          @click="close">
          {{ $t('oauth.administration.cancel') }}
        </v-btn>
        <v-btn
          :disabled="!modified"
          :loading="loading"
          @click="save"
          class="btn btn-primary ms-2">
          {{ $t('oauth.administration.save') }}
        </v-btn>
      </div>
    </template>
  </exo-drawer>
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
    drawer: false,
    expanded: false,
    allowAll: false,
    isValid: false,
    originRegExp: new RegExp(/(https?:\/\/[^/]+(:\d{1,4})?)/g),
    uris: null,
    uri: null,
  }),
  computed: {
    rules() {
      return [
        v => !!v?.length && (this.isValidUrl(v) || this.$t('oauth.administration.invalidUrl')),
        v => !!v?.length && (!this.isUriExists(v) || this.$t('oauth.administration.clientsAllowedCorsOrigins.alreadyExists')),
      ];
    },
    modified() {
      return this.allowAll !== this.allowAllOrigins
        || JSON.stringify(this.origins || []) !== JSON.stringify(this.uris || []);
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
  methods: {
    open() {
      this.uris = this.origins?.slice?.() || [];
      this.allowAll = this.allowAllOrigins;
      this.$refs.drawer.open();
    },
    close() {
      this.$refs.drawer.close();
    },
    isUriExists(uri) {
      return this.uris?.includes?.(this.computeOrigin(uri));
    },
    isValidUrl(uri) {
      return this.computeOrigin(uri) && this.$utils.isValidUrl(uri);
    },
    async addOrigin() {
      this.$refs.form.validate();
      await this.$nextTick();
      if (this.isValid) {
        const origin = this.computeOrigin(this.uri);
        if (origin) {
          this.uris.push(origin);
          this.uri = null;
        }
      }
    },
    removeOrigin(uri) {
      const index = this.uris.findIndex(u => u === uri);
      if (index >= 0) {
        this.uris.splice(index, 1);
      }
    },
    computeOrigin(uri) {
      if (uri?.trim?.()?.length && this.originRegExp.test(uri)) {
        return uri.match(this.originRegExp)?.[0];
      }
    },
    async save() {
      this.loading = true;
      try {
        if (this.allowAll !== this.allowAllOrigins) {
          await this.$oAuthSettingService.setAllowAllOrigins(this.allowAll);
        }
        if (!this.allowAll) {
          const urisToAdd = this.uris.filter(u => !this.origins?.includes?.(u));
          if (urisToAdd?.length) {
            await Promise.all(urisToAdd.map(this.$oAuthSettingService.addAllowedOrigin));
          }
          const urisToRemove = this.origins.filter(u => !this.uris?.includes?.(u));
          if (urisToRemove?.length) {
            await Promise.all(urisToRemove.map(this.$oAuthSettingService.removeAllowedOrigin));
          }
        }
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsAllowedCorsOrigins.saved'), 'success');
        this.$emit('saved');
        this.close();
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>