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
    id="CimdUrisDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    right
    allow-expand
    no-x-scroll>
    <template #title>
      {{ $t('oauth.administration.clientsSelfRegistrationCIMD.drwerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <v-switch
          v-model="allowAll"
          :label="$t('oauth.administration.clientsSelfRegistrationCIMD.allowAny')"
          class="ma-0" />
        <v-alert
          v-if="allowAll"
          type="warning"
          icon="warning"
          outlined>
          <div v-sanitized-html="warningMessage" class="paragraph text-body"></div>
        </v-alert>
        <v-card
          v-else
          max-width="min(560px, 100%)"
          flat>
          <v-form
            ref="form"
            v-model="isValid"
            @submit.prevent.stop="0">
            <v-text-field
              v-model="uri"
              :aria-label="$t('oauth.administration.clientsSelfRegistrationCIMD.inputTitle')"
              :placeholder="$t('oauth.administration.clientsSelfRegistrationCIMD.inputPlaceholder')"
              :rules="rules"
              name="allowedCimdUri"
              class="mt-4 pt-0 border-box-sizing"
              type="text"
              outlined
              dense
              solo
              flat
              @click:append="addCimdUri"
              @keypress.enter="addCimdUri">
              <template v-if="uri && isValid" #append>
                <v-btn
                  :title="$t('oauth.administration.clientsSelfRegistrationCIMD.buttonTooltip')"
                  class="me-n2"
                  icon
                  @click="addCimdUri">
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
                  :title="$t('oauth.administration.clientsSelfRegistrationCIMD.deleteTooltip')"
                  icon
                  @click="removeCimdUri(u)">
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
    cimdUris: {
      type: Array,
      default: null,
    },
    allowAllCimdUris: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    drawer: false,
    expanded: false,
    allowAll: false,
    isValid: false,
    confirmDialog: false,
    uris: null,
    uri: null,
  }),
  computed: {
    rules() {
      return [
        v => !!v?.length && (this.isValidUrl(v) || this.$t('oauth.administration.invalidUrl')),
        v => !!v?.length && (!this.isUriExists(v) || this.$t('oauth.administration.clientsSelfRegistrationCIMD.alreadyExists')),
      ];
    },
    modified() {
      return this.allowAll !== this.allowAllCimdUris
        || JSON.stringify(this.cimdUris || []) !== JSON.stringify(this.uris || []);
    },
    warningMessage() {
      return this.$t('oauth.administration.clientsSelfRegistrationCIMD.allowAny.warning').replaceAll('\\n', '\n');
    },
  },
  methods: {
    open() {
      this.uris = this.cimdUris?.slice?.() || [];
      this.allowAll = this.allowAllCimdUris;
      this.$refs.drawer.open();
    },
    close() {
      this.$refs.drawer.close();
    },
    isUriExists(uri) {
      return this.uris?.includes?.(uri?.trim?.());
    },
    isValidUrl(uri) {
      return this.$utils.isValidUrl(uri);
    },
    async addCimdUri() {
      this.$refs.form.validate();
      await this.$nextTick();
      if (this.isValid) {
        this.uris.push(this.uri.trim());
        this.uri = null;
      }
    },
    removeCimdUri(uri) {
      const index = this.uris.findIndex(u => u === uri);
      if (index >=0 ) {
        this.uris.splice(index, 1);
      }
    },
    async save() {
      this.loading = true;
      try {
        if (this.allowAll !== this.allowAllCimdUris) {
          await this.$oAuthSettingService.setAllowAllCimdUris(this.allowAll);
        }
        if (!this.allowAll) {
          const urisToAdd = this.uris.filter(u => !this.cimdUris?.includes?.(u));
          if (urisToAdd?.length) {
            await Promise.all(urisToAdd.map(this.$oAuthSettingService.addAllowedCimdUri));
          }
          const urisToRemove = this.cimdUris.filter(u => !this.uris?.includes?.(u));
          if (urisToRemove?.length) {
            await Promise.all(urisToRemove.map(this.$oAuthSettingService.removeAllowedCimdUri));
          }
        }
        this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationCIMD.saved'), 'success');
        this.$emit('saved');
        this.close();
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>