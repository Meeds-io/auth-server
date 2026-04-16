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
      label="oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.title"
      label-class="text-header"
      class="text-header"
      tooltip="oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.tooltip">
      <template #helpContent>
        <div class="paragraph">{{ description }}</div>
      </template>
    </help-label>
    <v-switch
      v-model="allowAll"
      :label="$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.allowAny')"
      @change="changeAllowAll" />
    <v-card
      v-if="!allowAllRedirectUris"
      max-width="min(560px, 100%)"
      flat>
      <v-text-field
        v-model="uri"
        :aria-label="$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.inputTitle')"
        :placeholder="$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.inputPlaceholder')"
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
      <v-list dense>
        <v-list-item
          v-for="u in redirectUris"
          :key="u"
          :title="u"
          class="ps-0 pe-2"
          dense>
          <v-list-item-title>
            {{ u }}
          </v-list-item-title>
          <v-list-item-action class="my-auto">
            <v-btn
              :title="$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.delete')"
              icon
              @click="removeRedirectUri(u)">
              <v-icon
                color="primary"
                size="18"
                @click:append="removeRedirectUri">
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
    redirectUris: {
      type: Array,
      default: null,
    },
    allowAllRedirectUris: {
      type: Boolean,
      default: false,
    },
  },
  computed: {
    description() {
      return this.$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.description').replaceAll('\\n', '\n');
    },
  },
  watch: {
    allowAllRedirectUris: {
      immediate: true,
      handler() {
        this.allowAll = this.allowAllRedirectUris;
      },
    },
  },
  data: () => ({
    uri: null,
    allowAll: false,
  }),
  methods: {
    changeAllowAll() {
      this.$emit('allow-all', this.allowAll);
      this.uri = null;
    },
    addRedirectUri() {
      if (this.uri?.trim?.()?.length) {
        if (this.redirectUris.includes(this.uri.trim())) {
          this.$root.$emit('alert-message', this.$t('oauth.administration.clientsSelfRegistrationAllowedSelfRegistration.alreadyExists'), 'warning');
        } else {
          this.$emit('add-redirect-uri', this.uri.trim());
          this.uri = null;
        }
      }
    },
    removeRedirectUri(uri) {
      this.$emit('remove-redirect-uri', uri);
    },
  },
};
</script>