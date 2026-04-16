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
  <v-card class="border-color" flat>
    <v-card-title class="d-flex flex-nowrap align-center font-weight-bold">
      <span :title="token.id" class="text-truncate">{{ token.name || token.id }}</span>
      <v-tooltip v-if="expiredToken" bottom>
        <template #activator="{on, attrs}">
          <v-icon
            v-on="on"
            v-bind="attrs"
            color="warning"
            class="ms-auto ps-4">
            fa-exclamation-triangle
          </v-icon>
        </template>
        <span>{{ $t('UserSettings.oauth.expiredToken') }}</span>
      </v-tooltip>
    </v-card-title>
    <v-divider />
    <v-list dense>
      <v-list-item dense>
        <v-list-item-content class="font-weight-bold">{{ $t('UserSettings.oauth.tokenCreationDate') }}:</v-list-item-content>
        <v-list-item-content>
          <date-format
            :value="token.createdDate"
            :format="fullDateFormat" />
        </v-list-item-content>
      </v-list-item>
      <v-list-item dense>
        <v-list-item-content class="font-weight-bold">{{ $t('UserSettings.oauth.tokenExpirationDate') }}:</v-list-item-content>
        <v-list-item-content>
          <date-format
            :value="token.expirationDate"
            :format="fullDateFormat" />
        </v-list-item-content>
      </v-list-item>
      <v-list-item dense>
        <v-list-item-content class="font-weight-bold align-self-start">{{ $t('UserSettings.oauth.tokenAllowedScopes') }}:</v-list-item-content>
        <v-list-item-content class="mt-n3">
          <template v-for="scope in scopes">
            <div
              v-if="$te(`oAuthConsent.scope.${scope}.name`)"
              :key="scope">
              <v-checkbox
                v-model="scopeSelection[scope]"
                :value="scope"
                :aria-label="$t(`oAuthConsent.scope.${scope}.name`)"
                :label="$t(`oAuthConsent.scope.${scope}.name`)"
                :ripple="false"
                name="scope"
                class="ms-n1 mt-2"
                on-icon="fa-check-square"
                off-icon="far fa-square"
                readonly />
            </div>
          </template>
        </v-list-item-content>
      </v-list-item>
    </v-list>
    <v-card-actions class="d-flex justify-end pt-0">
      <v-btn
        :aria-label="$t('UserSettings.oauth.deleteToken')"
        :disabled="loading"
        class="no-border"
        color="error"
        outlined
        text
        small
        @click="$emit('delete-token', token.id)">
        <v-icon size="18" class="me-2">fa-trash</v-icon>
        {{ expiredToken ? $t('UserSettings.oauth.deleteToken') : $t('UserSettings.oauth.revokeToken') }}
      </v-btn>
    </v-card-actions>
  </v-card>
</template>
<script>
export default {
  props: {
    token: {
      type: Object,
      default: null,
    },
    scopes: {
      type: Array,
      default: null,
    },
    loading: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    expanded: false,
    scopeSelection: {},
    fullDateFormat: {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }
  }),
  computed: {
    tokenScopes() {
      return this.token?.scopes;
    },
    expiredToken() {
      return new Date(this.token?.expirationDate).getTime() - Date.now() < 0;
    },
  },
  watch: {
    scopes: {
      immediate: true,
      handler() {
        this.scopes?.forEach?.(s => this.$set(this.scopeSelection, s, this.tokenScopes?.includes?.(s) ? s : null));
      },
    },
  },
};
</script>
