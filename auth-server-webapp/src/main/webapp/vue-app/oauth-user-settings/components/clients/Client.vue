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
  <v-hover v-slot="{ hover }">
    <v-card
      :class="hover ? 'elevation-2' : 'elevation-0'"
      class="position-relative"
      @click="$emit('edit')">
      <div class="d-flex flex-nowrap align-center">
        <v-avatar
          class="me-4"
          size="40"
          tile>
          <v-img
            v-if="client.logoUrl"
            :src="client.logoUrl"
            transition="none"
            width="40"
            max-height="40"
            contain
            eager />
          <v-icon
            v-else
            size="40">
            fa-key
          </v-icon>
        </v-avatar>
        <v-card
          class="d-flex flex-column justify-space-between text-start text-truncate flex-grow-1"
          height="40"
          flat>
          <v-card-title class="text-title pa-0 ma-0 line-height-normal">
            {{ client.name }}
          </v-card-title>
          <v-card-subtitle v-if="client.url" class="pa-0 ma-0 line-height-normal width-min-content">
            <a
              :href="client.url"
              :aria-label="$t('UserSettings.oauth.visitWebsite')"
              rel="nofollow noreferrer noopener"
              target="_blank"
              class="d-flex">
              {{ $t('UserSettings.oauth.visitWebsite') }}
              <v-icon size="12" class="text-link ms-1">fa-external-link-alt</v-icon>
            </a>
          </v-card-subtitle>
        </v-card>
        <div
          v-if="hover"
          class="d-flex flex-no-wrap me-n2 mb-auto">
          <v-btn
            :title="$t('UserSettings.oauth.view')"
            class="ms-2"
            icon
            small
            @click="$emit('edit')">
            <v-icon size="16">fa-eye</v-icon>
          </v-btn>
        </div>
      </div>
      <v-card
        class="d-flex align-center mt-8 full-width"
        flat>
        <v-icon
          color="tertiary"
          size="20"
          class="me-2">
          fa-bolt
        </v-icon>
        {{ $t('UserSettings.oauth.lastUse') }}
        <div class="ms-1">
          <relative-date-format
            v-if="lastUsedDate"
            :value="lastUsedDate"
            class="text-body" />
          <span v-else class="disabled--text">
            {{ $t('UserSettings.oauth.notUsedYet') }}
          </span>
        </div>
      </v-card>
    </v-card>
  </v-hover>
</template>
<script>
export default {
  props: {
    client: {
      type: Object,
      default: null,
    },
  },
  data: () => ({
    loading: false,
    lastUsedDate: null,
  }),
  async created() {
    try {
      this.lastUsedDate = await this.$oAuthClientService.getClientLastUsage(this.client.uuid, eXo.env.portal.userName);
    } catch {
      this.lastUsedDate = null;
    }
  },
};
</script>