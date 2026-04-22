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
        label="oauth.administration.clientsSelfRegistrationCIMD.title"
        tooltip="oauth.administration.clientsSelfRegistrationCIMD.tooltip"
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
    <oauth-administration-cimd-uris-drawer
      ref="drawer"
      :cimd-uris="cimdUris"
      :allow-all-cimd-uris="allowAllCimdUris"
      @saved="$emit('cimd-uris-updated')" />
  </div>
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
  computed: {
    description() {
      return this.$t('oauth.administration.clientsSelfRegistrationCIMD.description').replaceAll('\\n', '\n');
    },
  },
};
</script>
