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
    <div class="font-weight-bold mb-2">
      {{ $t('oauth.administration.client.scopes') }}
    </div>
    <div
      v-for="scope in scopes"
      :key="scope">
      <v-switch
        v-model="scopeSelection[scope]"
        :loading="loading[scope]"
        :aria-label="$t(`oAuthConsent.scope.${scope}.name`)"
        :label="$t(`oAuthConsent.scope.${scope}.name`)"
        :title="$t(`oAuthConsent.scope.${scope}.description`)"
        :name="`scope-${scope}`"
        :disabled="scopeSelection[scope] && scope === 'openid'"
        class="mt-2"
        @change="updateScopes(scope)" />
    </div>
  </div>
</template>
<script>
export default {
  props: {
    client: {
      type: Object,
      default: null,
    },
    scopes: {
      type: Array,
      default: null,
    },
    create: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    loading: {},
    scopeSelection: {},
    clientScopesToCreate: ['openid'],
  }),
  computed: {
    clientScopes() {
      return this.client?.scopes || this.clientScopesToCreate;
    },
  },
  watch: {
    clientScopes: {
      immediate: true,
      handler() {
        this.scopes?.forEach?.(s => this.$set(this.scopeSelection, s, this.clientScopes?.includes?.(s)));
      },
    },
  },
  created() {
    if (this.create) {
      this.$emit('scopes-updated', this.clientScopesToCreate);
    }
  },
  methods: {
    async updateScopes(scope) {
      if (!this.create) {
        this.$set(this.loading, scope, true);
        try {
          await this.$oAuthClientService.updateClientScopes(this.client.uuid, this.scopes.filter(s => this.scopeSelection[s]));
          this.$emit('refresh');
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.scopes.updated'), 'success');
        } finally {
          this.$set(this.loading, scope, false);
        }
      } else {
        this.clientScopesToCreate = this.scopes.filter(s => this.scopeSelection[s]);
        this.$emit('scopes-updated', this.clientScopesToCreate);
      }
    },
  },
};
</script>