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
  <v-tooltip
    v-if="$te(`oAuthConsent.scope.${scope}.name`)"
    :disabled="!tooltip"
    bottom>
    <template #activator="{on, attrs}">
      <div
        v-on="on"
        v-bind="attrs"
        class="flex-grow-0 flex-shrink-1 width-fit-content">
        <v-checkbox
          v-model="checked"
          :readonly="isReadonly"
          :color="isReadonly && 'disabled'"
          :value="scope"
          :aria-label="$t(`oAuthConsent.scope.${scope}.name`)"
          :label="$t(`oAuthConsent.scope.${scope}.name`)"
          name="scope"
          class="font-weight-bold ms-n1 mt-2"
          on-icon="fa-check-square"
          off-icon="far fa-square" />
        <div class="ms-7 mt-n3 text-subtitle">{{ $t(`oAuthConsent.scope.${scope}.description`) }}</div>
      </div>
    </template>
    <span>{{ tooltip }}</span>
  </v-tooltip>
</template>
<script>
export default {
  props: {
    value: {
      type: Boolean,
      default: false,
    },
    scope: {
      type: String,
      default: null,
    },
    consentedScopes: {
      type: Array,
      default: null,
    },
  },
  data: () => ({
    checked: null,
  }),
  computed: {
    isMandatory() {
      return this.scope === 'openid';
    },
    isConsented() {
      return this.consentedScopes?.find?.(cs => cs === this.scope);
    },
    isReadonly() {
      return this.isMandatory || this.isConsented;
    },
    tooltip() {
      if (this.isMandatory) {
        return this.$t('oAuthConsent.mandatoryScope');
      } else if (this.isConsented) {
        return this.$t('oAuthConsent.consentedScope');
      } else {
        return null;
      }
    },
  },
  watch: {
    checked() {
      this.$emit('input', this.checked);
    },
  },
  created() {
    this.checked = this.value;
  },
};
</script>
