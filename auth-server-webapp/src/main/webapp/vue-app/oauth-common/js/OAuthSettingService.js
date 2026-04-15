/*
 * This file is part of the Meeds project (https://meeds.io/).
 * 
 * Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

export async function getScopes() {
  const resp = await fetch('/auth-server/rest/settings/scopes', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

// Admin only
export async function getIssuerUrl() {
  const resp = await fetch('/auth-server/rest/settings/issuer-url', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getPublicClientSettings() {
  const resp = await fetch('/auth-server/rest/settings/public-client-settings', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getPublicClientTokenSettings() {
  const resp = await fetch('/auth-server/rest/settings/public-token-settings', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getAllowedRedirectUris() {
  const resp = await fetch('/auth-server/rest/settings/allowed-redirect-uris', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getAllowedCimdUris() {
  const resp = await fetch('/auth-server/rest/settings/allowed-cimd-uris', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getAllowedOrigins() {
  const resp = await fetch('/auth-server/rest/settings/allowed-origins', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function isAllowAllRedirectUris() {
  const resp = await fetch('/auth-server/rest/settings/allowed-redirect-uris/all', {
    credentials: 'include',
  });
  if (resp?.ok) {
    const allowed = await resp.text();
    return allowed === 'true';
  } else {
    throw new Error('Server Request Error');
  }
}

export async function isAllowAllCimdUris() {
  const resp = await fetch('/auth-server/rest/settings/allowed-cimd-uris/all', {
    credentials: 'include',
  });
  if (resp?.ok) {
    const allowed = await resp.text();
    return allowed === 'true';
  } else {
    throw new Error('Server Request Error');
  }
}

export async function isAllowAllOrigins() {
  const resp = await fetch('/auth-server/rest/settings/allowed-origins/all', {
    credentials: 'include',
  });
  if (resp?.ok) {
    const allowed = await resp.text();
    return allowed === 'true';
  } else {
    throw new Error('Server Request Error');
  }
}

export async function setAllowAllRedirectUris(allowAll) {
  const resp = await fetch('/auth-server/rest/settings/allowed-redirect-uris/all', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: `allowAll=${allowAll}`,
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function setAllowAllCimdUris(allowAll) {
  const resp = await fetch('/auth-server/rest/settings/allowed-cimd-uris/all', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: `allowAll=${allowAll}`,
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function setAllowAllOrigins(allowAll) {
  const resp = await fetch('/auth-server/rest/settings/allowed-origins/all', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: `allowAll=${allowAll}`,
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function addAllowedRedirectUri(uri) {
  const formData = new FormData();
  formData.append('uri', uri);
  const resp = await fetch('/auth-server/rest/settings/allowed-redirect-uris', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function addAllowedCimdUri(uri) {
  const formData = new FormData();
  formData.append('uri', uri);
  const resp = await fetch('/auth-server/rest/settings/allowed-cimd-uris', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function addAllowedOrigin(origin) {
  const formData = new FormData();
  formData.append('origin', origin);
  const resp = await fetch('/auth-server/rest/settings/allowed-origins', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function removeAllowedRedirectUri(uri) {
  const formData = new FormData();
  formData.append('uri', uri);
  const resp = await fetch('/auth-server/rest/settings/allowed-redirect-uris', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'DELETE',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function removeAllowedCimdUri(uri) {
  const formData = new FormData();
  formData.append('uri', uri);
  const resp = await fetch('/auth-server/rest/settings/allowed-cimd-uris', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'DELETE',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function removeAllowedOrigin(origin) {
  const formData = new FormData();
  formData.append('origin', origin);
  const resp = await fetch('/auth-server/rest/settings/allowed-origins', {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'DELETE',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}
