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

export async function getClients(includeAll) {
  const params = includeAll ? '?all=true' : '';
  const resp = await fetch(`/auth-server/rest/clients${params}`, {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function getClient(id, includeAll) {
  const formData = new FormData();
  formData.append('clientId', id);
  if (includeAll) {
    formData.append('all', true);
  }
  const params = new URLSearchParams(formData).toString();
  const resp = await fetch(`/auth-server/rest/clients/by-param?${params}`, {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

// Admin only
export async function createClient(client) {
  const resp = await fetch('/auth-server/rest/clients', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      id: crypto.randomUUID(),
      ...client, 
    }),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function deleteClient(id) {
  const resp = await fetch(`/auth-server/rest/clients/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientName(id, name) {
  const formData = new FormData();
  formData.append('name', name);
  const resp = await fetch(`/auth-server/rest/clients/${id}/name`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientUrl(id, url) {
  const formData = new FormData();
  formData.append('url', url);
  const resp = await fetch(`/auth-server/rest/clients/${id}/url`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientLogoUrl(id, logoUrl) {
  const formData = new FormData();
  formData.append('logoUrl', logoUrl);
  const resp = await fetch(`/auth-server/rest/clients/${id}/logo-url`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientRedirectUris(id, redirectUris) {
  const formData = new FormData();
  redirectUris.forEach(r => formData.append('redirectUri', r));
  const resp = await fetch(`/auth-server/rest/clients/${id}/uris`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientScopes(id, scopes) {
  const formData = new FormData();
  scopes.forEach(s => formData.append('scope', s));
  const resp = await fetch(`/auth-server/rest/clients/${id}/scopes`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientVisibility(id, displayed) {
  const formData = new FormData();
  formData.append('displayed', displayed);
  const resp = await fetch(`/auth-server/rest/clients/${id}/display`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function updateClientActivation(id, enabled) {
  const formData = new FormData();
  formData.append('enabled', enabled);
  const resp = await fetch(`/auth-server/rest/clients/${id}/enable`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'PATCH',
    credentials: 'include',
    body: new URLSearchParams(formData).toString(),
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}
