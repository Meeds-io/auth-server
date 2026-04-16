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

export async function getTokens() {
  const resp = await fetch('/auth-server/rest/tokens', {
    credentials: 'include',
  });
  if (resp?.ok) {
    return await resp.json();
  } else {
    throw new Error('Server Request Error');
  }
}

export async function deleteTokensByUser() {
  const resp = await fetch('/auth-server/rest/tokens', {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

export async function deleteTokenById(id) {
  const resp = await fetch(`/auth-server/rest/tokens/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}

// Admin only
export async function deleteTokensByClient(clientId) {
  const resp = await fetch(`/auth-server/rest/tokens/byClient/${clientId}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!resp?.ok) {
    throw new Error('Server Request Error');
  }
}
