import { describe, expect, it, mock } from 'bun:test'

import { refreshKakaoOAuthToken } from './oauth-refresh'

const credentials = {
  accessToken: 'access-secret',
  refreshToken: 'refresh-secret',
  deviceUuid: 'a'.repeat(64),
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('refreshKakaoOAuthToken', () => {
  it('sends the Android sub-device refresh request and normalizes success', async () => {
    const fetchImpl = mock(async () =>
      jsonResponse({ status: 0, access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600 }),
    )

    const result = await refreshKakaoOAuthToken(credentials, {
      fetchImpl,
      requestId: () => 'request-id',
    })

    expect(result).toEqual({ accessToken: 'new-access', refreshToken: 'new-refresh', expiresIn: 3600 })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://katalk.kakao.com/android/account/oauth2_token.json')
    expect(init.method).toBe('POST')
    expect(init.headers).toMatchObject({
      A: 'android/25.9.2/ko',
      Authorization: `access-secret-${'a'.repeat(64)}`,
      'Content-Type': 'application/json; charset=utf-8',
      C: 'request-id',
    })
    expect(JSON.parse(String(init.body))).toEqual({
      access_token: 'access-secret',
      refresh_token: 'refresh-secret',
      grant_type: 'refresh_token',
    })
  })

  it('allows a successful response that does not rotate the refresh token', async () => {
    const fetchImpl = mock(async () => jsonResponse({ status: 0, access_token: 'new-access' }))

    await expect(refreshKakaoOAuthToken(credentials, { fetchImpl })).resolves.toEqual({
      accessToken: 'new-access',
      refreshToken: undefined,
      expiresIn: undefined,
    })
  })

  it('classifies an invalid refresh token without leaking either token', async () => {
    const fetchImpl = mock(async () => jsonResponse({ status: -950, message: 'rejected', secret: 'raw-secret' }, 401))

    let error: unknown
    try {
      await refreshKakaoOAuthToken(credentials, { fetchImpl })
    } catch (cause) {
      error = cause
    }

    expect(error).toMatchObject({ code: 'refresh_rejected', serverStatus: -950 })
    const rendered = String(error)
    expect(rendered).not.toContain(credentials.accessToken)
    expect(rendered).not.toContain(credentials.refreshToken)
    expect(rendered).not.toContain('raw-secret')
  })

  it('redacts tokens when the request times out', async () => {
    const fetchImpl = mock(async () => {
      throw Object.assign(new Error(`timeout ${credentials.accessToken} ${credentials.refreshToken}`), { name: 'AbortError' })
    })

    let error: unknown
    try {
      await refreshKakaoOAuthToken(credentials, { fetchImpl })
    } catch (cause) {
      error = cause
    }

    expect(error).toMatchObject({ code: 'refresh_timeout' })
    expect(String(error)).not.toContain(credentials.accessToken)
    expect(String(error)).not.toContain(credentials.refreshToken)
  })

  it('rejects a malformed success response without including the raw body', async () => {
    const fetchImpl = mock(async () => jsonResponse({ status: 0, access_token: '', raw: 'do-not-log' }))

    let error: unknown
    try {
      await refreshKakaoOAuthToken(credentials, { fetchImpl })
    } catch (cause) {
      error = cause
    }

    expect(error).toMatchObject({ code: 'refresh_malformed_response' })
    expect(String(error)).not.toContain('do-not-log')
  })
})
