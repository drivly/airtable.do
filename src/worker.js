import { Router } from 'itty-router'

export const api = {
  icon: '💽',
  name: 'time.series.do',
  description: 'Simple time-series storage and analysis',
  url: 'https://time.series.do/api',
  type: 'https://apis.do/templates',
  endpoints: {
  },
  site: 'https://time.series.do',
  login: 'https://time.series.do/login',
  signup: 'https://time.series.do/signup',
  subscribe: 'https://time.series.do/subscribe',
  repo: 'https://github.com/drivly/time.series.do',
}

export const gettingStarted = [
  `If you don't already have a JSON Viewer Browser Extension, get that first:`,
  `https://extensions.do`,
]

export const examples = {
}

async function hash(str) {
  const encoder = new TextEncoder()
  const data = encoder.encode(str)
  const hashBuffer = await crypto.subtle.digest("SHA-256", data)
  return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
    .replace(/=/g, '') // remove =
    .replace(/\+/g, '-') // replace + with -
    .replace(/\//g, '_')
}

const gen_id = (l) => [...Array(l)].map(() => Math.random().toString(36)[2]).join('')

export default {
  fetch: async (req, env, ctx) => {
    const raw_url = req.url
    const { user, hostname, pathname, rootPath, pathSegments, query, method } = await env.CTX.fetch(req.clone()).then(res => res.json())
    const json=(e,t)=>(ctx.waitUntil(fetch(`https://debug.do/ingest/${req.headers.get("CF-Ray")}`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({request:{url:req.url,method:req.method,headers:Object.fromEntries(req.headers),query:Object.fromEntries(new URL(req.url).searchParams)},response:e,user,status: t?.status || 200})})),new Response(JSON.stringify(e,null,2),{headers:{"content-type":"application/json charset=utf-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET, POST, PUT, DELETE, OPTIONS","Access-Control-Allow-Headers":"Content-Type, Authorization, X-Requested-With","Cache-Control":"no-cache, no-store, must-revalidate"},...t}))
    
    if (rootPath) return json({ api, gettingStarted, examples, user })
    if (pathname.includes('favicon')) return new Response(null, { status: 302, headers: { location: 'https://uploads-ssl.webflow.com/60bee04bdb1a7a33432ce295/60ca2dd82fe6f273c60220ae_favicon_drivly.png' } })

    let namespace = pathSegments.shift()

    let config = await env.STORAGE.get(`config:namespaces:${namespace}`, { type: 'json' })

    const clientId = '89fed9be-0b10-4c74-8d30-731592283ea5'
    const redirectUri = `https://${hostname}/oauth-end`
    let last_cached = false // Dirty hack to know if we cached the response or not.

    const airtable = async (route, body, opt) => {
      // Request helper for airtable.
      last_cached = false
      let options = Object.assign({}, opt)
      const { access_token } = config
      const cache_ttl = options.cache_ttl || 60 * 60 * 24 // 1 day, by default we need to cache because god damn, airtables rate limits are low.

      const cache_key = `https://api.airtable.com/v0/${route}?____namespace-cache=${namespace}`
      const cache = caches.default

      const cached = await cache.match(cache_key)

      if (cached) {
        last_cached = true
        return await cached.json()
      }

      const res = await fetch(`https://api.airtable.com/v0/${route}`, {
        headers: {
          authorization: `Bearer ${access_token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        ...options,
      })

      if (res.status == 401) {
        // Refresh the token.
        const { refresh_token } = config

        const data = await fetch('https://airtable.com/oauth2/v1/token', {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: new URLSearchParams({
            client_id: clientId,
            refresh_token,
            grant_type: 'refresh_token',
          }),
        }).then(res => res.json())

        if (data.error) {
          return new Response(data.error.type, { status: 400 })
        }

        config.refresh_expires = new Date(Date.now() + data.expires_in * 1000).toISOString()
        config.lastUsed = new Date().toISOString()

        config.refresh_token = data.refresh_token
        config.access_token = data.access_token

        await env.STORAGE.put(`config:namespaces:${namespace}`, JSON.stringify(config))

        return await airtable(route, body, options)
      }

      // Cache the response.
      const cache_res = new Response(res.body, res)
      cache_res.headers.set('Cache-Control', `public, max-age=${cache_ttl}`)
      ctx.waitUntil(cache.put(cache_key, cache_res.clone()))

      return await res.json()
    }

    if (pathname.includes('oauth-end')) {
      const { code, state } = query

      const challenge = await env.STORAGE.get(`challenge:${state}`, { type: 'json' })

      if (!challenge) {
        return new Response('Invalid state', { status: 400 })
      }

      const data = await fetch('https://airtable.com/oauth2/v1/token', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: clientId,
          code_verifier: challenge.codeVerifier,
          code_challenge_method: 'S256',
          redirect_uri: redirectUri,
          code,
          grant_type: 'authorization_code',
        })
      }).then(res => res.json())

      if (data.error) {
        return new Response(data.error.type, { status: 400 })
      }

      config = data

      namespace = challenge.namespace

      await airtable('meta/bases')

      await env.STORAGE.put(`config:namespaces:${challenge.namespace}`, JSON.stringify({
        ...data,
        namespace,
        owner: user.email,
        createdAt: new Date().toISOString(),
        lastUsed: new Date().toISOString(),
        type: 'airtable',
        keys: [] // For authorization and sharing data without granting full write access.
      }))

      await env.STORAGE.delete(`challenge:${state}`)

      return json({ success: true })
    }

    if (!config) {
      // Run the setup for this namespace.
      // Oh god, Airtable's oAuth is so bad.
      // Like, i get it, but god damn.

      if (!user) {
        return Response.redirect(`https://${hostname}/login`)
      }

      // For state and code challenge, we need to generate a random string.
      const state = [...Array(128)].map(() => Math.random().toString(36)[2]).join('')
      const codeVerifier = [...Array(128)].map(() => Math.random().toString(36)[2]).join('')  

      const codeChallengeMethod = 'S256'

      const codeChallenge = await hash(codeVerifier)

      const scope = 'data.records:read data.records:write schema.bases:read'

      const api_url = new URL(`https://airtable.com/oauth2/v1/authorize`)

      api_url.searchParams.set('code_challenge', codeChallenge)
      api_url.searchParams.set('code_challenge_method', codeChallengeMethod)
      api_url.searchParams.set('state', state)
      api_url.searchParams.set('client_id', clientId)
      api_url.searchParams.set('redirect_uri', redirectUri)
      api_url.searchParams.set('response_type', 'code')
      // your OAuth integration register with these scopes in the management page
      api_url.searchParams.set('scope', scope)

      await env.STORAGE.put(
        `challenge:${state}`,
        JSON.stringify({
          namespace,
          codeVerifier,
          state,
        }),
        { expirationTtl: 60 * 10 } // 10 minutes
      )

      return new Response(null, {
        status: 302,
        headers: {
          location: api_url.toString(),
        },
      })
    }

    // All of our routes to manage and read from this airbase namespace.
    const router = new Router()

    if (!config.keys) {
      config = {
        ...config,
        owner: user.email,
        createdAt: new Date().toISOString(),
        lastUsed: new Date().toISOString(),
        type: 'airtable',
        keys: [] // For authorization and sharing data without granting full write access.
      }
    }

    // If the logged in user is the owner of this namespace, we can show them the key interface
    if (config.owner == user.email) {
      router.get('/:namespace', async (req, res) => {
        return json({
          api,
          data: {
            createdAt: config.createdAt,
            lastUsed: config.lastUsed,
            owner: config.owner,
            keys: config.keys.map(key => ({
              ...key,
              deleteKey: `https://${hostname}/${namespace}/keys/${key.id}/delete`
            })),
            createReadOnlyKey: `https://${hostname}/${namespace}/keys/new?readOnly=true`,
            createReadWriteKey: `https://${hostname}/${namespace}/keys/new?readOnly=false`,
          },
          user
        })
      })

      router.get('/:namespace/keys/new', async (req, res) => {
        const { readOnly } = query

        const key = {
          id: gen_id(12) + (readOnly ? '-ro' : '-rw'),
          readOnly: readOnly == 'true',
          createdAt: new Date().toISOString(),
        }

        await env.STORAGE.put(`config:namespaces:${namespace}`, JSON.stringify({
          ...config,
          keys: [...config.keys, key],
        }))

        return Response.redirect(`https://${hostname}/${namespace}`)
      })

      router.get('/:namespace/keys/:keyId/delete', async (req, res) => {
        const { keyId } = req.params

        await env.STORAGE.put(`config:namespaces:${namespace}`, JSON.stringify({
          ...config,
          keys: config.keys.filter(key => key.id != keyId),
        }))

        return Response.redirect(`https://${hostname}/${namespace}`)
      })
    } else {
      router.get('/:namespace', async (req, res) => {
        return Response.redirect(`https://${hostname}/${namespace}/bases?${ new URLSearchParams(query).toString() }`)
      })
    }

    const keyID = (req.headers.get('Authorization') || query.key || '').replace('Bearer ', '')

    const is_authorised = config.keys.some(key => key.id == keyID) || config.owner == user.email
    let is_read_only = config.keys.some(key => key.id == keyID && key.readOnly)
    
    if (user.email == config.owner) {
      is_read_only = false
    }

    if (!is_authorised) {
      return json({
        api,
        data: {
          error: 'You are not authorised to access this namespace.',
          message: 'Make sure you include a valid key in the Authorization header. e.g. Authorization: Bearer <key>',
          code: 'unauthorised',
        },
        user
      })
    }

    router.get('/:namespace/bases', async (req, res) => {
      const { namespace } = req.params

      const { bases } = await airtable(`meta/bases`)

      return json({
        api,
        data: bases.map(base => ({
          id: base.id,
          name: base.name,
          link: `https://${hostname}/${namespace}/bases/${base.id}?${ new URLSearchParams(query).toString() }`,
        })),
        user
      })
    })

    router.get('/:namespace/bases/:baseId', async (req, res) => {
      const { namespace, baseId } = req.params

      const { tables } = await airtable(`meta/bases/${baseId}/tables`)

      return json({
        api,
        data: tables.map(table => ({
          id: table.id,
          name: table.name,
          link: `https://${hostname}/${namespace}/bases/${baseId}/tables/${table.id}?${ new URLSearchParams(query).toString() }`,
        })),
        user
      })
    })

    router.get('/:namespace/bases/:baseId/tables/:tableId', async (req, res) => {
      const { namespace, baseId, tableId } = req.params

      const { records } = await airtable(`${baseId}/${tableId}?${ new URLSearchParams(Object.assign({ pageSize: 25 }, req.query)).toString() } `,
        undefined,
        {
          cache_ttl: 0 // Disable the cache since this route will change nearly every time. 
        }
      )

      if (query.expand) {
        // Unpack record references into the record itself.
        // Checking if the record is already in the response first to save API calls.

        const fields = query.expand.split(',')

        const get_record = async (id) => {
          if (records.find(record => record.id === id)) {
            return records.find(record => record.id === id) // Return the record if it's already in the response.
          }

          if (typeof id !== 'string') {
            return id
          }

          if (!id.includes('rec')) {
            return id // Not a record ID, so we can't get it.
          }

          let tbl = tableId
          let targetID = id

          if (id.includes('.')) {
            [tbl, targetID] = id.split('.')
          }

          return await airtable(`${baseId}/${tbl}/${targetID}`)
        }

        const new_records = []

        for (const record of records) {
          const new_record = { ...record }

          for (const [key, value] of Object.entries(record.fields)) {
            if (!fields.includes(key)) {
              continue
            }

            if (Array.isArray(value)) {
              if (value.length === 1) {
                // Since its just one item, we can just return the record.
                new_record.fields[key] = await get_record(value[0])
                continue
              }

              new_record.fields[key] = await Promise.all(value.map(async (id) => {
                return await get_record(id)
              }))
            } else {
              new_record.fields[key] = await get_record(value)
            }
          }

          new_records.push(new_record)
        }
      }

      return json({
        api,
        data: records,
        user
      })
    })

    router.post('/:namespace/bases/:baseId/tables/:tableId', async (req, res) => {
      if (is_read_only) return json({ api, data: { error: 'You are not authorised to write to this namespace.', message: 'This key is for read-only operations such as GET requests.', code: 'unauthorised' }, user }, { status: 403 })

      const { namespace, baseId, tableId } = req.params
      const { fields } = await req.json()

      const { records } = await airtable(
        `${baseId}/${tableId}`,
        {
          fields
        },
        {
          method: 'POST'
        }
      )

      return json({
        api,
        data: records,
        user
      })
    })

    return router.handle(req)
  }
}