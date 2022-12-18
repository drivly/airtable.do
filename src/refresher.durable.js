// DurableObject that will execute every 30 days to ensure the refresh token doesnt expire.

export class Refresher {
  constructor (state, env) {
    this.state = state
    this.env = env
  }

  async fetch (request) {
    // Get the refresh token from the state
    await this.state.storage.put('namespace', request.query.get('namespace'))

    await this.state.storage.setAlarm(
      new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
    )
  }

  async alarm() {
    const ns = await this.state.storage.get('namespace')
    const config = await this.env.STORAGE.get(`config:${ns}`)
  }
}