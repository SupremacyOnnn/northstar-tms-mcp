// Render's edge terminates HTTPS. Trust only its immediate hop, never an arbitrary chain.
function configureTransport(app, publicUrl, env = process.env) {
  const url = new URL(publicUrl);
  const production = env.NODE_ENV === 'production' || env.RENDER === 'true';
  if (url.username || url.password || url.search || url.hash ||
      (url.protocol !== 'https:' && (production || url.protocol !== 'http:' ||
        !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new Error('Public URL must use HTTPS (HTTP loopback is allowed locally only)');
  }
  const renderProxy = env.RENDER === 'true';
  app.set('trust proxy', renderProxy ? 1 : false);
  app.use((req, res, next) => {
    // Health checks contain no user data and can arrive internally over HTTP.
    if (production && req.path !== '/health') {
      if (!req.secure || (renderProxy && req.get('x-forwarded-proto') !== 'https')) {
        return res.status(400).json({error: 'HTTPS required'});
      }
      if (req.get('host') !== url.host) return res.status(400).json({error: 'Unexpected host'});
      res.set('Strict-Transport-Security', 'max-age=31536000');
    }
    // Koa must see only the validated protocol and canonical host, not client-supplied values.
    req.headers['x-forwarded-proto'] = req.secure ? 'https' : 'http';
    delete req.headers['x-forwarded-host'];
    next();
  });
  return {production, renderProxy};
}
module.exports = {configureTransport};
