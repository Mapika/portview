// Demo service: a plain web server on :3000.
const http = require('http');
http.createServer((_, res) => res.end('ok\n')).listen(3000, '127.0.0.1');
setInterval(() => {}, 1 << 30);
