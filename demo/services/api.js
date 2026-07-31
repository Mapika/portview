// Demo service: a supervisor on :8080 with three worker processes.
//
// Each worker listens on its own port rather than sharing the primary's socket
// (which is what cluster does by default). That matters for the recording: tree
// mode in `portview watch` groups *rows*, and a worker only becomes a row if it
// holds a listening socket of its own. With a shared socket the workers are
// invisible and there is no tree to show.
// Workers are started with spawn("node", ...) rather than fork(). fork() uses
// process.execPath, which is an absolute path to the real interpreter — under
// nvm that is inside the user's home directory, and it would appear verbatim in
// the COMMAND column of a published recording. spawn passes "node" as argv[0],
// keeping the command line free of host paths.
const http = require('http');
const { spawn } = require('child_process');

const workerPort = process.env.WORKER_PORT;

if (workerPort) {
  http
    .createServer((_, res) => res.end('worker\n'))
    .listen(Number(workerPort), '127.0.0.1');
} else {
  http.createServer((_, res) => res.end('supervisor\n')).listen(8080, '127.0.0.1');
  for (const port of [8081, 8082, 8083]) {
    spawn('node', [__filename], {
      env: { ...process.env, WORKER_PORT: String(port) },
      stdio: 'ignore',
    });
  }
  setInterval(() => {}, 1 << 30);
}
