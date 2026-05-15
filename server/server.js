const express = require("express");
const http    = require("http");
const { Server } = require("socket.io");
const cors    = require("cors");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin:"*", methods:["GET","POST"] },
  perMessageDeflate: false,
  pingInterval: 10000, pingTimeout: 5000,
  maxHttpBufferSize: 2e6,
});

app.use(cors());
app.use(express.json());
app.get("/health", (_,res) => res.json({ok:true,ts:Date.now()}));

let bridgeSock = null, latestTele = null;

const bridgeNS = io.of("/bridge");
const dashNS   = io.of("/dash");

bridgeNS.on("connection", sock => {
  console.log(`[SERVER] bridge connected  ${sock.id}`);
  bridgeSock = sock;

  sock.on("telemetry",      d => { latestTele=d; dashNS.volatile.emit("telemetry",d); });
  sock.on("ip_blocked",     d => { console.log(`BLOCKED   ${d.ip} ${d.score}%`); dashNS.emit("ip_blocked",d); });
  sock.on("ip_unblocked",   d => { console.log(`UNBLOCKED ${d.ip} ${d.reason}`); dashNS.emit("ip_unblocked",d); });
  sock.on("sentry_trained", d => dashNS.emit("sentry_trained",d));
  sock.on("cmd_ack",        d => dashNS.emit("cmd_ack",d));

  sock.on("disconnect", r => {
    console.log(`[SERVER] bridge disconnected: ${r}`);
    bridgeSock = null;
  });
});

dashNS.on("connection", sock => {
  console.log(`[SERVER] dashboard  ${sock.id}`);
  if (latestTele) sock.emit("telemetry", latestTele);

  const fwd = (ev,d) => {
    if (!bridgeSock?.connected) { sock.emit("cmd_error",{ev,msg:"bridge offline"}); return; }
    bridgeSock.emit(ev, d);
    sock.emit("cmd_ack", {event:ev});
  };

  sock.on("cmd_unblock",       d => fwd("cmd_unblock",d));
  sock.on("cmd_set_prob_drop", d => fwd("cmd_set_prob_drop",d));
  sock.on("cmd_set_bypass",    d => fwd("cmd_set_bypass",d));
  sock.on("disconnect", () => console.log(`[SERVER] dashboard gone ${sock.id}`));
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`[SERVER] :${PORT}  /bridge ← bridge.py  /dash ← browser`);
});