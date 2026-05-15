"use client";
/**
 * Sentinel-X Dashboard — app/page.jsx (Next.js 14)
 * Connects to /dash namespace on :3001
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { io } from "socket.io-client";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, ShieldOff, Zap, Activity, Cpu, HardDrive,
  Wifi, WifiOff, AlertTriangle, CheckCircle, RefreshCw,
  Settings, Clock, Eye, TrendingUp,
} from "lucide-react";
import {
  Chart as ChartJS, CategoryScale, LinearScale,
  PointElement, LineElement, Filler, Tooltip, Legend,
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, PointElement,
                 LineElement, Filler, Tooltip, Legend);

const SOCKET_URL   = process.env.NEXT_PUBLIC_SOCKET_URL || "http://localhost:3001";
const CHART_POINTS = 60;
const PPS_SPIKE    = 1_000_000;

// ── Helpers ───────────────────────────────────────────────────────────────────
const fmt = (n) => {
  if (n == null || isNaN(n)) return "—";
  if (n >= 1e9) return `${(n/1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n/1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n/1e3).toFixed(1)}K`;
  return String(Math.round(n));
};
const fmtTTL = (s) => {
  if (!s && s !== 0) return "--:--";
  return `${String(Math.floor(s/60)).padStart(2,"0")}:${String(Math.floor(s%60)).padStart(2,"0")}`;
};

// ── Drop Gauge ────────────────────────────────────────────────────────────────
function DropGauge({ pct = 0 }) {
  const p     = Math.min(Math.max(pct, 0), 100);
  const angle = (p / 100) * Math.PI;
  const r = 52, cx = 68, cy = 65;
  const ex = cx - r * Math.cos(angle);
  const ey = cy - r * Math.sin(angle);
  const color = p > 80 ? "#ef4444" : p > 40 ? "#f59e0b" : "#22c55e";
  return (
    <svg viewBox="0 0 136 80" className="w-full max-w-[180px] select-none">
      <path d={`M${cx-r},${cy} A${r},${r} 0 0,1 ${cx+r},${cy}`}
            fill="none" stroke="#1e293b" strokeWidth="9" strokeLinecap="round"/>
      {p > 0 && (
        <path d={`M${cx-r},${cy} A${r},${r} 0 ${angle>Math.PI/2?1:0},1 ${ex},${ey}`}
              fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
              style={{filter:`drop-shadow(0 0 5px ${color})`}}/>
      )}
      <text x={cx} y={cy+2} textAnchor="middle" fill={color}
            fontSize="18" fontWeight="800" fontFamily="monospace">{p.toFixed(1)}%</text>
      <text x={cx} y={cy+15} textAnchor="middle" fill="#475569"
            fontSize="7" fontFamily="sans-serif">DROP EFFICIENCY</text>
    </svg>
  );
}

// ── Metric Card ───────────────────────────────────────────────────────────────
function Card({ icon: Icon, label, value, sub, color="text-cyan-400", glow, pulse }) {
  return (
    <div className={`rounded-xl border bg-slate-900 p-4 flex flex-col gap-1
                     transition-all duration-300
                     ${glow?"border-red-500 shadow-[0_0_16px_rgba(239,68,68,0.2)]":"border-slate-800"}`}>
      <div className="flex items-center gap-1.5 text-slate-500 text-[10px] uppercase tracking-wider">
        <Icon size={10}/>{label}
        {pulse && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"/>}
      </div>
      <div className={`text-2xl font-mono font-bold ${color}`}>{value}</div>
      {sub && <div className="text-[10px] text-slate-600">{sub}</div>}
    </div>
  );
}

// ── Latency Card ──────────────────────────────────────────────────────────────
function LatencyCard() {
  const rows = [
    {label:"Linux iptables",    val:"~10ms",  color:"#64748b", w:100},
    {label:"Linux TC/NetFilter",val:"~1ms",   color:"#f59e0b", w:10},
    {label:"Sentinel-X XDP",    val:"<1µs",   color:"#22d3ee", w:0.02},
  ];
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-3
                      flex items-center gap-1.5"><Zap size={10}/>Latency Advantage</div>
      <div className="space-y-3">
        {rows.map(({label,val,color,w})=>(
          <div key={label}>
            <div className="flex justify-between text-[10px] mb-1">
              <span className="text-slate-400">{label}</span>
              <span className="font-mono" style={{color}}>{val}</span>
            </div>
            <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
              <motion.div className="h-full rounded-full"
                initial={{width:0}} animate={{width:`${Math.max(w,0.3)}%`}}
                transition={{duration:1.4,ease:"easeOut"}}
                style={{background:color,boxShadow:`0 0 5px ${color}`}}/>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-2 text-center text-[10px] font-mono text-emerald-400">
        10,000× faster than iptables
      </div>
    </div>
  );
}

// ── Traffic Chart ─────────────────────────────────────────────────────────────
function TrafficChart({ labels, ppsData, dropData, spiking }) {
  const data = {
    labels,
    datasets: [
      { label:"Incoming PPS", data:ppsData,  borderColor:"#38bdf8",
        backgroundColor:"rgba(56,189,248,0.07)", borderWidth:1.5,
        pointRadius:0, fill:true, tension:0.4 },
      { label:"Dropped PPS",  data:dropData, borderColor:"#f87171",
        backgroundColor:"rgba(248,113,113,0.07)", borderWidth:1.5,
        pointRadius:0, fill:true, tension:0.4 },
    ],
  };
  const opts = {
    responsive:true, maintainAspectRatio:false, animation:false,
    interaction:{mode:"index",intersect:false},
    plugins:{
      legend:{labels:{color:"#475569",boxWidth:10,font:{size:10}}},
      tooltip:{backgroundColor:"#0f172a",borderColor:"#1e293b",borderWidth:1,
               titleColor:"#94a3b8",bodyColor:"#e2e8f0",
               callbacks:{label:(c)=>` ${c.dataset.label}: ${fmt(c.raw)}`}},
    },
    scales:{
      x:{ticks:{color:"#334155",font:{size:9},maxTicksLimit:8,maxRotation:0},
         grid:{color:"#0f172a"}},
      y:{ticks:{color:"#334155",font:{size:9},callback:(v)=>fmt(v)},
         grid:{color:"#0f172a"},min:0},
    },
  };
  return (
    <div className={`rounded-xl border bg-slate-900 p-4 transition-all duration-300
                     ${spiking?"border-red-500 shadow-[0_0_20px_rgba(239,68,68,0.2)]"
                              :"border-slate-800"}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider
                         flex items-center gap-1.5">
          <Activity size={10}/>Live Traffic — {CHART_POINTS}s window
        </span>
        <AnimatePresence>
          {spiking && (
            <motion.span initial={{opacity:0}} animate={{opacity:[1,0.3,1]}}
                         exit={{opacity:0}} transition={{repeat:Infinity,duration:0.5}}
                         className="text-[10px] text-red-400 font-mono flex items-center gap-1">
              <TrendingUp size={10}/> SPIKE &gt;1M PPS
            </motion.span>
          )}
        </AnimatePresence>
      </div>
      <div className="h-44"><Line data={data} options={opts}/></div>
    </div>
  );
}

// ── Blocklist Table ───────────────────────────────────────────────────────────
function BlocklistTable({ entries, onUnblock }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider
                         flex items-center gap-1.5">
          <Shield size={10}/>Adaptive Blocklist
        </span>
        <span className="text-[10px] font-mono text-slate-600">
          {entries.length} / 65536
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px]">
          <thead>
            <tr className="border-b border-slate-800">
              {["IP Address","XGB Score","TTL","Status","Action"].map(h=>(
                <th key={h} className="px-4 py-2 text-left text-[9px] text-slate-600
                                       uppercase tracking-wider font-normal">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {entries.length===0 ? (
                <tr key="empty">
                  <td colSpan={5} className="px-4 py-10 text-center text-slate-700 text-[11px]">
                    No IPs currently blocked — all traffic passing
                  </td>
                </tr>
              ) : entries.map(e=>(
                <motion.tr key={e.ip}
                  initial={{opacity:0,y:-6}} animate={{opacity:1,y:0}}
                  exit={{opacity:0,x:30}}
                  className="border-b border-slate-800/40 hover:bg-slate-800/20">
                  <td className="px-4 py-2.5 font-mono text-cyan-300">{e.ip}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div className="h-full rounded-full transition-all"
                             style={{width:`${e.score}%`,
                                     background:e.score>85?"#ef4444":"#f59e0b"}}/>
                      </div>
                      <span className="font-mono text-slate-300 w-9 text-right">{e.score}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-amber-400 flex items-center gap-1">
                    <Clock size={9}/>{fmtTTL(e.ttl)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5
                                      rounded-full text-[9px] font-medium ${
                      e.status==="1% Sampling"
                        ?"bg-purple-950/60 text-purple-300 border border-purple-800/40"
                        :"bg-red-950/60 text-red-300 border border-red-800/40"
                    }`}>
                      {e.status==="1% Sampling"
                        ?<><Eye size={8}/>1% Sampling</>
                        :<><Shield size={8}/>Active Drop</>}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <button onClick={()=>onUnblock(e.ip)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded
                                       bg-slate-800 hover:bg-emerald-900/60
                                       text-slate-400 hover:text-emerald-300
                                       border border-slate-700 hover:border-emerald-700/50
                                       text-[9px] transition-all">
                      <RefreshCw size={8}/>Restore
                    </button>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Config Sidebar ────────────────────────────────────────────────────────────
function Sidebar({ probDrop, onProbDrop, bypass, onBypass, connected, cmdAck, cmdErr }) {
  const [local, setLocal] = useState(probDrop);
  useEffect(()=>setLocal(probDrop),[probDrop]);
  return (
    <aside className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-5 h-fit">
      <div className="text-[10px] text-slate-500 uppercase tracking-wider
                      flex items-center gap-1.5">
        <Settings size={10}/>Configuration
      </div>

      <div className={`flex items-center gap-2 text-[10px] rounded-lg px-2.5 py-1.5 border ${
            connected?"border-emerald-800/40 bg-emerald-950/30 text-emerald-400"
                     :"border-red-800/40 bg-red-950/30 text-red-400"}`}>
        {connected?<Wifi size={10}/>:<WifiOff size={10}/>}
        {connected?"Bridge connected":"Bridge offline"}
      </div>

      <AnimatePresence>
        {cmdAck && (
          <motion.div initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}}
                      className="text-[10px] text-emerald-400 flex items-center gap-1">
            <CheckCircle size={9}/>Command applied
          </motion.div>
        )}
        {cmdErr && (
          <motion.div initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}}
                      className="text-[10px] text-red-400 flex items-center gap-1">
            <AlertTriangle size={9}/>{cmdErr}
          </motion.div>
        )}
      </AnimatePresence>

      <div>
        <div className="flex justify-between text-[10px] mb-2">
          <span className="text-slate-400">Drop Threshold (PROB_DROP)</span>
          <span className="font-mono text-cyan-400">{local.toFixed(2)}</span>
        </div>
        <input type="range" min="0" max="1" step="0.01" value={local}
               onChange={e=>setLocal(+e.target.value)}
               onMouseUp={()=>onProbDrop(local)}
               onTouchEnd={()=>onProbDrop(local)}
               className="w-full h-1.5 rounded-full appearance-none cursor-pointer accent-cyan-400 bg-slate-700"/>
        <div className="flex justify-between text-[9px] text-slate-700 mt-1">
          <span>Sensitive (0)</span><span>Conservative (1)</span>
        </div>
      </div>

      <div className="space-y-1.5 text-[10px] text-slate-600 bg-slate-950/40
                      rounded-lg p-2.5 border border-slate-800/50">
        <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0"/>≥ {local.toFixed(2)} → XDP_DROP</div>
        <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-amber-500 flex-shrink-0"/>0.30–{local.toFixed(2)} → Grey zone</div>
        <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0"/>≤ 0.30 → FP ignored</div>
        <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-purple-500 flex-shrink-0"/>1% gate → auto-unblock</div>
      </div>

      <div>
        <div className="text-[10px] text-slate-400 mb-2">Global Kill-Switch</div>
        <button onClick={()=>onBypass(!bypass)}
                className={`w-full flex items-center justify-between px-3 py-2.5
                            rounded-lg border text-[10px] font-medium transition-all ${
                  bypass?"border-amber-700/60 bg-amber-950/40 text-amber-300"
                        :"border-slate-700 bg-slate-800/60 text-slate-400 hover:border-slate-600"
                }`}>
          <span className="flex items-center gap-2">
            {bypass?<ShieldOff size={11}/>:<Shield size={11}/>}
            {bypass?"BYPASS MODE (XDP_PASS ALL)":"ENFORCE MODE (XDP_DROP)"}
          </span>
          <div className={`w-9 h-5 rounded-full relative transition-colors flex-shrink-0 ${
                bypass?"bg-amber-500":"bg-slate-700"}`}>
            <motion.div animate={{x:bypass?16:2}}
                        transition={{type:"spring",stiffness:500,damping:30}}
                        className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow"/>
          </div>
        </button>
        <AnimatePresence>
          {bypass && (
            <motion.p initial={{opacity:0,height:0}} animate={{opacity:1,height:"auto"}}
                      exit={{opacity:0,height:0}}
                      className="text-[9px] text-amber-500 mt-1.5 overflow-hidden">
              ⚠ bypass_mode[0]=1 — XDP_DROP disabled kernel-wide
            </motion.p>
          )}
        </AnimatePresence>
      </div>
    </aside>
  );
}

// ── Toast Alerts ──────────────────────────────────────────────────────────────
function Toasts({ items }) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {items.map(a=>(
          <motion.div key={a.id}
            initial={{x:64,opacity:0}} animate={{x:0,opacity:1}} exit={{x:64,opacity:0}}
            className={`px-3.5 py-2 rounded-lg text-[10px] font-medium shadow-2xl ${
              a.type==="block"
                ?"bg-red-950/90 border border-red-700/50 text-red-200"
                :"bg-emerald-950/90 border border-emerald-700/50 text-emerald-200"
            }`}>
            {a.type==="block"
              ?`🚨 Blocked ${a.ip} (${a.score}%)`
              :`✅ Unblocked ${a.ip} — ${a.reason||"manual"}`}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

// ── MAIN ──────────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [connected,   setConnected]   = useState(false);
  const [tele,        setTele]        = useState(null);
  const [blocklist,   setBlocklist]   = useState([]);
  const [probDrop,    setProbDrop]    = useState(0.85);
  const [bypass,      setBypass]      = useState(false);
  const [spiking,     setSpiking]     = useState(false);
  const [sentryReady, setSentryReady] = useState(false);
  const [alerts,      setAlerts]      = useState([]);
  const [cmdAck,      setCmdAck]      = useState(false);
  const [cmdErr,      setCmdErr]      = useState(null);

  // Rolling chart data
  const [chartData, setChartData] = useState({
    labels: Array(CHART_POINTS).fill(""),
    pps:    Array(CHART_POINTS).fill(0),
    drops:  Array(CHART_POINTS).fill(0),
  });

  const socketRef = useRef(null);
  const alertId   = useRef(0);

  const toast = useCallback((a) => {
    const id = alertId.current++;
    setAlerts(p=>[...p.slice(-5),{...a,id}]);
    setTimeout(()=>setAlerts(p=>p.filter(x=>x.id!==id)), 5000);
  },[]);

  const flashAck = useCallback(()=>{
    setCmdAck(true); setTimeout(()=>setCmdAck(false),2000);
  },[]);

  useEffect(()=>{
    const socket = io(SOCKET_URL+"/dash",{
      transports:["websocket"], reconnectionDelay:1500,
    });
    socketRef.current = socket;

    socket.on("connect",    ()=>setConnected(true));
    socket.on("disconnect", ()=>setConnected(false));

    socket.on("telemetry",(d)=>{
      setTele(d);
      if(d.blocklist) setBlocklist(d.blocklist);
      if(d.prob_drop!=null) setProbDrop(d.prob_drop);
      if(d.sentry_ready)    setSentryReady(true);
      setSpiking((d.pps||0)>PPS_SPIKE);

      // Update rolling chart
      setChartData(prev=>{
        const now   = new Date().toLocaleTimeString("en-GB",{hour12:false});
        const lbls  = [...prev.labels.slice(1), now];
        const pps   = [...prev.pps.slice(1),   d.pps||0];
        const drops = [...prev.drops.slice(1),  d.drop_pps||0];
        return {labels:lbls, pps, drops};
      });
    });

    socket.on("ip_blocked",     d=>toast({type:"block",   ...d}));
    socket.on("ip_unblocked",   d=>toast({type:"unblock", ...d}));
    socket.on("sentry_trained", ()=>setSentryReady(true));
    socket.on("cmd_ack",        ()=>flashAck());
    socket.on("cmd_error",      d=>{
      setCmdErr(d.msg);
      setTimeout(()=>setCmdErr(null),3000);
    });

    return ()=>socket.disconnect();
  },[toast,flashAck]);

  const emit = useCallback((ev,data)=>socketRef.current?.emit(ev,data),[]);

  const handleUnblock  = useCallback(ip  =>emit("cmd_unblock",{ip}),[emit]);
  const handleProbDrop = useCallback(val =>{setProbDrop(val);emit("cmd_set_prob_drop",{value:val});},[emit]);
  const handleBypass   = useCallback(en  =>{setBypass(en);   emit("cmd_set_bypass",{enabled:en});},[emit]);

  const t = tele;

  return (
    <div className="min-h-screen bg-[#020817] text-slate-100 font-sans">
      {/* scanline */}
      <div className="pointer-events-none fixed inset-0 z-0 opacity-[0.012]"
           style={{background:"repeating-linear-gradient(0deg,transparent,transparent 2px,#fff 2px,#fff 4px)"}}/>

      {/* HEADER */}
      <header className="relative z-10 border-b border-slate-800/60 px-6 py-3
                          flex items-center justify-between
                          bg-[#020817]/90 backdrop-blur-sm sticky top-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20
                          flex items-center justify-center">
            <Shield size={16} className="text-cyan-400"/>
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-widest">SENTINEL-X</h1>
            <p className="text-[9px] text-slate-600 tracking-wider uppercase">
              eBPF · XDP · Real-time Firewall
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className={`text-[10px] flex items-center gap-1 ${
                sentryReady?"text-emerald-400":"text-amber-400 animate-pulse"}`}>
            {sentryReady
              ?<><CheckCircle size={9}/>Sentry armed</>
              :<><AlertTriangle size={9}/>Training…</>}
          </span>
          <span className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${
                connected?"bg-emerald-950/40 border-emerald-800/40 text-emerald-400"
                         :"bg-red-950/40 border-red-800/40 text-red-400"}`}>
            {connected?"● LIVE":"○ OFFLINE"}
          </span>
        </div>
      </header>

      <main className="relative z-10 p-4 max-w-[1440px] mx-auto space-y-4">

        {/* TOP METRICS */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="col-span-2 sm:col-span-1 rounded-xl border border-slate-800
                          bg-slate-900 flex items-center justify-center p-3">
            <DropGauge pct={t?.drop_pct??0}/>
          </div>
          <Card icon={Activity} label="Incoming PPS"
                value={fmt(t?.pps)} sub={`Total: ${fmt(t?.kernel_total)}`}
                color="text-cyan-400" glow={spiking} pulse={connected}/>
          <Card icon={Shield} label="Kernel Drops"
                value={fmt(t?.kernel_drops)} sub={`${blocklist.length} IPs blocked`}
                color="text-red-400"/>
          <Card icon={RefreshCw} label="Auto-Unblocked"
                value={fmt(t?.unblocked)} sub="TTL + 1% gate"
                color="text-purple-400"/>
          <Card icon={Cpu} label="CPU"
                value={`${t?.cpu_pct?.toFixed(1)??"—"}%`}
                sub="eBPF overhead minimal"
                color={(t?.cpu_pct??0)>80?"text-red-400":"text-emerald-400"}/>
          <Card icon={HardDrive} label="RAM"
                value={`${t?.ram_pct?.toFixed(1)??"—"}%`}
                sub="System memory"
                color={(t?.ram_pct??0)>85?"text-red-400":"text-slate-300"}/>
        </div>

        {/* LATENCY + CHART */}
        <div className="grid grid-cols-1 md:grid-cols-[210px_1fr] gap-3">
          <LatencyCard/>
          <TrafficChart labels={chartData.labels}
                        ppsData={chartData.pps}
                        dropData={chartData.drops}
                        spiking={spiking}/>
        </div>

        {/* TABLE + SIDEBAR */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_260px] gap-3">
          <BlocklistTable entries={blocklist} onUnblock={handleUnblock}/>
          <div className="space-y-3">
            <Sidebar probDrop={probDrop} onProbDrop={handleProbDrop}
                     bypass={bypass} onBypass={handleBypass}
                     connected={connected} cmdAck={cmdAck} cmdErr={cmdErr}/>
            <div className="grid grid-cols-2 gap-3">
              <Card icon={CheckCircle} label="FP Saved"
                    value={fmt(t?.fp_saved)} sub="Not dropped"
                    color="text-emerald-400"/>
              <Card icon={AlertTriangle} label="Grey Zone"
                    value={fmt(t?.grey_count)} sub="Logged only"
                    color="text-amber-400"/>
            </div>
          </div>
        </div>
      </main>

      <Toasts items={alerts}/>
    </div>
  );
}