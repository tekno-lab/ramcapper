/* RamCapper – shared runtime: layout shell, API, formatting, charts, status polling */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const GB=1073741824, MB=1048576;
const PALETTE=['#5b8cff','#f59f45','#34c38f','#e5609a','#9b7bea','#e3c545','#3cc8c8','#ef6a64','#8fd14f','#c58b6a'];
const OTHER='#6b7686';
const PAGE=document.body.dataset.page||'index';
const S={range:'1h',now:null,hist:null,cfg:null,hidden:new Set(),colors:{},lastEv:null,info:null};
let colorIdx=0;
const colorOf=n=>n==='other'?OTHER:(S.colors[n]||(S.colors[n]=PALETTE[colorIdx++%PALETTE.length]));

async function api(path,body){
  const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json','X-RamCapper':'1'},body:JSON.stringify(body)}:{});
  if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||r.status);
  return r.json();
}
function fmtB(b){return b>=GB?(b/GB).toFixed(2)+' GB':Math.round(b/MB)+' MB'}
function fmtD(b){const s=b>=0?'+':'−';b=Math.abs(b);return b<MB?'±0':s+(b>=GB?(b/GB).toFixed(2)+' GB':Math.round(b/MB)+' MB')}
function fmtT(ts,full){const sec=S.range==='5m'||full;const d=new Date(ts*1000);
  const t=d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',...(sec?{second:'2-digit'}:{})});
  return (S.range==='24h'||S.range==='3d'||full)?d.toLocaleDateString([],{month:'short',day:'numeric'})+' '+t:t}
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('show');clearTimeout(toast.h);toast.h=setTimeout(()=>t.classList.remove('show'),3800)}
const niceMax=v=>{const p=Math.pow(10,Math.floor(Math.log10(v||1)));const n=v/p;return(n<=1?1:n<=2?2:n<=5?5:10)*p};
const icon=n=>`<img class="ico" loading="lazy" src="/api/icon?name=${encodeURIComponent(n)}" alt="" onerror="this.style.visibility='hidden'">`;
const ACTL={notify:'alert',trim:'trim',cap:'hard cap',terminate:'terminate'};
const mod=n=>!!(S.cfg&&S.cfg.modules&&S.cfg.modules[n]);

/* ---------------------------------------------------------------- shell */
const NAV=[
  ['index','/','Memory','<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 11v2M11 11v2M15 11v2M7 17v2M11 17v2M15 17v2"/>'],
  ['limiter','/limiter.html','Limiter','<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>'],
  ['network','/network.html','Network','<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>'],
  ['storage','/storage.html','Storage','<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'],
  ['events','/events.html','Events','<path d="M5 6h14M5 12h14M5 18h9"/>'],
  ['settings','/settings.html','Settings','<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M18.7 5.3l-2.1 2.1M7.4 16.6l-2.1 2.1"/>'],
];
document.body.insertAdjacentHTML('afterbegin',`
<aside class="side">
  <a class="brand" href="/"><img src="/logo.png" alt=""><span><b>RamCapper</b><small id="ver"> </small></span></a>
  <nav>${NAV.map(([k,h,l,p])=>`<a href="${h}" class="${k===PAGE?'on':''}"><svg viewBox="0 0 24 24">${p}</svg><span>${l}</span>${k==='limiter'?'<em class="nb" id="nb-limiter" style="display:none"></em>':''}</a>`).join('')}</nav>
  <div class="sidefoot">
    <div class="sbox"><div class="live" id="conn"><b></b><span>connecting…</span></div>
      <div class="t" style="margin-top:9px"><span>System RAM</span><b id="side-pct">–</b></div>
      <div class="bar"><i id="side-bar" style="width:0;background:var(--ok)"></i></div>
      <div class="t" style="margin-top:9px" id="selfchip" title="RamCapper's own resource use"><span>RamCapper</span><b>…</b></div>
      <div class="sub hide" id="capchip" style="margin-top:7px"></div>
    </div>
    <div class="sbox hide" id="adminbox"><div style="margin-bottom:7px">Standard permissions: elevated and system processes can't be trimmed or capped.</div><button class="btn sm primary block" id="b-admin">Restart as administrator</button></div>
    <div class="row" style="gap:8px"><button class="btn sm grow" id="btn-close" title="Close this window. RamCapper keeps monitoring and enforcing limits in the background.">Close window</button><button class="btn sm danger grow" id="btn-quit" title="Fully exit RamCapper: stops monitoring, limits and scanning">⏻ Quit</button></div>
  </div>
</aside>`);
document.body.insertAdjacentHTML('beforeend','<div class="toast" id="toast"></div>');
document.title=(document.body.dataset.title||'RamCapper')+' · RamCapper';

/* ---------------------------------------------------------------- charts */
function drawChart(cv,d,o={}){
  const dpr=window.devicePixelRatio||1,w=cv.clientWidth,h=cv.clientHeight;
  if(cv.width!==Math.round(w*dpr)||cv.height!==Math.round(h*dpr)){cv.width=Math.round(w*dpr);cv.height=Math.round(h*dpr)}
  const g=cv.getContext('2d');g.setTransform(dpr,0,0,dpr,0,0);g.clearRect(0,0,w,h);
  const css=getComputedStyle(document.documentElement),grid=css.getPropertyValue('--grid').trim(),muted=css.getPropertyValue('--muted').trim(),bad=css.getPropertyValue('--bad').trim();
  const L=54,R=10,T=8,B=24,pw=w-L-R,ph=h-T-B;
  cv._m={d,L,R,T,B,pw,ph,o};
  const vis=d.series.filter(s=>!S.hidden.has(s.name));
  const n=d.t.length;
  const cum=[];let prev=new Array(n).fill(0);
  vis.forEach(s=>{const c=prev.map((p,i)=>p+s.v[i]);cum.push(c);prev=c});
  const peak=Math.max(1,...prev);
  const yMax=o.yMax||niceMax(peak*1.12);
  const X=t=>L+(t-d.start)/Math.max(1,d.end-d.start)*pw, Y=v=>T+ph-(Math.min(v,yMax)/yMax)*ph;
  g.font='11.5px "Segoe UI",sans-serif';g.textBaseline='middle';
  const unit=yMax>=GB*1.5?GB:MB, step=niceMax(yMax/unit/4)*(unit);
  for(let v=0;v<=yMax+1;v+=step){const y=Y(v);g.strokeStyle=grid;g.lineWidth=1;g.beginPath();g.moveTo(L,y+.5);g.lineTo(w-R,y+.5);g.stroke();
    g.fillStyle=muted;g.textAlign='right';g.fillText(unit===GB?(v/GB).toFixed(v%GB?1:0)+' GB':Math.round(v/MB)+' MB',L-8,y)}
  g.textAlign='center';g.textBaseline='top';
  const ticks=Math.max(2,Math.floor(pw/110));
  for(let i=0;i<=ticks;i++){const t=d.start+(d.end-d.start)*i/ticks;g.fillStyle=muted;g.fillText(fmtT(t),Math.min(w-R-22,Math.max(L+22,X(t))),h-B+7)}
  if(n){
    vis.forEach((s,k)=>{
      g.beginPath();
      for(let i=0;i<n;i++){const x=X(d.t[i]),y=Y(cum[k][i]);i?g.lineTo(x,y):g.moveTo(x,y)}
      for(let i=n-1;i>=0;i--){g.lineTo(X(d.t[i]),Y(k?cum[k-1][i]:0))}
      g.closePath();g.fillStyle=colorOf(s.name)+'cc';g.fill();
      g.beginPath();for(let i=0;i<n;i++){const x=X(d.t[i]),y=Y(cum[k][i]);i?g.lineTo(x,y):g.moveTo(x,y)}
      g.strokeStyle=colorOf(s.name);g.lineWidth=1.4;g.stroke();
    });
  }else{g.fillStyle=muted;g.textAlign='center';g.textBaseline='middle';g.fillText('Collecting data…',L+pw/2,T+ph/2)}
  if(o.threshold){const y=Y(o.threshold);g.setLineDash([5,4]);g.strokeStyle=bad;g.lineWidth=1.2;g.beginPath();g.moveTo(L,y);g.lineTo(w-R,y);g.stroke();g.setLineDash([]);
    g.fillStyle=bad;g.textAlign='right';g.textBaseline='bottom';g.fillText('auto-trim',w-R-4,y-2)}
  (d.events||[]).forEach(e=>{if(e.ts<d.start)return;const x=X(e.ts),y=T+ph;g.fillStyle=({kill:bad,notify:'#f0b34a'}[e.kind])||'#5b8cff';
    g.beginPath();g.moveTo(x,y-9);g.lineTo(x-5,y);g.lineTo(x+5,y);g.closePath();g.fill()});
  if(cv._hover!=null&&n){
    const i=cv._hover,x=X(d.t[i]);g.strokeStyle=muted;g.lineWidth=1;g.setLineDash([3,3]);g.beginPath();g.moveTo(x+.5,T);g.lineTo(x+.5,T+ph);g.stroke();g.setLineDash([]);
    if(o.hoverEv)return;
    if(vis.length){g.beginPath();g.arc(x,Y(prev[i]),4,0,7);g.fillStyle=css.getPropertyValue('--text').trim();g.fill()}
  }
}
function bindHover(cv,tip,getD){
  cv.addEventListener('mousemove',ev=>{
    const m=cv._m,d=getD();if(!m||!d||!d.t.length)return;
    const r=cv.getBoundingClientRect(),mx=ev.clientX-r.left,my=ev.clientY-r.top;
    const t=d.start+(mx-m.L)/m.pw*(d.end-d.start);
    let best=0,bd=1e18;d.t.forEach((x,i)=>{const dd=Math.abs(x-t);if(dd<bd){bd=dd;best=i}});
    const near=(d.events||[]).find(e=>Math.abs(m.L+(e.ts-d.start)/(d.end-d.start)*m.pw-mx)<7&&my>m.T+m.ph-14);
    let html;
    if(near){html=`<div class="h">${fmtT(near.ts,true)} · ${esc(near.kind)}</div><div>${esc(near.detail)}</div>`}
    else{
      const rows=d.series.filter(s=>!S.hidden.has(s.name)).map(s=>({n:s.name,v:s.v[best]})).sort((a,b)=>b.v-a.v);
      const tot=rows.reduce((a,r)=>a+r.v,0);
      html=`<div class="h">${fmtT(d.t[best],true)}</div>`+rows.filter(r=>r.v>0).map(r=>`<div class="r"><span><i class="dot" style="background:${colorOf(r.n)}"></i>${esc(r.n)}</span><b>${fmtB(r.v)}</b></div>`).join('')
       +(rows.length>1?`<div class="r" style="margin-top:4px;border-top:1px solid var(--line);padding-top:4px"><span>Total</span><b>${fmtB(tot)}</b></div>`:'');
    }
    tip.innerHTML=html;tip.style.display='block';
    const tw=tip.offsetWidth;let left=mx+16;if(left+tw>r.width)left=mx-tw-16;
    tip.style.left=Math.max(0,left)+'px';tip.style.top=Math.max(0,Math.min(my-20,r.height-tip.offsetHeight))+'px';
    cv._hover=best;cv._m.o.hoverEv=!!near;cv._redraw&&cv._redraw();
  });
  cv.addEventListener('mouseleave',()=>{tip.style.display='none';cv._hover=null;cv._redraw&&cv._redraw()});
}

/* ---------------------------------------------------------------- status polling (every page) */
async function loadNow(){
  try{
    S.now=await api('/api/now?ui=1');
    $('#conn').classList.remove('off');$('#conn span').textContent='Live · '+new Date().toLocaleTimeString();
    $('#adminbox').classList.toggle('hide',S.now.admin);
    const cc=$('#capchip');cc.classList.toggle('hide',!S.now.capped);cc.textContent=S.now.capped+' processes hard-capped';
    const me=S.now.self,sy=S.now.sys;
    $('#selfchip b').textContent=`${fmtB(me.rss)} · ${me.cpu.toFixed(1)}% CPU`;
    $('#selfchip').title=`RamCapper's own use\nWorking set: ${fmtB(me.rss)} (private ${fmtB(me.private)})\nCPU: ${me.cpu.toFixed(2)}% of the whole machine\nThreads: ${me.threads} · Processes: ${me.procs}\nHistory database: ${fmtB(me.db)}\n(The window itself is a separate browser process.)`;
    $('#side-pct').textContent=Math.round(sy.percent)+'% · '+fmtB(sy.used);
    const sb=$('#side-bar');sb.style.width=sy.percent+'%';sb.style.background=sy.percent>=85?'var(--bad)':sy.percent>=70?'var(--warn)':'var(--ok)';
    window.onNow&&await window.onNow();
  }catch(e){$('#conn').classList.add('off');$('#conn span').textContent='Disconnected'}
}
async function loadCfg(){
  S.cfg=await api('/api/config');
  const nb=$('#nb-limiter');nb.textContent=S.cfg.rules.length;nb.style.display=S.cfg.rules.length?'inline':'none';
  window.onCfg&&window.onCfg();
}
async function saveCfg(){S.cfg=await api('/api/config',S.cfg);const nb=$('#nb-limiter');nb.textContent=S.cfg.rules.length;nb.style.display=S.cfg.rules.length?'inline':'none';window.onCfg&&window.onCfg()}
async function loadInfo(){
  try{S.info=await api('/api/info');$('#ver').textContent='v'+S.info.version+(S.info.admin?' · admin':'');window.onInfo&&window.onInfo(S.info)}catch(e){}
}
async function loadEvents(){
  try{const ev=await api('/api/events');
    if(S.lastEv!=null)ev.filter(e=>e.id>S.lastEv&&['notify','kill','auto','net'].includes(e.kind)).reverse().forEach(e=>toast(`${e.app}: ${e.detail}`));
    if(ev.length)S.lastEv=Math.max(S.lastEv||0,ev[0].id);else if(S.lastEv==null)S.lastEv=0;
    window.onEvents&&window.onEvents(ev)}catch(e){}
}

/* ---------------------------------------------------------------- shared actions */
async function waitForRestart(msg){
  document.body.innerHTML=`<div style="display:grid;place-content:center;height:100vh;width:100%;text-align:center;font:16px Segoe UI;color:#8b98a9"><b style="font-size:20px;color:#e6edf3">${msg}</b><br>This window will reload automatically…</div>`;
  await new Promise(r=>setTimeout(r,2500));
  for(let i=0;i<60;i++){try{const r=await fetch('/api/info');if(r.ok){location.reload();return}}catch(e){}await new Promise(r=>setTimeout(r,700))}
}
async function elevate(){
  if(!confirm('Restart RamCapper with administrator rights?\n\nWindows will ask for permission. Monitoring pauses for a few seconds.'))return;
  try{await api('/api/elevate',{});waitForRestart('Restarting as administrator…')}catch(e){toast(e.message)}
}
$('#b-admin').onclick=elevate;
$('#btn-close').onclick=async()=>{let r={};try{r=await api('/api/closing',{})}catch(e){}if(!r.closed){window.close();setTimeout(()=>toast('This browser tab can’t be closed by the page — close it yourself. (RamCapper keeps running.)'),400)}};
$('#btn-quit').onclick=async()=>{
  if(!confirm('Quit RamCapper completely?\n\nMonitoring, history recording and all limits will stop until you start it again.'))return;
  try{await api('/api/quit',{})}catch(e){}
  document.body.innerHTML='<div style="display:grid;place-content:center;height:100vh;width:100%;text-align:center;font:16px Segoe UI;color:#8b98a9"><b style="font-size:20px;color:#e6edf3">RamCapper has quit</b><br>You can close this window.</div>';
  setTimeout(()=>window.close(),600);
};
/* opt-in module switches (Network / Storage pages) */
document.body.addEventListener('change',async e=>{
  const n=e.target.dataset&&e.target.dataset.mod;if(!n)return;
  try{S.cfg.modules=await api('/api/module',{name:n,enabled:e.target.checked})}catch(x){toast('Failed: '+x.message)}
  window.applyModules&&applyModules(true);
});
function boot(){
  loadInfo();
  loadCfg().then(()=>{window.applyModules&&applyModules();loadNow()});
  setInterval(loadNow,2000);
  setInterval(loadEvents,5000);loadEvents();
}

/* ---------------------------------------------------------------- DataTable: sortable columns + show/hide menu (remembered per table) */
function DataTable(table,o){
  const key='rc.cols.'+o.key;
  let st={hidden:null,sort:o.sort||null,dir:o.dir||-1};
  try{const v=JSON.parse(localStorage.getItem(key)||'null');if(v&&Array.isArray(v.hidden)){st=Object.assign(st,v);if(st.sort&&!o.cols.some(c=>c.id===st.sort&&c.val))st.sort=o.sort||null}}catch(e){}
  if(!st.hidden)st.hidden=o.cols.filter(c=>c.off).map(c=>c.id);
  const save=()=>{try{localStorage.setItem(key,JSON.stringify(st))}catch(e){}};
  const vis=()=>o.cols.filter(c=>c.fixed||!st.hidden.includes(c.id));
  table.innerHTML='<thead><tr></tr></thead><tbody></tbody>';
  const tr=table.querySelector('thead tr'),tb=table.querySelector('tbody');
  const dt={rows:[],
    head(){
      const v=vis();
      tr.innerHTML=v.map((c,i)=>`<th class="${c.th||''}${c.val?' sortable':''}" data-col="${c.id}"${c.w?` style="width:${c.w}"`:''}${c.tip?` title="${esc(c.tip)}"`:''}>${c.label}${st.sort===c.id?`<span class="arr">${st.dir<0?'▼':'▲'}</span>`:''}${i===v.length-1?'<span class="colbtn" title="Show or hide columns">⋮</span>':''}</th>`).join('');
    },
    body(){
      let rows=dt.rows.slice();
      const c=o.cols.find(x=>x.id===st.sort);
      if(c&&c.val){const d=st.dir;rows.sort((a,b)=>{const x=c.val(a),y=c.val(b);
        const r=(typeof x==='string'||typeof y==='string')?String(x).localeCompare(String(y)):(x-y);
        return r*d||(o.tie?o.tie(a,b):0)})}
      if(o.limit)rows=rows.slice(0,o.limit);
      const v=vis();
      tb.innerHTML=rows.map(r=>`<tr ${o.rowAttr?o.rowAttr(r):''}>${v.map(c=>`<td class="${c.td||''}${c.cls?' '+c.cls(r):''}">${c.render(r)}</td>`).join('')}</tr>`).join('')
        ||`<tr><td colspan="${v.length}" class="sub">${o.empty||'Nothing to show'}</td></tr>`;
    },
    render(rows){dt.rows=rows;dt.body()},
  };
  let pop=null;
  const closePop=()=>{if(pop){pop.remove();pop=null}};
  tr.addEventListener('click',e=>{
    const b=e.target.closest('.colbtn');
    if(b){
      if(pop){closePop();return}
      pop=document.createElement('div');pop.className='pop';
      pop.innerHTML='<h4>Columns</h4>'+o.cols.filter(c=>!c.fixed).map(c=>`<label><input type="checkbox" data-c="${c.id}" ${st.hidden.includes(c.id)?'':'checked'}>${c.menu||c.label}</label>`).join('')+'<a href="#" class="rst">Reset to default</a>';
      document.body.appendChild(pop);
      const r=b.getBoundingClientRect();pop.style.top=Math.min(innerHeight-pop.offsetHeight-8,r.bottom+6)+'px';pop.style.left=Math.max(8,Math.min(innerWidth-pop.offsetWidth-8,r.right-pop.offsetWidth))+'px';
      pop.onchange=ev=>{const id=ev.target.dataset.c;st.hidden=st.hidden.filter(x=>x!==id);if(!ev.target.checked)st.hidden.push(id);save();dt.head();dt.body()};
      pop.querySelector('.rst').onclick=ev=>{ev.preventDefault();st.hidden=o.cols.filter(c=>c.off).map(c=>c.id);st.sort=o.sort||null;st.dir=o.dir||-1;save();closePop();dt.head();dt.body()};
      return}
    const th=e.target.closest('th.sortable');if(!th)return;
    const id=th.dataset.col;
    if(st.sort===id)st.dir=-st.dir;else{st.sort=id;const c=o.cols.find(x=>x.id===id);st.dir=c&&c.first==='asc'?1:-1}
    save();dt.head();dt.body();
  });
  document.addEventListener('mousedown',e=>{if(pop&&!pop.contains(e.target)&&!e.target.closest('.colbtn'))closePop()});
  dt.head();
  return dt;
}
const fmtBps=b=>b>=MB*0.95?(b/MB).toFixed(2)+' MB/s':b>=1024?Math.round(b/1024)+' KB/s':Math.round(b)+' B/s';
