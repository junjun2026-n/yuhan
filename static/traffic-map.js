'use strict';
(() => {
 const dialog=$('traffic-map-dialog'),canvas=$('traffic-map-canvas'),stage=$('map-stage'),ctx=canvas.getContext('2d');
 let world=null,snapshot=null,selected=null,points=[],hub={x:0,y:0},scale=1,pan={x:0,y:0},drag=null,moved=false;
 let frame=0,lastFrame=0,refreshTimer=null,controller=null,revision=0,nativeFullscreen=false,width=0,height=0;
 const colors={blocked:'#ff647e',detected:'#ffc766',allowed:'#39d5c1',error:'#ac9cff'};
 const color=n=>n.blocked?colors.blocked:n.detected?colors.detected:n.errors?colors.error:colors.allowed;
 const count=n=>Number(n||0).toLocaleString();
 function syncButton(){$('open-traffic-map').hidden=!can('overview')||$('overview').hidden;}
 document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>setTimeout(syncButton,0)));
 function project(lon,lat){return {x:((lon+180)/360*(width-70)+35-width/2)*scale+width/2+pan.x,y:((85-lat)/145*(height-100)+25-height/2)*scale+height/2+pan.y};}
 function resize(){
  const rect=stage.getBoundingClientRect();width=rect.width;height=rect.height;
  const dpr=Math.min(window.devicePixelRatio||1,2);canvas.width=Math.round(width*dpr);canvas.height=Math.round(height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);layout();
 }
 function layout(){
  hub={x:width/2,y:height-55};points=[];
  if(!snapshot||!width)return;
  const cells=new Map(),cellKey=(x,y)=>`${x},${y}`;
  for(const item of snapshot.nodes){
   if(item.latitude===null)continue;
   const base=project(item.longitude,item.latitude),radius=4+Math.log2(item.requests+1)*.5;
   const r=Math.min(radius,10);let point={...base};
   // Screen-space separation preserves readable nodes at every zoom level.
   for(let attempt=0;attempt<5000;attempt++){
    if(attempt){const angle=attempt*2.399963,reach=6*Math.sqrt(attempt);point={x:base.x+Math.cos(angle)*reach,y:base.y+Math.sin(angle)*reach};}
    if(Math.hypot(point.x-hub.x,point.y-hub.y)<45)continue;
    const cx=Math.floor(point.x/26),cy=Math.floor(point.y/26);let nearby=[];
    for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++)nearby.push(...(cells.get(cellKey(cx+dx,cy+dy))||[]));
    if(nearby.every(p=>Math.hypot(point.x-p.x,point.y-p.y)>r+p.r+5))break;
   }
   const placed={...point,r,item};points.push(placed);const key=cellKey(Math.floor(point.x/26),Math.floor(point.y/26));if(!cells.has(key))cells.set(key,[]);cells.get(key).push(placed);
  }
 }
 function ring(coordinates){
  let previous=null;
  for(const coordinate of coordinates){const p=project(coordinate[0],coordinate[1]);if(!previous||Math.abs(p.x-previous.x)>width*scale*.5)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y);previous=p;}
  ctx.closePath();
 }
 function curve(point){const lift=Math.min(140,Math.hypot(point.x-hub.x,point.y-hub.y)*.25);return {x:(point.x+hub.x)/2,y:Math.min(point.y,hub.y)-lift};}
 function path(point){const c=curve(point);ctx.beginPath();ctx.moveTo(point.x,point.y);ctx.quadraticCurveTo(c.x,c.y,hub.x,hub.y);}
 function draw(time){
  if(!dialog.open)return;
  frame=requestAnimationFrame(draw);if(time-lastFrame<40)return;lastFrame=time;
  ctx.clearRect(0,0,width,height);
  ctx.strokeStyle='#1b3a52';ctx.lineWidth=.6;
  for(let lon=-180;lon<=180;lon+=30){const a=project(lon,85),b=project(lon,-60);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  for(let lat=-60;lat<=85;lat+=30){const a=project(-180,lat),b=project(180,lat);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  ctx.fillStyle='#17354a';ctx.strokeStyle='#386078';ctx.lineWidth=.65;
  for(const feature of world?.features||[]){ctx.beginPath();const polygons=feature.geometry.type==='Polygon'?[feature.geometry.coordinates]:feature.geometry.coordinates;for(const polygon of polygons)for(const line of polygon)ring(line);ctx.fill('evenodd');ctx.stroke();}
  for(const point of points){
   const active=selected?.ip===point.item.ip;ctx.globalAlpha=(selected&&!active)? .25 : .55;ctx.strokeStyle=color(point.item);ctx.lineWidth=Math.min(5,.6+Math.log2(point.item.requests+1)*.4);path(point);ctx.stroke();
   if(!matchMedia('(prefers-reduced-motion: reduce)').matches){
    const t=(time/3500+points.indexOf(point)*.127)%1,c=curve(point),u=1-t;
    ctx.beginPath();ctx.arc(u*u*point.x+2*u*t*c.x+t*t*hub.x,u*u*point.y+2*u*t*c.y+t*t*hub.y,2,0,Math.PI*2);ctx.fillStyle=color(point.item);ctx.fill();
   }
  }
  ctx.globalAlpha=1;
  for(const point of points){const active=selected?.ip===point.item.ip;ctx.beginPath();ctx.arc(point.x,point.y,point.r+(active?3:0),0,Math.PI*2);ctx.fillStyle=color(point.item);ctx.fill();ctx.strokeStyle=active?'#fff':'#0a2034';ctx.lineWidth=active?2:1;ctx.stroke();}
  ctx.shadowColor='#4cdac9';ctx.shadowBlur=18;ctx.beginPath();ctx.arc(hub.x,hub.y,23,0,Math.PI*2);ctx.fillStyle='#123e4c';ctx.fill();ctx.strokeStyle='#65f2df';ctx.lineWidth=2;ctx.stroke();ctx.shadowBlur=0;
  ctx.textAlign='center';ctx.fillStyle='#e3fffb';ctx.font='bold 12px sans-serif';ctx.fillText('WAF',hub.x,hub.y+4);ctx.font='11px sans-serif';ctx.fillStyle='#9cb8cc';ctx.fillText('防护入口 · 逻辑节点',hub.x,hub.y+41);
 }
 function renderDetails(item){
  selected=item;const box=$('map-detail');box.replaceChildren();
  if(!item){box.textContent='点击地图节点或下方 IP 查看统计。';return;}
  box.append(element('strong',item.ip),element('p',`${countryName(item.country)} · ${item.latitude===null?'无可用定位':'国家级近似定位'}`));
  for(const [key,label] of [['requests','请求'],['blocked','拦截'],['detected','观察命中'],['allowed','已转发'],['observed','旁挂审计'],['errors','代理异常']])box.append(element('p',`${label}：${count(item[key])} 次`));
  box.append(element('small','最近访问：'+new Date(item.last).toLocaleString()));
  if(can('audit')){const button=element('button','查看访问审计');button.type='button';button.addEventListener('click',run(async()=>{const result=snapshot;await close();await openOverviewEvents(result,'business','公网来源：'+item.ip,{ip:item.ip,external:'true'});}));box.append(button);}
  document.querySelectorAll('#map-source-list button').forEach(b=>b.classList.toggle('selected',b.dataset.ip===item.ip));
 }
 function render(){
  const totals=snapshot.totals;$('map-metrics').replaceChildren();
  for(const [label,value] of [['公网请求',totals.requests],['公网 IP',totals.sources],['国家 / 地区',totals.countries],['拦截请求',totals.blocked],['观察命中',totals.detected]]){const card=element('div');card.append(element('small',label),element('strong',count(value)));$('map-metrics').append(card);}
  const list=$('map-source-list');list.replaceChildren();
  for(const item of snapshot.nodes){const button=element('button');button.type='button';button.dataset.ip=item.ip;button.append(element('span',item.ip),element('small',`${countryName(item.country)} · ${count(item.requests)} 次${item.latitude===null?' · 未定位':''}`));button.style.borderLeftColor=color(item);button.addEventListener('click',()=>renderDetails(item));list.append(button);}
  if(!snapshot.nodes.length)list.append(element('p','暂无公网来源审计数据。'));
  const domains=$('map-domain-list');domains.replaceChildren();for(const item of snapshot.domains)domains.append(element('p',`${item.domain} · ${count(item.requests)} 次`));if(!snapshot.domains.length)domains.append(element('p','暂无已记录域名。'));
  const selection=snapshot.nodes.find(n=>n.ip===selected?.ip);renderDetails(selection||null);layout();
  $('map-status').textContent=totals.requests?`展示请求最多的 ${count(totals.shown_sources)} / ${count(totals.sources)} 个公网 IP，其中 ${count(totals.mapped_sources)} 个可定位；全范围未定位请求 ${count(totals.unlocated_requests)} 次。`:'暂无公网访问记录；请确认业务请求已通过 WAF 或镜像审计链路。';
  $('map-updated').textContent='更新于 '+new Date(snapshot.until).toLocaleString();
 }
 async function refresh(){
  if(!dialog.open)return;const current=++revision;controller?.abort();controller=new AbortController();$('map-refresh').disabled=true;$('map-updated').textContent='正在刷新…';
  try{const data=await api('/api/stats/traffic-map?'+new URLSearchParams({period:$('map-period').value,limit:$('map-limit').value}),{signal:controller.signal});if(current!==revision||!dialog.open)return;snapshot=data;render();}
  catch(e){if(e.name!=='AbortError'&&current===revision){$('map-status').textContent='更新失败：'+e.message;$('map-updated').textContent=snapshot?'更新失败，保留上次数据':'数据加载失败';}}
  finally{if(current===revision)$('map-refresh').disabled=false;}
 }
 async function open(){
  if(!can('overview'))return;$('map-period').value=$('overview-period').value;dialog.showModal();document.body.classList.add('traffic-map-open');resize();frame=requestAnimationFrame(draw);
  await enterFullscreen();
  resize();
  try{if(!world)world=await api('/world-map.json');}catch(e){$('map-status').textContent='底图加载失败：'+e.message;}
  await refresh();if(dialog.open)refreshTimer=setInterval(()=>{if($('map-auto').checked&&!document.hidden)refresh();},15000);
 }
 async function enterFullscreen(){
  const root=document.documentElement;
  if(document.fullscreenElement===root){updateFullscreenControls();return;}
  try{
   // Dialog elements cannot be fullscreen targets. Request the document root
   // directly from the user's click, and keep the modal in its top layer.
   if(!root.requestFullscreen)throw new Error('Fullscreen unavailable');
   await root.requestFullscreen({navigationUI:'hide'});
   nativeFullscreen=document.fullscreenElement===root;
   if(!dialog.open&&nativeFullscreen){nativeFullscreen=false;await document.exitFullscreen();}
  }catch{nativeFullscreen=false;}
  updateFullscreenControls();
 }
 function updateFullscreenControls(){
  const active=Boolean(document.fullscreenElement);
  $('map-fullscreen').hidden=active;
  $('map-fullscreen-hint').hidden=active;
 }
 async function close(){
  revision++;controller?.abort();clearInterval(refreshTimer);refreshTimer=null;cancelAnimationFrame(frame);$('map-refresh').disabled=false;
  if(dialog.open)dialog.close();document.body.classList.remove('traffic-map-open');
  const exit=nativeFullscreen;nativeFullscreen=false;if(exit&&document.fullscreenElement)await document.exitFullscreen().catch(()=>{});
 }
 $('open-traffic-map').addEventListener('click',run(open));$('map-close').addEventListener('click',()=>close());dialog.addEventListener('cancel',e=>{e.preventDefault();close();});dialog.addEventListener('close',()=>{if(document.body.classList.contains('traffic-map-open'))close();});
 $('map-fullscreen').addEventListener('click',enterFullscreen);
 document.addEventListener('fullscreenchange',()=>{updateFullscreenControls();if(nativeFullscreen&&!document.fullscreenElement)close();else if(dialog.open)resize();});
 for(const id of ['map-period','map-limit'])$(id).addEventListener('change',refresh);$('map-refresh').addEventListener('click',refresh);
 $('map-zoom-in').addEventListener('click',()=>{scale=Math.min(6,scale*1.25);layout();});$('map-zoom-out').addEventListener('click',()=>{scale=Math.max(.7,scale/1.25);layout();});$('map-reset').addEventListener('click',()=>{scale=1;pan={x:0,y:0};layout();});
 canvas.addEventListener('wheel',e=>{e.preventDefault();scale=Math.max(.7,Math.min(6,scale*(e.deltaY<0?1.12:.89)));layout();},{passive:false});
 canvas.addEventListener('pointerdown',e=>{drag={x:e.clientX,y:e.clientY,pan:{...pan}};moved=false;canvas.setPointerCapture(e.pointerId);});
 canvas.addEventListener('pointermove',e=>{
  if(drag){const dx=e.clientX-drag.x,dy=e.clientY-drag.y;if(Math.hypot(dx,dy)>4)moved=true;if(moved){pan={x:drag.pan.x+dx,y:drag.pan.y+dy};layout();}return;}
  const rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top,point=points.find(p=>Math.hypot(p.x-x,p.y-y)<p.r+6);canvas.style.cursor=point?'pointer':'grab';const tooltip=$('map-tooltip');tooltip.hidden=!point;
  if(point){tooltip.textContent=`${point.item.ip} · ${countryName(point.item.country)} · ${count(point.item.requests)} 次请求`;tooltip.style.left=Math.max(4,Math.min(width-260,x+12))+'px';tooltip.style.top=Math.max(4,Math.min(height-45,y-35))+'px';}
 });
 canvas.addEventListener('pointerup',e=>{if(!moved){const rect=canvas.getBoundingClientRect();const point=points.find(p=>Math.hypot(p.x-(e.clientX-rect.left),p.y-(e.clientY-rect.top))<p.r+6);if(point)renderDetails(point.item);}drag=null;});canvas.addEventListener('pointercancel',()=>{drag=null;});canvas.addEventListener('pointerleave',()=>{$('map-tooltip').hidden=true;});
 new ResizeObserver(()=>{if(dialog.open)resize();}).observe(stage);
})();
