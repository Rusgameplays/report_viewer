const DATA=__DATA__;const $=id=>document.getElementById(id);let sortKey="cvss",sortDir=-1;const LARGE_DATASET=DATA.length>3500;
// Преобразует числовую оценку CVSS в категорию критичности. Пороги можно изменить здесь.
function severity(s){if(s===null||s===undefined)return"unknown";if(s<4)return"low";if(s<7)return"medium";if(s<9)return"high";return"critical"}
function exploitKey(v){return v===true?"yes":v===false?"no":"unknown"}
function safe(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
// Начальная настройка отчёта: сводные числа, список хостов, диаграмма и обработчики интерфейса.
function init(){
if(LARGE_DATASET){$("allVulnerabilitiesButton").textContent="Только с эксплойтами";$("largeDatasetNotice").hidden=false;$("largeDatasetGuidance").hidden=false;}
$("total").textContent=DATA.length;$("critical").textContent=DATA.filter(x=>x.cvss!==null&&x.cvss>=9).length;
$("high").textContent=DATA.filter(x=>x.cvss!==null&&x.cvss>=7&&x.cvss<9).length;$("exploits").textContent=DATA.filter(x=>x.exploit===true).length;
const hosts=[...new Set(DATA.map(x=>String(x.host??"").trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,"ru"));
for(const host of hosts){const o=document.createElement("option");o.value=host;o.textContent=host;$("host").appendChild(o)}
renderHostList(hosts);drawSeverityChart();renderRequirements();
document.querySelectorAll("th[data-key]").forEach(th=>th.addEventListener("click",()=>{const key=th.dataset.key;sortDir=sortKey===key?-sortDir:(key==="cvss"?-1:1);sortKey=key;render()}));
["search","severity","exploit","host"].forEach(id=>$(id).addEventListener(id==="search"?"input":"change",render));
$("widgetsButton").addEventListener("click",toggleWidgetsMenu);
$("overviewWidgetButton").addEventListener("click",showOverview);
$("allVulnerabilitiesButton").addEventListener("click",showAllVulnerabilities);
$("networkViolationsButton").addEventListener("click",showNetworkViolations);
render()}
// Заполняет левую карточку уникальными именами хостов.
function renderHostList(hosts){
 const list=$("hostList");list.replaceChildren();$("hostCount").textContent=`Всего уникальных хостов: ${hosts.length}`;
 if(!hosts.length){const item=document.createElement("div");item.className="host-item";item.textContent="Хосты не найдены.";list.appendChild(item);return}
 const target=list;
 if(hosts.length>25){
   const details=document.createElement("details");details.className="hosts-details";
   const summary=document.createElement("summary");summary.textContent=`Показать список хостов (${hosts.length})`;
   const contents=document.createElement("div");contents.className="hosts-details-list";
   details.append(summary,contents);target.appendChild(details);
   hosts.forEach(host=>{const item=document.createElement("div");item.className="host-item";item.textContent=host;contents.appendChild(item)});
 }else{
   hosts.forEach(host=>{const item=document.createElement("div");item.className="host-item";item.textContent=host;target.appendChild(item)});
 }
}
// Формирует обязательные действия для итогового акта.
function renderRequirements(){
 // Внутри каждого действия создаём отдельный блок для каждого хоста.
 const updateByHost=new Map();
 DATA.forEach(x=>{
   const entity=String(x.entity??"").trim();
   const unsupported=String(x.vulnerability??"").toLocaleLowerCase("ru").includes("неподдерживаемое по");
   if(!entity||!(x.exploit===true||unsupported)) return;
   const host=String(x.host??"").trim()||"Хост не указан";
   if(!updateByHost.has(host)) updateByHost.set(host,new Set());
   updateByHost.get(host).add(entity);
 });
 const updateList=$("updateList");updateList.replaceChildren();
 [...updateByHost.keys()].sort((a,b)=>a.localeCompare(b,"ru")).forEach(host=>{
   const group=document.createElement("li");group.className="host-action-group";
   const details=document.createElement("details");details.className="host-action-details";
   const heading=document.createElement("summary");heading.className="host-action-heading";heading.textContent=host;
   const list=document.createElement("ul");list.className="host-action-items";
   [...updateByHost.get(host)].sort((a,b)=>a.localeCompare(b,"ru")).forEach(entity=>{const li=document.createElement("li");li.textContent=entity;list.appendChild(li)});
   details.append(heading,list);group.appendChild(details);updateList.appendChild(group);
 });
 $("updateEmpty").hidden=updateByHost.size!==0;

 const fixByHost=new Map();
 DATA.filter(x=>!String(x.entity??"").trim()).forEach(x=>{
   const host=String(x.host??"").trim()||"Хост не указан";
   if(!fixByHost.has(host)) fixByHost.set(host,[]);
   fixByHost.get(host).push(x);
 });
 const fixList=$("fixList");fixList.replaceChildren();
 [...fixByHost.keys()].sort((a,b)=>a.localeCompare(b,"ru")).forEach(host=>{
   const group=document.createElement("li");group.className="host-action-group";
   const details=document.createElement("details");details.className="host-action-details";
   const heading=document.createElement("summary");heading.className="host-action-heading";heading.textContent=host;
   const list=document.createElement("ul");list.className="host-action-items fix-host-items";
   fixByHost.get(host).forEach(x=>{
     const li=document.createElement("li");li.className="fix-item";
     const title=document.createElement("strong");title.textContent=String(x.vulnerability??"").trim()||"Нарушение без названия";li.appendChild(title);
     const detail=[String(x.remediation??"").trim()].filter(Boolean);
     if(detail.length){const small=document.createElement("div");small.className="fix-detail";small.textContent=detail.join(" — ");li.appendChild(small)}
     list.appendChild(li);
   });
   details.append(heading,list);group.appendChild(details);fixList.appendChild(group);
 });
 $("fixEmpty").hidden=fixByHost.size!==0;
}
// Рисует круговую диаграмму и выносит число для каждого сектора наружу.
// Чтобы изменить подписи или цвета, редактируйте массив buckets ниже.
function drawSeverityChart(){
 const buckets=[
  {key:"critical",label:"Критический",color:"#fb7185",count:DATA.filter(x=>x.cvss!==null&&x.cvss>=9).length},
  {key:"high",label:"Высокий",color:"#fb923c",count:DATA.filter(x=>x.cvss!==null&&x.cvss>=7&&x.cvss<9).length},
  {key:"medium",label:"Средний",color:"#facc15",count:DATA.filter(x=>x.cvss!==null&&x.cvss>=4&&x.cvss<7).length},
  {key:"low",label:"Низкий",color:"#4ade80",count:DATA.filter(x=>x.cvss!==null&&x.cvss<4).length},
  {key:"unknown",label:"Не указан",color:"#64748b",count:DATA.filter(x=>x.cvss===null||x.cvss===undefined).length}
 ];
 const svg=$("severityChart");svg.replaceChildren();
 const ns="http://www.w3.org/2000/svg";
 const total=buckets.reduce((sum,b)=>sum+b.count,0);
 // Центр и радиус круга. Координаты подобраны так, чтобы оставить место для выносных линий.
 const cx=180,cy=140,r=78;
 if(total===0){
  const circle=document.createElementNS(ns,"circle");circle.setAttribute("cx",cx);circle.setAttribute("cy",cy);circle.setAttribute("r",r);circle.setAttribute("fill","#29364d");svg.appendChild(circle);
  const empty=document.createElementNS(ns,"text");empty.setAttribute("x",cx);empty.setAttribute("y",cy+5);empty.setAttribute("text-anchor","middle");empty.setAttribute("fill","#e8eef9");empty.setAttribute("font-size","12");empty.textContent="Нет данных";svg.appendChild(empty);
  return;
 }
 // Сохраняем только непустые категории, чтобы не рисовать нулевые сектора и подписи к ним.
 const visible=buckets.filter(b=>b.count>0);
 let angle=-Math.PI/2;
 const labelPoints=[];
 visible.forEach(b=>{
  const sliceAngle=2*Math.PI*b.count/total;
  const next=angle+sliceAngle;
  const x1=cx+r*Math.cos(angle),y1=cy+r*Math.sin(angle);
  const x2=cx+r*Math.cos(next),y2=cy+r*Math.sin(next);
  const large=sliceAngle>Math.PI?1:0;
  const path=document.createElementNS(ns,"path");
  path.setAttribute("d",`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`);
  path.setAttribute("fill",b.color);path.setAttribute("stroke","#121a2d");path.setAttribute("stroke-width","2");
  // Подсказка при наведении на сектор.
  const title=document.createElementNS(ns,"title");title.textContent=`${b.label}: ${b.count} уязвимостей`;path.appendChild(title);svg.appendChild(path);
  // Точка посередине сектора задаёт направление выносной линии с подписью.
  const mid=angle+sliceAngle/2;
  labelPoints.push({b,mid});
  angle=next;
 });
 // Выносные линии: короткий диагональный отрезок от сектора и горизонтальный отрезок к подписи.
 // Слева текст выравнивается вправо, справа — влево, чтобы подписи не упирались в край SVG.
 labelPoints.forEach(({b,mid})=>{
  const x1=cx+(r+2)*Math.cos(mid),y1=cy+(r+2)*Math.sin(mid);
  const x2=cx+(r+18)*Math.cos(mid),y2=cy+(r+18)*Math.sin(mid);
  const right=Math.cos(mid)>=0;
  const x3=right?Math.min(278,x2+22):Math.max(82,x2-22);
  const line=document.createElementNS(ns,"polyline");
  line.setAttribute("points",`${x1},${y1} ${x2},${y2} ${x3},${y2}`);
  line.setAttribute("fill","none");line.setAttribute("stroke",b.color);line.setAttribute("stroke-width","1.5");svg.appendChild(line);
  const label=document.createElementNS(ns,"text");
  label.setAttribute("x",right?x3+4:x3-4);label.setAttribute("y",y2+4);
  label.setAttribute("text-anchor",right?"start":"end");label.setAttribute("fill","#e8eef9");
  label.setAttribute("font-size","11");label.setAttribute("font-weight","750");
  // Показываем число и название категории у каждого сектора; общее число в центре не выводим.
  label.textContent=`${b.count} · ${b.label}`;svg.appendChild(label);
 });
}
// Управление меню выбора виджетов.
function toggleWidgetsMenu(){const menu=$("widgetsMenu");menu.hidden=!menu.hidden;$("widgetsButton").setAttribute("aria-expanded",String(!menu.hidden))}
function hideAllViews(){
  // Keep exactly one widget visible at a time.
  $("overviewView").hidden=true;$("allVulnerabilitiesView").hidden=true;$("networkViolationsView").hidden=true;
}
function showOverview(){hideAllViews();$("overviewView").hidden=false;closeWidgetsMenu()}
function showAllVulnerabilities(){hideAllViews();$("allVulnerabilitiesView").hidden=false;closeWidgetsMenu()}
function showNetworkViolations(){hideAllViews();$("networkViolationsView").hidden=false;renderNetworkViolations();closeWidgetsMenu()}
// В результат пентеста попадают строки, где уязвимая сущность не заполнена.
function renderNetworkViolations(){
  const networkRows=DATA.filter(x=>!String(x.entity??"").trim());
  $("networkShown").textContent=`Результатов пентеста: ${networkRows.length}`;
  $("networkSummary").textContent=`Найдено результатов пентеста: ${networkRows.length}`;
  $("networkRows").innerHTML=networkRows.map(x=>{
    const sev=severity(x.cvss);
    const exploit=x.exploit===true?'<span class="exploit exploit-yes">Есть</span>':x.exploit===false?'<span class="exploit exploit-no">Нет</span>':'<span class="exploit exploit-unknown">Не указано</span>';
    const score=x.cvss===null?"—":safe(x.cvss_raw||x.cvss);
    return `<tr><td class="host">${safe(x.host)}</td><td class="vuln">${safe(x.vulnerability)}</td><td class="entity">${safe(x.entity)}</td><td><span class="score ${sev}">${score}</span></td><td class="remediation">${safe(x.remediation)}</td><td>${exploit}</td></tr>`;
  }).join("");
  $("networkEmpty").hidden=networkRows.length!==0;
}
function closeWidgetsMenu(){$("widgetsMenu").hidden=true;$("widgetsButton").setAttribute("aria-expanded","false")}
// Фильтрует, сортирует и выводит строки таблицы во вкладке «Все уязвимости».
function render(){
const q=$("search").value.trim().toLocaleLowerCase("ru"),sf=$("severity").value,ef=$("exploit").value,hf=$("host").value;
const sourceRows=LARGE_DATASET?DATA.filter(x=>x.exploit===true):DATA;
const filtered=sourceRows.filter(x=>{const hay=[x.host,x.vulnerability,x.entity,x.cvss_raw,x.remediation,x.exploit===true?"да есть true":x.exploit===false?"нет false":"не указано"].join(" ").toLocaleLowerCase("ru");
return(!q||hay.includes(q))&&(!sf||severity(x.cvss)===sf)&&(!ef||exploitKey(x.exploit)===ef)&&(!hf||x.host===hf)});
filtered.sort((a,b)=>{let av=a[sortKey],bv=b[sortKey];if(sortKey==="exploit"){av=exploitKey(av);bv=exploitKey(bv)}if(sortKey==="cvss"){av=av??-1;bv=bv??-1;return(av-bv)*sortDir}return String(av??"").localeCompare(String(bv??""),"ru",{numeric:true})*sortDir});
$("rows").innerHTML=filtered.map(x=>{const sev=severity(x.cvss),exploit=x.exploit===true?'<span class="exploit exploit-yes">Есть</span>':x.exploit===false?'<span class="exploit exploit-no">Нет</span>':'<span class="exploit exploit-unknown">Не указано</span>',score=x.cvss===null?"—":safe(x.cvss_raw||x.cvss);
return `<tr><td class="host">${safe(x.host)}</td><td class="vuln">${safe(x.vulnerability)}</td><td class="entity">${safe(x.entity)}</td><td><span class="score ${sev}">${score}</span></td><td class="remediation">${safe(x.remediation)}</td><td>${exploit}</td></tr>`}).join("");
$("shown").textContent=`Показано ${filtered.length} из ${sourceRows.length}`;$("empty").hidden=filtered.length!==0}
init();
