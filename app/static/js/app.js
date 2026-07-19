(() => {
  const $ = (q, root=document) => root.querySelector(q);
  const $$ = (q, root=document) => [...root.querySelectorAll(q)];
  const overlay = $('#loadingOverlay');
  $$('.loading-form').forEach(form => form.addEventListener('submit', () => overlay?.classList.add('show')));
  $('#menuToggle')?.addEventListener('click', () => $('#sidebar')?.classList.toggle('open'));
  document.addEventListener('click', e => {
    const button = e.target.closest('[data-copy-target]');
    if (!button) return;
    const target = document.getElementById(button.dataset.copyTarget);
    navigator.clipboard?.writeText(target?.innerText || '');
    button.textContent = 'Copied'; setTimeout(() => button.textContent = 'Copy', 1200);
  });
  const toastText = new URLSearchParams(location.search).get('toast');
  if (toastText) {
    const toast = document.createElement('div'); toast.className = 'toast'; toast.textContent = toastText;
    $('#toastContainer')?.appendChild(toast); setTimeout(() => toast.remove(), 4200);
  }
  const palette = {cyan:'#35e6ff', blue:'#4f8cff', purple:'#9d6bff', green:'#38d996', yellow:'#f4c75d', orange:'#ff8a4c', red:'#ff5f72', grid:'rgba(141,167,191,.12)', text:'#8da7bf'};
  if (window.Chart && ($('#scoreChart') || $('#severityChart') || $('#categoryChart'))) {
    fetch('/api/stats').then(r => r.json()).then(({charts}) => {
      Chart.defaults.color = palette.text; Chart.defaults.borderColor = palette.grid;
      const mk = (id, config) => { const el=$(id); if(el) new Chart(el, config); };
      mk('#scoreChart',{type:'line',data:{labels:charts.scores.labels,datasets:[{label:'Security score',data:charts.scores.values,borderColor:palette.cyan,backgroundColor:'rgba(53,230,255,.08)',fill:true,tension:.35,pointRadius:3}]},options:{maintainAspectRatio:false,scales:{y:{min:0,max:100}},plugins:{legend:{display:false}}}});
      mk('#severityChart',{type:'doughnut',data:{labels:charts.severity.labels,datasets:[{data:charts.severity.values,backgroundColor:[palette.red,palette.orange,palette.yellow,palette.cyan,palette.purple],borderWidth:0}]},options:{maintainAspectRatio:false,cutout:'68%',plugins:{legend:{position:'bottom',labels:{boxWidth:9}}}}});
      mk('#categoryChart',{type:'bar',data:{labels:charts.categories.labels,datasets:[{data:charts.categories.values,backgroundColor:palette.blue,borderRadius:5}]},options:{maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}}}});
    }).catch(() => {});
  }
  const graph = $('#iamGraph');
  if (graph) {
    let data={nodes:[],edges:[]}; try{data=JSON.parse(graph.dataset.graph||'{}')}catch(e){}
    const nodes=data.nodes||[], edges=data.edges||[], center={x:50,y:50}, radius=Math.min(40, 18+nodes.length*1.2), positions={};
    nodes.forEach((node,i)=>{const angle=(Math.PI*2*i/Math.max(nodes.length,1))-Math.PI/2; positions[node.id]={x:center.x+Math.cos(angle)*radius,y:center.y+Math.sin(angle)*Math.min(radius,37)};});
    edges.forEach(edge=>{const a=positions[edge.source],b=positions[edge.target]; if(!a||!b)return; const line=document.createElement('div'); line.className='graph-edge'; const dx=b.x-a.x,dy=b.y-a.y; line.style.left=a.x+'%';line.style.top=a.y+'%';line.style.width=Math.hypot(dx,dy)+'%';line.style.transform=`rotate(${Math.atan2(dy,dx)}rad)`;graph.appendChild(line);});
    nodes.forEach(node=>{const p=positions[node.id],el=document.createElement('div');el.className='graph-node '+(node.risky?'risky':'');el.style.left=p.x+'%';el.style.top=p.y+'%';el.innerHTML=`<strong>${escapeHtml(node.label||node.id)}</strong><small>${escapeHtml(node.type||'resource')}</small>`;graph.appendChild(el);});
  }
  function escapeHtml(value){const d=document.createElement('div');d.textContent=value;return d.innerHTML;}
})();
