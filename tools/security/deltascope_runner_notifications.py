"""GitHub runner/workflow progress notifications for DeltaScope.

Consumes the existing rate-aware live Operations endpoint. No GitHub credential,
acquisition, workflow mutation, or security authority is added here.
"""
from __future__ import annotations
import json

_NOTIFICATION_CSS = r"""
.runner-notification-settings{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 12px;border-bottom:1px solid #e0e0e0;background:#f4f4f4;font-size:11px}
.runner-notification-settings label{display:flex;gap:5px;align-items:center}.runner-notification-settings input{min-height:0;width:auto}
.runner-toast-stack{position:fixed;z-index:160;top:58px;right:14px;width:min(390px,calc(100vw - 28px));display:grid;gap:7px;pointer-events:none}
.runner-toast{pointer-events:auto;border:1px solid #c6c6c6;border-left:4px solid #0f62fe;background:#fff;padding:10px 11px;box-shadow:0 5px 18px rgba(0,0,0,.16)}
.runner-toast.success{border-left-color:#24a148}.runner-toast.warning{border-left-color:#f1c21b}.runner-toast.error{border-left-color:#da1e28}
.runner-toast-title{font-weight:700;font-size:12px}.runner-toast-detail{margin-top:3px;color:#525252;font-size:11px;line-height:1.35}
"""

_NOTIFICATION_JS = r"""
setTimeout(function(){
 if(window.__deltascopeRunnerNotificationsInstalled)return;window.__deltascopeRunnerNotificationsInstalled=true;
 const STATE_KEY='deltascope.runner-notifications.state.v1',HISTORY_KEY='deltascope.runner-notifications.history.v1',PREF_KEY='deltascope.runner-notifications.preferences.v1',MAX_HISTORY=80;
 var timer=0,inFlight=false;
 function loadJson(key,fallback){try{var value=JSON.parse(localStorage.getItem(key)||'null');return value&&typeof value==='object'?value:fallback}catch{return fallback}}
 function saveJson(key,value){try{localStorage.setItem(key,JSON.stringify(value))}catch{}}
 function prefs(){return Object.assign({runs:true,runners:true,progress:true,desktop:false},loadJson(PREF_KEY,{}))}
 function savePrefs(p){saveJson(PREF_KEY,p)}
 function history(){var rows=loadJson(HISTORY_KEY,[]);return Array.isArray(rows)?rows:[]}
 function restoreHistory(){history().slice(-MAX_HISTORY).forEach(n=>upsertNotification(n))}
 function rank(level){return level==='error'?100:level==='warning'?80:level==='success'?50:30}
 function toast(n){var stack=$('runnerNotificationToasts');if(!stack){stack=document.createElement('div');stack.id='runnerNotificationToasts';stack.className='runner-toast-stack';stack.setAttribute('aria-live','polite');document.body.appendChild(stack)}var node=document.createElement('button');node.type='button';node.className=`runner-toast ${n.level||'info'}`;node.innerHTML=`<div class=runner-toast-title>${esc(n.title||'Runner update')}</div><div class=runner-toast-detail>${esc(n.detail||'')}</div>`;node.addEventListener('click',()=>{node.remove();if(n.view)setWorkbenchView(n.view)});stack.prepend(node);while(stack.children.length>3)stack.lastElementChild?.remove();setTimeout(()=>node.remove(),7000)}
 function desktop(n){var p=prefs();if(!p.desktop||!('Notification'in window)||Notification.permission!=='granted')return;try{var x=new Notification(n.title||'DeltaScope',{body:n.detail||'',tag:n.id,silent:n.level==='info'});x.onclick=()=>{window.focus();if(n.view)setWorkbenchView(n.view)}}catch{}}
 function emit(id,level,title,detail,meta,view){var n={id:`runner:${id}`,level,title,detail,meta:meta||'GitHub Actions · live Operations snapshot',view:view||'runners',rank:rank(level),time:new Date().toISOString()};var rows=history().filter(x=>x&&x.id!==n.id);rows.push(n);saveJson(HISTORY_KEY,rows.slice(-MAX_HISTORY));upsertNotification(n);toast(n);desktop(n)}
 function runState(r){return `${r.status||''}|${r.conclusion||''}|${r.state||''}`}
 function stepState(j){var step=j.currentStep||{},role=j.workerRole||{},tele=j.latestTelemetry||{},progress=tele.progress||{};return `${step.number||0}|${step.name||''}|${step.status||''}|${role.state||''}|${progress.current??''}|${progress.total??''}`}
 function snapshot(r){var runs={},jobs={},runners={};(r.recentRuns||[]).slice(0,30).forEach(x=>runs[String(x.runId||0)]={name:x.workflow||x.component||x.displayTitle||'Workflow',number:x.runNumber||0,status:x.status||'',conclusion:x.conclusion||'',state:x.state||''});(r.jobs||[]).slice(0,120).forEach(x=>jobs[String(x.jobId||0)]={runId:x.runId||0,runNumber:x.runNumber||0,name:x.name||'Job',workflow:x.workflow||'',runnerName:x.runnerName||'',step:stepState(x),stepName:(x.currentStep||{}).name||'',workerState:(x.workerRole||{}).state||''});(r.runners||[]).slice(0,100).forEach(x=>runners[String(x.runnerId||0)+'|'+String(x.runnerName||'')]={name:x.runnerName||`runner ${x.runnerId||'?'}`,status:x.status||'observed',busy:!!x.busy});return{at:r.fetchedAtUtc||'',runs,jobs,runners,stale:!!r.stale,error:String(r.error||''),rateLimited:!!r.rateLimited}}
 function compare(prev,cur){var p=prefs();
  if(p.runs)for(const[id,r]of Object.entries(cur.runs)){var old=prev.runs?.[id];if(!old){if(['queued','requested','waiting'].includes(r.status))emit(`run:${id}:queued`,'info',`${r.name} queued`,`Run #${r.number} is waiting for a runner.`,'GitHub workflow','workflows');else if(r.status==='in_progress')emit(`run:${id}:running`,'info',`${r.name} started`,`Run #${r.number} is now running.`,'GitHub workflow','workflows');continue}if(runState(r)!==runState(old)){if(r.status==='in_progress')emit(`run:${id}:running`,'info',`${r.name} started`,`Run #${r.number} moved into progress.`,'GitHub workflow','workflows');if(r.status==='completed'){var c=String(r.conclusion||'').toLowerCase(),level=c==='success'?'success':(['cancelled','skipped','neutral'].includes(c)?'warning':'error');emit(`run:${id}:completed:${c}`,level,`${r.name} ${c||'completed'}`,`Run #${r.number} completed with ${c||'an unknown conclusion'}.`,'GitHub workflow','workflows')}}}
  if(p.progress)for(const[id,j]of Object.entries(cur.jobs)){var old=prev.jobs?.[id];if(!old){emit(`job:${id}:assigned`,'info',`${j.name} assigned`,`${j.workflow||'Workflow'} run #${j.runNumber}${j.runnerName?` · ${j.runnerName}`:''}.`,'GitHub job','runners');continue}if(j.step!==old.step){var detail=[j.workflow?`${j.workflow} #${j.runNumber}`:'',j.runnerName,j.stepName||j.workerState].filter(Boolean).join(' · ');emit(`job:${id}:progress:${j.step}`,'info',`${j.name} progressed`,detail||'Job progress changed.','GitHub job','runners')}}
  if(p.runners)for(const[id,r]of Object.entries(cur.runners)){var old=prev.runners?.[id];if(!old)continue;if(r.status!==old.status){var offline=String(r.status).toLowerCase()==='offline';emit(`runner:${id}:status:${r.status}`,offline?'error':'success',`${r.name} ${r.status}`,offline?'GitHub reports this runner offline.':'Runner status changed.','GitHub runner','runners')}if(r.busy!==old.busy)emit(`runner:${id}:busy:${r.busy}`,r.busy?'info':'success',`${r.name} ${r.busy?'busy':'idle'}`,r.busy?'A GitHub Actions job is now using this runner.':'The runner is no longer executing an observed job.','GitHub runner','runners')}
  if((cur.stale||cur.error||cur.rateLimited)&&!(prev.stale||prev.error||prev.rateLimited))emit(`acquisition:${cur.error||'stale'}`,'warning','Runner status is stale',cur.error||'GitHub live Operations acquisition is delayed; the last known-good snapshot remains visible.','GitHub Operations','diagnostics')
 }
 function settings(){var drawer=$('notificationDrawer');if(!drawer||$('runnerNotificationSettings'))return;var p=prefs(),row=document.createElement('div');row.id='runnerNotificationSettings';row.className='runner-notification-settings';row.innerHTML=`<b>Runner alerts</b><label><input data-rn-pref=runs type=checkbox ${p.runs?'checked':''}> runs</label><label><input data-rn-pref=runners type=checkbox ${p.runners?'checked':''}> runners</label><label><input data-rn-pref=progress type=checkbox ${p.progress?'checked':''}> progress</label><label><input data-rn-pref=desktop type=checkbox ${p.desktop?'checked':''}> desktop</label>`;drawer.querySelector('.notification-head')?.insertAdjacentElement('afterend',row);row.querySelectorAll('[data-rn-pref]').forEach(input=>input.addEventListener('change',async()=>{var next=prefs(),key=input.dataset.rnPref;if(key==='desktop'&&input.checked){if(!('Notification'in window)){input.checked=false;return}if(Notification.permission!=='granted'){var permission=await Notification.requestPermission();if(permission!=='granted'){input.checked=false;next.desktop=false;savePrefs(next);return}}}next[key]=!!input.checked;savePrefs(next)}))}
 async function poll(){if(inFlight)return;inFlight=true;try{var r=await api('/api/operations/live?foreground=0'),cur=snapshot(r),prev=loadJson(STATE_KEY,null);if(prev&&prev.runs&&prev.jobs&&prev.runners)compare(prev,cur);saveJson(STATE_KEY,cur);var next=Math.max(15,Number(r.nextPollSeconds||60));clearTimeout(timer);timer=setTimeout(poll,next*1000)}catch(e){clearTimeout(timer);timer=setTimeout(poll,60000)}finally{inFlight=false}}
 var style=document.createElement('style');style.textContent=__NOTIFICATION_CSS__;document.head.appendChild(style);settings();restoreHistory();poll();
},0);
"""

def _patch_html(html: str) -> str:
    text = str(html)
    if "__deltascopeRunnerNotificationsInstalled" in text:
        return text
    script = _NOTIFICATION_JS.replace("__NOTIFICATION_CSS__", json.dumps(_NOTIFICATION_CSS))
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]

def install() -> None:
    import developer_view
    if getattr(developer_view, "_deltascope_runner_notifications_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    developer_view._deltascope_runner_notifications_installed = True
