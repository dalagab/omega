"""DeltaScope contextual control availability.

Keeps unavailable actions visible but disabled, with deterministic unlock guidance.
This is presentation state only; server-side authority checks remain authoritative.
"""
from __future__ import annotations

import developer_view

_INSTALLED = False

_CSS = r'''
/* Contextual availability: visible, slightly grey, and explanatory. */
.app-shell button:disabled,
.app-shell input:disabled,
.app-shell select:disabled,
.app-shell textarea:disabled,
.app-switcher-drawer button:disabled,
.plugin-picker-drawer button:disabled{
  opacity:.62!important;cursor:not-allowed!important;box-shadow:none!important;transform:none!important;
}
.app-shell>main button:disabled,.app-shell>main .is-unavailable{
  background:#e8e8e8!important;color:#6f6f6f!important;border-color:#c6c6c6!important;
}
.app-shell>main button:disabled:hover{background:#e8e8e8!important;color:#6f6f6f!important;border-color:#c6c6c6!important;outline:0!important}
.app-shell>main input:disabled,.app-shell>main select:disabled,.app-shell>main textarea:disabled{
  background:#e0e0e0!important;color:#6f6f6f!important;border-color:#c6c6c6!important;
}
.workbench-nav button[data-perspective-route]:disabled{
  opacity:1!important;background:#161616!important;color:#6f6f6f!important;cursor:not-allowed!important;
}
.workbench-nav button[data-perspective-route]:disabled:hover{background:#161616!important;color:#6f6f6f!important}
.workbench-nav button[data-perspective-route]:disabled .nav-icon{color:#525252!important}
.toni-rail button:disabled{opacity:.48!important;cursor:not-allowed!important}
.availability-placeholder{border:1px dashed #c6c6c6;background:#f4f4f4;padding:12px;margin-top:10px}
.availability-placeholder .availability-reason{margin:0 0 9px;color:#6f6f6f;font-size:12px}
.workflow-dispatch-form.is-unavailable-context{opacity:.78}
'''

_JS = r'''
setTimeout(()=>{
 if(window.__deltascopeAvailabilityInstalled)return;
 window.__deltascopeAvailabilityInstalled=true;
 const baseTitles=new WeakMap();
 const pluginScoped={
   developer:new Set(['Security Review','Journey','Behaviors','Changes','Omega Profile','Source & Build']),
   investigator:new Set(['Journey','Findings','Behaviors','Relationships','Published Evidence']),
   researcher:new Set(['Behaviors','Relationships','Compare'])
 };
 function rememberTitle(el){if(el&&!baseTitles.has(el))baseTitles.set(el,el.getAttribute('title')||'')}
 function setUnavailable(el,unavailable,reason=''){
   if(!el)return;
   rememberTitle(el);
   const disabled=!!unavailable;
   el.disabled=disabled;
   el.classList.toggle('is-unavailable',disabled);
   if(disabled){
     el.dataset.unavailableReason=reason||'This action is unavailable in the current context.';
     el.setAttribute('aria-disabled','true');
     el.title=el.dataset.unavailableReason;
   }else{
     delete el.dataset.unavailableReason;
     el.removeAttribute('aria-disabled');
     el.classList.remove('is-unavailable');
     el.title=baseTitles.get(el)||'';
   }
 }
 window.deltaScopeSetUnavailable=setUnavailable;
 function navLabel(button){const spans=button?.querySelectorAll?.('span')||[];return spans.length?String(spans[spans.length-1].textContent||'').trim():''}
 function hasPlugin(){return !!Number(currentSubject?.variantId||0)}
 function githubConnected(){const state=String($('githubAccessState')?.textContent||'PUBLIC').trim().toUpperCase();return !!state&&state!=='PUBLIC'&&state!=='CHECKING ACCESS…'}
 function syncNavigation(){
   const required=pluginScoped[currentPerspective]||new Set(),selected=hasPlugin();
   document.querySelectorAll('#perspectiveNav [data-perspective-route]').forEach(button=>{
     const needsPlugin=required.has(navLabel(button));
     setUnavailable(button,needsPlugin&&!selected,'Select a plugin from the top bar first.');
   });
 }
 function ensureWorkflowDispatchPlaceholder(){
   const main=$('workflowCenterMain');if(!main||!main.querySelector('.workflow-main-head'))return;
   const blocks=[...main.querySelectorAll('.workflow-actions-block')];
   let dispatch=blocks.find(block=>String(block.querySelector('h3')?.textContent||'').trim()==='Dispatch');
   if(!dispatch){
     const acquire=blocks.find(block=>String(block.querySelector('h3')?.textContent||'').trim()==='Acquire selected workflow');
     dispatch=document.createElement('div');dispatch.className='workflow-actions-block availability-placeholder';dispatch.dataset.availabilityPlaceholder='dispatch';
     dispatch.innerHTML='<h3>Dispatch</h3><div class="availability-reason">Acquire workflow details first. DeltaScope needs the workflow_dispatch contract before this action can be enabled.</div><button data-availability-placeholder-button disabled title="Acquire workflow details first.">Start workflow</button>';
     acquire?.after(dispatch);return;
   }
   if(!dispatch.querySelector('#workflowCenterDispatch')&&!dispatch.querySelector('[data-availability-placeholder-button]')){
     const note=document.createElement('div');note.className='availability-placeholder';
     note.innerHTML='<div class="availability-reason">This acquired workflow does not declare workflow_dispatch on the selected ref.</div><button data-availability-placeholder-button disabled title="This workflow does not declare workflow_dispatch on the selected ref.">Start workflow</button>';
     dispatch.appendChild(note);
   }
 }
 function syncWorkflowCenter(){
   ensureWorkflowDispatchPlaceholder();
   const connected=githubConnected(),dispatch=$('workflowCenterDispatch'),confirmation=$('workflowCenterDispatchConfirm');
   if(dispatch){
     const confirmed=String(confirmation?.value||'').trim()==='DISPATCH';
     const reason=!connected?'Connect GitHub workflow access first.':!confirmed?'Type DISPATCH to enable this action.':'';
     setUnavailable(dispatch,!connected||!confirmed,reason);
     const form=dispatch.closest('.workflow-dispatch-form');form?.classList.toggle('is-unavailable-context',!connected);
   }
   const pluginUrl=document.querySelector('[data-wc-plugin-url]'),pluginResolve=document.querySelector('[data-wc-plugin-resolve]');
   if(pluginResolve)setUnavailable(pluginResolve,!String(pluginUrl?.value||'').trim(),'Paste a plugin GitHub link first.');
   const runConfirm=$('workflowRunActionConfirm'),runButtons=[...document.querySelectorAll('[data-wc-run-action]')];
   if(runButtons.length){
     const expected=String(runConfirm?.placeholder||'').toUpperCase().includes('CANCEL')?'CANCEL':'RERUN';
     const confirmed=String(runConfirm?.value||'').trim()===expected;
     runButtons.forEach(button=>setUnavailable(button,!confirmed,`Type ${expected} to enable this action.`));
   }
   const inspector=$('workflowRunInspector');
   if(inspector?.querySelector('.workflow-run-head')&&!runButtons.length){
     const message=[...inspector.querySelectorAll('.workflow-run-control')].find(el=>!el.querySelector('button'));
     if(message&&!message.querySelector('[data-availability-run-control]')){
       const box=document.createElement('div');box.className='availability-placeholder';box.dataset.availabilityRunControl='1';
       box.innerHTML='<div class="availability-reason">Connect GitHub workflow access, then reacquire this workflow to enable run controls.</div><button disabled title="Connect GitHub workflow access, then reacquire this workflow.">Run control</button>';
       message.appendChild(box);
     }
   }
 }
 function syncKnownControls(){
   const selected=hasPlugin();
   setUnavailable($('toniSelection'),!selected,'Select a plugin first.');
   setUnavailable($('ruleEvaluate'),!selected,'Select a plugin first.');
   setUnavailable($('ruleCreatePositiveFixture'),!selected,'Select a plugin first.');
   setUnavailable($('ruleCreateNegativeFixture'),!selected,'Select a plugin first.');
   const riftFile=$('riftFileInput'),riftUrl=$('riftGithubUrl');
   setUnavailable($('riftImportFile'),!(riftFile?.files?.length),'Select a local Rift JSON report first.');
   setUnavailable($('riftImportGithub'),!String(riftUrl?.value||'').trim(),'Paste a GitHub JSON report link first.');
   setUnavailable($('githubAccessForget'),!githubConnected(),'Connect GitHub first.');
   if($('ruleForkLocal')?.disabled&&!$('ruleForkLocal').dataset.unavailableReason){$('ruleForkLocal').title='Select a System Rule first.';$('ruleForkLocal').dataset.unavailableReason='Select a System Rule first.'}
   if($('ruleSaveLocal')?.disabled&&!$('ruleSaveLocal').dataset.unavailableReason){$('ruleSaveLocal').title='Open or create an editable My Rule first.';$('ruleSaveLocal').dataset.unavailableReason='Open or create an editable My Rule first.'}
   if($('ruleVisualDelete')?.disabled&&!$('ruleVisualDelete').dataset.unavailableReason){$('ruleVisualDelete').title='Select a visual rule node first.';$('ruleVisualDelete').dataset.unavailableReason='Select a visual rule node first.'}
   syncWorkflowCenter();
 }
 function syncAvailability(){syncNavigation();syncKnownControls()}
 const renderPerspectiveNavBase=renderPerspectiveNav;renderPerspectiveNav=function(){const result=renderPerspectiveNavBase();syncAvailability();return result};
 const updateSubjectAvailabilityBase=updateSubject;updateSubject=function(d){const result=updateSubjectAvailabilityBase(d);syncAvailability();return result};
 const clearSubjectAvailabilityBase=clearSubject;clearSubject=function(){const result=clearSubjectAvailabilityBase();syncAvailability();return result};
 document.addEventListener('input',event=>{if(event.target.closest('#workflowCenterMain,#workbench-rift-reports'))syncAvailability()},true);
 document.addEventListener('change',event=>{if(event.target.closest('#workflowCenterMain,#workbench-rift-reports,#githubAccessPanel'))syncAvailability()},true);
 const observer=new MutationObserver(()=>syncAvailability());observer.observe(document.body,{childList:true,subtree:true,characterData:true});
 syncAvailability();
},0);
'''


def _insert_before_last(text: str, marker: str, payload: str) -> str:
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError(f"DeltaScope HTML boundary not found: {marker}")
    return text[:index] + payload + text[index:]


def install() -> None:
    global _INSTALLED
    if _INSTALLED or "__deltascopeAvailabilityInstalled" in developer_view.HTML:
        _INSTALLED = True
        return
    html = developer_view.HTML
    html = _insert_before_last(html, "</style>", "\n" + _CSS + "\n")
    html = _insert_before_last(html, "</script>", "\n" + _JS + "\n")
    developer_view.HTML = html
    _INSTALLED = True
