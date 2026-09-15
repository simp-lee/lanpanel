import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import readline from 'node:readline';

let fixture, fixtureExit, origin, controlOrigin;
const running=()=>fixture&&fixture.exitCode===null&&fixture.signalCode===null;
const signalFixture=signal=>{if(!running())return;try{process.kill(-fixture.pid,signal)}catch{fixture.kill(signal)}};
test.beforeAll(async()=>{
  fixture=spawn('go',['test','-run','^TestPlaywrightFixture$','-count=1','-v','./internal/ui'],{cwd:process.cwd(),env:{...process.env,LANPANEL_PLAYWRIGHT_FIXTURE:'1'},detached:true,stdio:['ignore','pipe','pipe']});
  fixtureExit=new Promise(resolve=>fixture.once('exit',(code,signal)=>resolve({code,signal})));
  const lines=readline.createInterface({input:fixture.stdout});
  let stderr='';fixture.stderr.on('data',chunk=>{stderr=(stderr+String(chunk)).slice(-8192)});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Go UI fixture timeout')),30000);let settled=false;const ready=()=>{if(origin&&controlOrigin&&!settled){settled=true;clearTimeout(timer);resolve()}};lines.on('line',line=>{for(const [marker,set] of [['LANPANEL_FIXTURE_ORIGIN=',value=>{origin=value}],['LANPANEL_FIXTURE_CONTROL=',value=>{controlOrigin=value}]]){const index=line.indexOf(marker);if(index>=0)set(line.slice(index+marker.length))}ready()});fixture.once('error',error=>{if(!settled){settled=true;clearTimeout(timer);reject(error)}});fixtureExit.then(({code,signal})=>{if(!settled){settled=true;clearTimeout(timer);reject(new Error(`Go UI fixture exited ${code??signal}: ${stderr}`))}})});
});
test.afterAll(async()=>{if(!running())return;signalFixture('SIGTERM');await Promise.race([fixtureExit,new Promise(resolve=>setTimeout(resolve,5000))]);if(running()){signalFixture('SIGKILL');await fixtureExit}});
async function login(page,token='admin'){await page.goto(origin);await page.locator('input[name=token]').fill(token);await page.locator('button').first().click();await expect(page.locator('#status')).toHaveText('Authenticated')}
async function fixturePost(request,path,body={}){const response=await request.post(controlOrigin+path,{data:body});expect(response.ok(),`${path} returned ${response.status()}`).toBeTruthy();return response}
async function resetFixture(request){await fixturePost(request,'/fixture/reset')}
async function fixtureScenario(request,scenario){await fixturePost(request,'/fixture/scenario',{scenario})}
async function fixtureState(request){return await (await request.get(controlOrigin+'/fixture/state')).json()}
async function fixtureCounters(request){return await (await request.get(controlOrigin+'/fixture/counters')).json()}
test('LP-AUTH-001 real UI stores host-only selector and memory credentials',async({page,context})=>{await login(page);const cookies=await context.cookies();expect(cookies).toHaveLength(1);expect(cookies[0]).toMatchObject({name:'lanpanel_session',httpOnly:true,sameSite:'Strict',secure:false});expect(await page.evaluate(()=>sessionStorage.getItem('lp.proof'))).toHaveLength(64);expect(await page.evaluate(()=>sessionStorage.getItem('lp.csrf'))).toHaveLength(64)});
test('LP-AUTH-002 real UI logout clears selector and browser credentials',async({page,context})=>{await login(page);await page.locator('#logout').click();await page.waitForURL(origin+'/');expect(await context.cookies()).toHaveLength(0);await page.waitForFunction(()=>sessionStorage.length===0)});
test('LP-AUTH-003 real UI Host Origin CSRF and response defenses fail closed',async({request})=>{let bad=await request.post(origin+'/login',{headers:{Origin:'http://127.0.0.1:1','Content-Type':'application/x-www-form-urlencoded'},data:'token=admin'});expect(bad.status()).toBe(403);let response=await request.get(origin+'/',{headers:{Host:'example.invalid'}});expect(response.status()).toBe(421);response=await request.get(origin+'/');expect(response.headers()['cache-control']).toBe('no-store, private');expect(response.headers()['content-security-policy']).not.toContain('unsafe-inline');expect(response.headers()['x-frame-options']).toBe('DENY')});
test('LP-AUTH-004 real UI browser back does not reveal authenticated content',async({page})=>{await login(page);await page.goto('about:blank');await page.goBack();await expect(page.locator('#status')).toHaveText('');expect(await page.evaluate(()=>sessionStorage.length)).toBe(0)});
test('LP-HEADSCALE-001 immutable Headscale initialization requires warning and typed action',async({page})=>{await login(page);const form=page.locator('#headscale-initialize');await form.locator('input[name=control_domain]').fill('control.example.test');await form.locator('input[name=magicdns_namespace]').fill('mesh.example.test');page.once('dialog',async dialog=>{expect(dialog.message()).toContain('cannot be changed or removed');await dialog.accept()});const responsePromise=page.waitForResponse(response=>response.url()===origin+'/api/actions/headscale_initialize');await form.locator('button').click();const response=await responsePromise;expect(response.status(),response.request().postData()).toBe(200);await expect(page.locator('#status')).toHaveText('Headscale identity hds_00000000000000000000000000000001 initialized; control service and ingress remain inactive');await expect(form).toBeHidden()});
test('LP-HEADSCALE-002 foreign initialization evidence reports terminal job',async({page})=>{await login(page);const form=page.locator('#headscale-initialize');await form.locator('input[name=control_domain]').fill('foreign.example.test');await form.locator('input[name=magicdns_namespace]').fill('mesh.example.test');page.once('dialog',dialog=>dialog.accept());const responsePromise=page.waitForResponse(response=>response.url()===origin+'/api/actions/headscale_initialize');await form.locator('button').click();const response=await responsePromise;expect(response.status()).toBe(409);await expect(page.locator('#status')).toHaveText('Blocked: foreign Headscale database, account, or artifact evidence; job job_foreign_headscale_fixture')});
test('LP-HEADSCALE-004 legacy source fields are rejected',async({page})=>{await login(page);const response=await page.evaluate(async()=>{const result=await fetch('/api/actions/headscale_initialize',{method:'POST',headers:{'X-LanPanel-Session-Proof':sessionStorage.getItem('lp.proof'),'X-LanPanel-CSRF':sessionStorage.getItem('lp.csrf'),'Content-Type':'application/json'},body:JSON.stringify({control_domain:'legacy.example.test',magicdns_namespace:'mesh.example.test',proxy_url:'https://proxy.example.test',confirmation:'initialize'})});return result.status});expect(response).toBe(400)});
test('LP-HEADSCALE-003 preauth key creation submits canonical terminal JSON and delivers the key once',async({page})=>{
  const bodies=[];
  await page.route('**/api/actions/preauth_key_create**',async route=>{
    bodies.push(route.request().postData());
    const planned=new URL(route.request().url()).pathname.endsWith('/plan');
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(planned?{plan_id:'plan-fixture',exposure_summary:'creates one short-lived key'}:{secret:'Zml4dHVyZS1rZXk='})});
  });
  await login(page);
  const form=page.locator('#headscale-key-create');
  await form.locator('input[name=user_id]').fill('1');
  await form.locator('input[name=expiration_seconds]').fill('3600');
  page.once('dialog',dialog=>dialog.accept());
  await form.locator('button').click();
  await expect(page.locator('#status')).toHaveText('Preauth key (shown once): fixture-key');
  expect(bodies).toEqual([
    '{"expiration_seconds":3600}',
    '{"plan_id":"plan-fixture","confirmation":"create","expiration_seconds":3600}',
  ]);
});
test('LP-APP-LOCAL-001 structured local wizard saves stopped and unpublished without side effects',async({page,request})=>{
  await resetFixture(request); await login(page);
  await page.locator('#resource-create-open').click();
  const form=page.locator('#resource-create');
  await form.locator('input[name=name]').fill('Created local');
  await form.locator('input[name=executable]').fill('/usr/local/bin/fixture-app');
  await form.locator('input[name=working_directory]').fill('/srv/fixture-app');
  await form.locator('select[name=endpoint_kind]').selectOption('tcp_socket_activation');
  await expect(form.locator('#create-tcp-fields')).toBeVisible();
  await form.locator('input[name=tcp_address]').fill('127.0.0.1'); await form.locator('input[name=tcp_port]').fill('18080');
  await form.locator('select[name=endpoint_kind]').selectOption('relay_unix');
  await expect(form.locator('#create-tcp-fields')).toBeHidden();
  await form.locator('select[name=endpoint_kind]').selectOption('unix_socket_activation');
  await form.locator('input[name=canonical_domain]').fill('created.example.test');
  await form.locator('button[type=submit]').click();
  await expect(page.locator('#status')).toHaveText('Application saved; resource remains stopped and unpublished');
  const card=page.locator('#resource-list article').filter({hasText:'Created local'});
  await expect(card).toContainText('local_http'); await expect(card).toContainText('closed'); await expect(card).toContainText('stopped'); await expect(card).toContainText('unpublished');
  await card.getByRole('button',{name:'Edit configuration'}).click(); const update=page.locator('#resource-update-json'); await expect(update).toBeVisible(); await expect(update.locator('input[name=executable]')).toHaveValue('/usr/local/bin/fixture-app'); await update.locator('input[name=name]').fill('Edited local'); await update.locator('button[type=submit]').click(); await expect(page.locator('#status')).toHaveText('Configuration saved; resource remains stopped and unpublished'); const editedCard=page.locator('#resource-list article').filter({hasText:'Edited local'}); await expect(editedCard).toContainText('stopped'); await expect(editedCard).toContainText('unpublished');
  const state=await fixtureState(request); expect(state.resource_count).toBe(3); expect(state.resource_ids).toContain('res_00000000000000000000000000000003');
  const counters=await fixtureCounters(request); expect(counters).toEqual({process_start:0,process_stop:0,acme_requests:0,dns_requests:0,tailscale_commands:0,remote_commands:0,connector_logins:0,connector_verifies:0});
  await editedCard.getByRole('button',{name:'Start process'}).click();
  await expect(page.locator('#status')).toContainText('job_');
  expect((await fixtureCounters(request)).process_start).toBe(1);
  const listResponse=page.waitForResponse(response=>response.url().endsWith('/api/actions/job_list')); await page.locator('#product-reads button[data-read="job_list"]').click(); const jobList=await (await listResponse).json(); const startJob=jobList.jobs.find(job=>job.operation==='process_start'); expect(startJob.result).toBe('succeeded'); const detail=page.locator('#job-detail'); await detail.locator('input[name=job_id]').fill(startJob.id); const detailResponse=page.waitForResponse(response=>response.url().includes('/api/actions/job_detail?job_id=')); await detail.locator('button').click(); const jobDetail=await (await detailResponse).json(); expect(jobDetail.job.id).toBe(startJob.id); expect(jobDetail.job.result).toBe('succeeded');
});
test('LP-APP-LOCAL-002 browser and authoritative validation do not create a resource',async({page,request})=>{
  await resetFixture(request); await login(page); await page.locator('#resource-create-open').click();
  const form=page.locator('#resource-create'); await form.locator('input[name=name]').fill('Rejected local'); await form.locator('input[name=canonical_domain]').fill('rejected.example.test');
  await form.locator('button[type=submit]').click(); await expect(page.locator('#status')).toHaveText('Executable and working directory are required for local_http');
  expect((await fixtureState(request)).resource_count).toBe(2);
  await fixtureScenario(request,'create-preflight-failure');
  await form.locator('input[name=executable]').fill('/usr/local/bin/fixture-app'); await form.locator('input[name=working_directory]').fill('/srv/fixture-app'); await form.locator('button[type=submit]').click();
  await expect(page.locator('#status')).toHaveText('authoritative_preflight_failed'); expect((await fixtureState(request)).resource_count).toBe(2);
});
test('LP-APP-TAILNET-001 fixed remote wizard keeps evidence stages separate and hides process actions',async({page,request})=>{
  await resetFixture(request); await login(page); await page.locator('#resource-create-open').click();
  const form=page.locator('#resource-create'); await form.locator('select[name=target_kind]').selectOption('tailnet_http');
  await expect(form.locator('#create-local-fields')).toBeHidden(); await expect(form.locator('#create-tailnet-fields')).toBeVisible();
  await expect(form.locator('input[name=executable]')).toBeHidden(); await expect(form.locator('input[name=working_directory]')).toBeHidden();
  await form.locator('input[name=name]').fill('Created tailnet'); await form.locator('input[name=peer_ip]').fill('100.64.0.2'); await form.locator('input[name=source_ip]').fill('100.64.0.1'); await form.locator('input[name=remote_port]').fill('8080'); await form.locator('input[name=canonical_domain]').fill('tailnet.example.test');
  await form.locator('button[type=submit]').click(); await expect(page.locator('#status')).toHaveText('Application saved; resource remains stopped and unpublished');
  const card=page.locator('#resource-list article').filter({hasText:'Created tailnet'}); await expect(card).toContainText('tailnet_http'); await expect(card).toContainText('unknown'); await expect(card).not.toContainText('Start process');
  await card.getByRole('button',{name:'Review status'}).click(); await expect(page.locator('#detail-evidence')).toContainText('Connector: unverified'); await expect(page.locator('#detail-evidence')).toContainText('route: unverified'); await expect(page.locator('#detail-evidence')).toContainText('target: unknown');
  await fixtureScenario(request,'tailnet-ready'); await page.locator('#refresh-status').click();
  const readyCard=page.locator('#resource-list article').filter({hasText:'Created tailnet'}); await expect(readyCard).toContainText('closed'); await expect(readyCard.getByRole('button',{name:'Publish'})).toBeVisible();
  const planResponse=page.waitForResponse(response=>response.url().includes('/api/actions/publish/plan?resource_id=res_00000000000000000000000000000003'));
  const dialogPromise=page.waitForEvent('dialog'); await readyCard.getByRole('button',{name:'Publish'}).click(); await planResponse; const dialog=await dialogPromise; await fixtureScenario(request,'tailnet-revalidation-failure'); await dialog.accept();
  await expect(page.locator('#status')).toHaveText('target_preflight_failed');
  await fixtureScenario(request,'tailnet-ready'); await page.locator('#refresh-status').click(); page.once('dialog',dialog=>dialog.accept()); await readyCard.getByRole('button',{name:'Publish'}).click(); await expect(page.locator('#status')).toContainText('Publication job job_');
  for (const [scenario,evidence] of [['tailnet-connector-failure','Connector: unreachable'],['tailnet-route-failure','route: unreachable'],['tailnet-target-failure','target: unreachable']]) { await fixtureScenario(request,scenario); await page.locator('#refresh-status').click(); const failedCard=page.locator('#resource-list article').filter({hasText:'Created tailnet'}); await expect(failedCard).toContainText('unreachable'); await failedCard.getByRole('button',{name:'Review status'}).click(); await expect(page.locator('#detail-evidence')).toContainText(evidence); }
  const counters=await fixtureCounters(request); expect(counters.process_start).toBe(0); expect(counters.process_stop).toBe(0); expect(counters.acme_requests).toBe(0); expect(counters.dns_requests).toBe(0); expect(counters.tailscale_commands).toBe(0); expect(counters.remote_commands).toBe(0); expect(counters.connector_logins).toBe(0); expect(counters.connector_verifies).toBe(0);
});

test('LP-ACTION-002 final typed management controls are discoverable after login', async ({ page }) => {
  await login(page)
  for (const id of ['resource-create','resource-update-json','process-control','resource-delete','headscale-user-create','headscale-key-create','headscale-key-revoke','headscale-device-expire','headscale-reads','connector-binding','connector-login','connector-verify','product-reads','job-detail']) {
    await expect(page.locator('#'+id)).toBeVisible()
  }
})

test('LP-CONTRACTION-001 unpublish and close-all display exact contraction outcomes',async({page})=>{
  const outcomes=[
    {value:{outcome:'succeeded',access_closed:true,shared_ingress_down:false,access_may_remain:false},unpublish:'App unpublished',closeAll:'All App origin ingress closed'},
    {value:{outcome:'partial',access_closed:true,shared_ingress_down:true,access_may_remain:false},unpublish:'App access closed; shared ingress is down',closeAll:'App access closed; shared ingress is down'},
    {value:{outcome:'unknown',access_closed:false,shared_ingress_down:false,access_may_remain:true},unpublish:'Unknown: App access may remain',closeAll:'Unknown: App access may remain'},
  ];
  let current=outcomes[0].value;
  const fulfill=async(route,operation)=>{
    const planned=new URL(route.request().url()).pathname.endsWith('/plan');
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(planned?{plan_id:'plan-fixture',operation,target_kind:operation==='unpublish'?'resource':'installation',exposure_summary:'contracts App ingress',prerequisites:'fresh closure authority',expires_at:'2030-01-01T00:00:00Z'}:current)});
  };
  await page.route('**/api/actions/unpublish**',route=>fulfill(route,'unpublish'));
  await page.route('**/api/actions/close_all**',route=>fulfill(route,'close_all'));
  await login(page);
  const form=page.locator('#unpublish'),status=page.locator('#status');
  for(let index=0;index<outcomes.length;index++){
    current=outcomes[index].value;
    await form.locator('input[name=resource_id]').fill('res_'+String(index+1).padStart(32,'0'));
    page.once('dialog',dialog=>dialog.accept());
    await form.locator('button').click();
    await expect(status).toHaveText(outcomes[index].unpublish);
  }
  for(const outcome of outcomes){
    current=outcome.value;
    page.once('dialog',dialog=>dialog.accept());
    await page.locator('#close-all').click();
    await expect(status).toHaveText(outcome.closeAll);
  }
});

test('LP-AUTH-005 real UI WebSocket binds selector and first-frame proof',async({page,context})=>{await login(page);const proofA=await page.evaluate(()=>sessionStorage.getItem('lp.proof'));const accepted=await page.evaluate(({origin,proof})=>new Promise(resolve=>{const ws=new WebSocket(origin.replace('http:','ws:')+'/api/events','lanpanel.events.v1');ws.onopen=()=>ws.send(JSON.stringify({type:'auth',proof}));ws.onmessage=event=>{resolve(JSON.parse(String(event.data)).type==='ready');ws.close()};ws.onerror=()=>resolve(false);setTimeout(()=>resolve(false),7000)}),{origin,proof:proofA});expect(accepted).toBe(true);await context.clearCookies();await login(page);const rejected=await page.evaluate(({origin,proof})=>new Promise(resolve=>{let ready=false;const ws=new WebSocket(origin.replace('http:','ws:')+'/api/events','lanpanel.events.v1');ws.onopen=()=>ws.send(JSON.stringify({type:'auth',proof}));ws.onmessage=()=>{ready=true};ws.onclose=()=>resolve(!ready);ws.onerror=()=>resolve(true);setTimeout(()=>resolve(false),7000)}),{origin,proof:proofA});expect(rejected).toBe(true)});
test('LP-ACTION-003 rotation Plan does not cancel a concurrent mutation',async({page,request})=>{await login(page);const action=page.evaluate(async()=>{const response=await fetch('/api/actions/headscale_initialize',{method:'POST',headers:{'X-LanPanel-Session-Proof':sessionStorage.getItem('lp.proof'),'X-LanPanel-CSRF':sessionStorage.getItem('lp.csrf'),'Content-Type':'application/json'},body:JSON.stringify({control_domain:'blocked.example.test',magicdns_namespace:'mesh.example.test',confirmation:'initialize'})});return response.status});const started=await request.get(controlOrigin+'/action/started');expect(started.status()).toBe(204);let planStatus;try{planStatus=await page.evaluate(async()=>{const response=await fetch('/api/actions/admin_token_rotate/plan',{method:'POST',headers:{'X-LanPanel-Session-Proof':sessionStorage.getItem('lp.proof'),'X-LanPanel-CSRF':sessionStorage.getItem('lp.csrf'),'Content-Type':'application/json'},body:'{}'});return response.status})}finally{const released=await request.post(controlOrigin+'/action/release');expect(released.status()).toBe(204)}expect(planStatus).toBe(200);expect(await action).toBe(200)});
test('LP-ACTION-001 admin token rotation reviews Plan, rejects the old token, and accepts the new token',async({page,context})=>{await login(page);page.once('dialog',async dialog=>{expect(dialog.message()).toContain('admin_token_rotate');expect(dialog.message()).toContain('admin_token_rotation');await dialog.accept()});await page.locator('#rotate').click();await expect(page.locator('#status')).toHaveText('New admin token: new-admin-token');expect(await context.cookies()).toHaveLength(0);expect(await page.evaluate(()=>sessionStorage.length)).toBe(0);await page.locator('input[name=token]').fill('admin');await page.locator('#login button').click();await expect(page.locator('#status')).toHaveText('Authentication failed');expect(await context.cookies()).toHaveLength(0);expect(await page.evaluate(()=>sessionStorage.length)).toBe(0);await page.locator('input[name=token]').fill('new-admin-token');await page.locator('#login button').click();await expect(page.locator('#status')).toHaveText('Authenticated')});
test('LP-AUTH-006 Shutdown prevents relogin and WebSocket attachment',async({page,request})=>{await login(page,'new-admin-token');const proof=await page.evaluate(()=>sessionStorage.getItem('lp.proof'));const socketAttached=await page.evaluate(({origin,proof})=>new Promise(resolve=>{const ws=new WebSocket(origin.replace('http:','ws:')+'/api/events','lanpanel.events.v1');window.__shutdownSocket=ws;ws.onopen=()=>ws.send(JSON.stringify({type:'auth',proof}));ws.onmessage=event=>{if(JSON.parse(String(event.data)).type==='ready')resolve(true)};ws.onerror=()=>resolve(false);ws.onclose=()=>resolve(false)}),{origin,proof});expect(socketAttached).toBe(true);const socketClosed=page.evaluate(()=>new Promise(resolve=>{const ws=window.__shutdownSocket;if(!ws||ws.readyState>=WebSocket.CLOSING){resolve(true);return}ws.addEventListener('close',()=>resolve(true),{once:true});ws.addEventListener('error',()=>resolve(true),{once:true})}));const shutdown=await request.post(controlOrigin+'/shutdown');expect(shutdown.status()).toBe(204);expect(await socketClosed).toBe(true);const loginStatus=await page.evaluate(async({origin})=>{try{return(await fetch(origin+'/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'token=new-admin-token'})).status}catch{return 0}},{origin});expect(loginStatus).toBe(0);const attached=await page.evaluate(({origin,proof})=>new Promise(resolve=>{try{let ready=false;const ws=new WebSocket(origin.replace('http:','ws:')+'/api/events','lanpanel.events.v1');ws.onopen=()=>ws.send(JSON.stringify({type:'auth',proof}));ws.onmessage=event=>{ready=JSON.parse(String(event.data)).type==='ready';resolve(ready)};ws.onerror=()=>resolve(false);ws.onclose=()=>resolve(ready)}catch{resolve(false)}}),{origin,proof});expect(attached).toBe(false)});
