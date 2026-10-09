const {chromium}=require(process.env.HC_PLAYWRIGHT);
const fs=require('fs');
(async()=>{
  const browser=await chromium.launch({headless:true,channel:'chrome'});
  const page=await browser.newPage();
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  let unavailable=false;
  const users=Object.fromEntries(Array.from({length:60},(_,i)=>['User'+String(i).padStart(3,'0'),{online:i===0?1:0,enabled:true,tx:1000000,rx:2000000}]));
  await page.route('**/*',route=>{
    if(route.request().url().endsWith('/api/metrics'))return route.fulfill({json:{service:unavailable?null:true,users:unavailable?Object.fromEntries(Object.entries(users).map(([n,u])=>[n,{...u,online:null}])):users,resources:{ram:{percent:20},swap:{percent:0},disk:{percent:10}}}});
    if(route.request().url()==='https://localhost/')return route.fulfill({contentType:'text/html',body:fs.readFileSync('/private/tmp/hc-browser-fixture.html','utf8')});
    return route.fulfill({status:404});
  });
  for(const width of [1440,768,390]){
    await page.setViewportSize({width,height:900});
    await page.goto('https://localhost/');
    await page.waitForFunction(()=>document.querySelector('[data-online]').textContent==='Активно');
    const layout=await page.evaluate(()=>({viewport:innerWidth,page:document.documentElement.scrollWidth,chart:trafficBars.clientWidth,content:trafficBars.scrollWidth,active:!document.querySelector('.userlamp').classList.contains('off')}));
    if(layout.page>width||layout.content<=layout.chart||!layout.active)throw new Error(JSON.stringify(layout));
    await page.evaluate(()=>trafficBars.scrollLeft=200);
    await page.evaluate(()=>upd());
    if(await page.evaluate(()=>trafficBars.scrollLeft)<190)throw new Error('Scroll position lost');
    console.log('PASS layout/status/scroll',width,layout);
  }
  unavailable=true;
  await page.evaluate(()=>upd());
  await page.waitForFunction(()=>document.querySelector('.userlamp').classList.contains('unknown'));
  if(await page.locator('.userlamp.off').count())throw new Error('Unavailable marked offline');
  if(errors.length)throw new Error(errors.join('\n'));
  console.log('PASS unknown status; no JavaScript errors');
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
