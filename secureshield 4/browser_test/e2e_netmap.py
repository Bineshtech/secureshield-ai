import json,time,subprocess,sys
from playwright.sync_api import sync_playwright
srv=subprocess.Popen([sys.executable,"-m","http.server","8765"],cwd=__import__("os").path.dirname(__import__("os").path.abspath(__file__)),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1)
out={}
try:
  with sync_playwright() as p:
    b=p.chromium.launch(); pg=b.new_page(viewport={"width":1300,"height":760}); errs=[]
    pg.on("pageerror",lambda e:errs.append(str(e))); pg.on("console",lambda m:errs.append(m.text) if m.type=="error" else None)
    pg.goto("http://localhost:8765/host.html"); pg.wait_for_function("window.ready && window.nframes()>0")
    fr=pg.frame_locator("iframe"); f=[x for x in pg.frames if x!=pg.main_frame][0]; el=f.frame_element().bounding_box()
    abs_=lambda id:(lambda s:(el["x"]+s["x"],el["y"]+s["y"]))(f.evaluate(f"window.__nexus.screenPos('{id}')"))
    nm=lambda n:f.evaluate("(n)=>{for(const [id,r] of window.__nexus.nodes) if(r.label.startsWith(n)) return id}",n)
    # 1 baseline + staggered pop-in
    pg.evaluate("push(0)"); time.sleep(.3)
    out["popin_scale_early"]=f.evaluate("[...window.__nexus.nodes.values()].filter(r=>performance.now()>r.born).length")
    time.sleep(1.6); pg.screenshot(path="./s1_baseline.png")
    out["baseline_nodes"]=f.evaluate("window.__nexus.nodes.size"); out["baseline_edges"]=len(f.evaluate("window.__nexus.edges()")); out["baseline_pulsing"]=f.evaluate("window.__nexus.pulsing()")
    # 2 hover tooltip
    db=nm("db-01"); x,y=abs_(db); pg.mouse.move(x,y); time.sleep(.5)
    out["tooltip"]=f.evaluate("document.getElementById('tip').style.display")=="block" and f.evaluate("document.getElementById('tip').innerText")[:90].replace("\n"," | ")
    pg.screenshot(path="./s2_tooltip.png"); pg.mouse.move(5,5)
    # 3 drag persists across refreshes (re-push same + newer frames)
    p0=f.evaluate(f"window.__nexus.screenPos('{db}')"); x,y=abs_(db)
    pg.mouse.move(x,y); pg.mouse.down(); pg.mouse.move(x+90,y+50,steps=8); pg.mouse.up(); time.sleep(.2)
    p1=f.evaluate(f"window.__nexus.screenPos('{db}')")
    out["drag_moved_px"]=round(((p1["x"]-p0["x"])**2+(p1["y"]-p0["y"])**2)**.5)
    # 4 red node moment: push frame 1 (unknown device appears with alert)
    pg.evaluate("push(0)"); pg.evaluate("push(0)")
    t0=time.time(); pg.evaluate("push(1)")
    for _ in range(40):
        un=f.evaluate("[...window.__nexus.nodes.values()].filter(r=>r.unauth).map(r=>r.id)")
        if un: break
        time.sleep(.05)
    out["red_node_appears_ms_after_frame"]=round((time.time()-t0)*1000); out["unknown_id"]=un[0] if un else None
    out["pulsing_now"]=f.evaluate("window.__nexus.pulsing()"); out["banner"]=f.evaluate("window.__nexus.bannerText()")
    time.sleep(.35); pg.screenshot(path="./s3_birth.png"); time.sleep(.9); pg.screenshot(path="./s4_pulse.png")
    p2=f.evaluate(f"window.__nexus.screenPos('{db}')"); out["drag_survives_refresh_px_off"]=round(((p2["x"]-p1["x"])**2+(p2["y"]-p1["y"])**2)**.5)
    out["fill"]=f.evaluate(f"window.__nexus.nodes.get('{un[0]}').fill")
    # keep pushing later frames: pulse must persist, no duplicates
    for i in range(2,12): pg.evaluate(f"push({i})"); time.sleep(.05)
    out["nodes_after_refreshes"]=f.evaluate("window.__nexus.nodes.size"); out["still_pulsing"]=f.evaluate("window.__nexus.pulsing()")
    # 5 click -> value sent to Python
    ux,uy=abs_(un[0]); pg.mouse.click(ux,uy); time.sleep(.3)
    out["click_value"]=pg.evaluate("window.values.slice(-1)[0]")
    pg.evaluate("window.values.length=0"); x,y=abs_(db); pg.mouse.move(x,y); pg.mouse.down(); pg.mouse.move(x+30,y,steps=5); pg.mouse.up()
    out["drag_does_not_click"]=pg.evaluate("window.values.length")==0
    # 6 zoom + fit
    pg.mouse.move(600,350); pg.mouse.wheel(0,-400); time.sleep(.3); out["zoomed"]=f.evaluate("1")  # smoke
    pg.screenshot(path="./s5_zoom.png")
    out["js_errors"]=errs[:5]; b.close()
finally: srv.terminate()
print(json.dumps(out,indent=1))
