export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const ADMIN_PASS = env.ADMIN_PASSWORD || "admin"; 

    // 探针上报 (免密)
    if (action === "report" && method === "POST") {
        let vpsList = await env.KUI_KV.get("vps_list", { type: "json" }) || [];
        const data = await request.json(); 
        let updated = false;
        for (let i = 0; i < vpsList.length; i++) {
            if (vpsList[i].ip === data.ip) {
                vpsList[i].cpu = data.cpu;
                vpsList[i].mem = data.mem;
                vpsList[i].last_report = Date.now();
                updated = true; break;
            }
        }
        if (updated) await env.KUI_KV.put("vps_list", JSON.stringify(vpsList));
        return Response.json({ success: true });
    }

    // Agent 拉取配置 (需要 Token，此处简单使用 ADMIN_PASSWORD)
    if (action === "config" && method === "GET") {
        if (request.headers.get("Authorization") !== ADMIN_PASS) return Response.json({ error: "Unauthorized" }, { status: 401 });
        const ip = url.searchParams.get("ip");
        let nodeList = await env.KUI_KV.get("node_list", { type: "json" }) || [];
        const machineNodes = nodeList.filter(n => n.vps_ip === ip);
        return Response.json({ success: true, configs: machineNodes });
    }

    if (action === "login" && method === "POST") {
        const data = await request.json();
        if (data.password === ADMIN_PASS) return Response.json({ success: true });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // 后台管理拦截
    if (request.headers.get("Authorization") !== ADMIN_PASS) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let vpsList = await env.KUI_KV.get("vps_list", { type: "json" }) || [];
    let nodeList = await env.KUI_KV.get("node_list", { type: "json" }) || [];

    try {
        if (action === "data" && method === "GET") return Response.json({ servers: vpsList, nodes: nodeList });

        if (action === "vps") {
            if (method === "POST") {
                const newVps = await request.json();
                if (!vpsList.find(v => v.ip === newVps.ip)) {
                    vpsList.push({ ip: newVps.ip, name: newVps.name, cpu: 0, mem: 0, last_report: null });
                    await env.KUI_KV.put("vps_list", JSON.stringify(vpsList));
                }
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const targetIp = url.searchParams.get("ip");
                vpsList = vpsList.filter(v => v.ip !== targetIp);
                nodeList = nodeList.filter(n => n.vps_ip !== targetIp); 
                await env.KUI_KV.put("vps_list", JSON.stringify(vpsList));
                await env.KUI_KV.put("node_list", JSON.stringify(nodeList));
                return Response.json({ success: true });
            }
        }

        if (action === "nodes") {
            if (method === "POST") {
                nodeList.push(await request.json());
                await env.KUI_KV.put("node_list", JSON.stringify(nodeList));
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const id = url.searchParams.get("id");
                nodeList = nodeList.filter(n => n.id !== id);
                await env.KUI_KV.put("node_list", JSON.stringify(nodeList));
                return Response.json({ success: true });
            }
        }
        return new Response("Not Found", { status: 404 });
    } catch (err) { return Response.json({ error: err.message }, { status: 500 }); }
}
