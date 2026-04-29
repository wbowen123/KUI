// ==========================================
// KUI Serverless 网关后端 - 纯 D1 极致纯净版
// ==========================================

// --- 密码学辅助函数 ---
async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyAuth(authHeader, adminPass) {
    if (!authHeader) return false;

    // 1. 兼容旧版明文密码
    if (authHeader === adminPass) return true;

    // 2. 兼容终端部署的静态 Hash Token
    const baseKeyHex = await sha256(adminPass);
    if (authHeader === baseKeyHex) return true;

    // 3. 校验前端的 HMAC 动态时间戳签名
    const parts = authHeader.split('.');
    if (parts.length !== 2) return false;
    const [timestamp, clientSig] = parts;

    // 防重放攻击：签名有效期 5 分钟
    if (Date.now() - parseInt(timestamp) > 300000) return false;

    const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(timestamp));
    const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

    return clientSig === expectedSig;
}

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    
    const ADMIN_PASS = env.ADMIN_PASSWORD || "admin"; 
    const db = env.DB; 

    // --- [接口] 边缘节点上报数据 ---
    if (action === "report" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), ADMIN_PASS))) return new Response("Unauthorized", { status: 401 });
        const data = await request.json(); 
        const nowMs = Date.now();
        
        // 核心修复：更新最后在线时间，并将 alert_sent 重置为 0 (表示已恢复健康)
        await db.prepare("UPDATE servers SET cpu = ?, mem = ?, last_report = ?, alert_sent = 0 WHERE ip = ?")
                .bind(data.cpu, data.mem, nowMs, data.ip).run();
        
        const stmts = [];
        let totalDelta = 0;
        
        // 累加节点流量
        if (data.node_traffic && data.node_traffic.length > 0) {
            for (let nt of data.node_traffic) {
                stmts.push(db.prepare("UPDATE nodes SET traffic_used = traffic_used + ? WHERE id = ?").bind(nt.delta_bytes, nt.id));
                totalDelta += nt.delta_bytes;
            }
        }
        
        // 记录历史流量用于图表展示
        if (totalDelta > 0) {
            stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) VALUES (?, ?, ?)")
                    .bind(data.ip, totalDelta, nowMs));
        }
        
        if (stmts.length > 0) await db.batch(stmts);
        return Response.json({ success: true });
    }

    // --- [接口] 边缘节点拉取路由配置 ---
    if (action === "config" && method === "GET") {
        if (!(await verifyAuth(request.headers.get("Authorization"), ADMIN_PASS))) return new Response("Unauthorized", { status: 401 });
        const ip = url.searchParams.get("ip");
        const now = Date.now();
        
        const query = `SELECT * FROM nodes WHERE vps_ip = ? AND enable = 1 AND (traffic_limit = 0 OR traffic_used < traffic_limit) AND (expire_time = 0 OR expire_time > ?)`;
        const { results: machineNodes } = await db.prepare(query).bind(ip, now).all();
        
        for (let node of machineNodes) {
            if (node.protocol === "dokodemo-door" && node.relay_type === "internal") {
                const targetNode = await db.prepare("SELECT * FROM nodes WHERE id = ?").bind(node.target_id).first();
                if (targetNode) {
                    node.chain_target = { 
                        ip: targetNode.vps_ip, port: targetNode.port, protocol: targetNode.protocol, 
                        uuid: targetNode.uuid, sni: targetNode.sni, public_key: targetNode.public_key, short_id: targetNode.short_id 
                    };
                }
            }
        }
        return Response.json({ success: true, configs: machineNodes });
    }

    // --- [接口] 客户端订阅链接下发 ---
    if (action === "sub" && method === "GET") {
        const ip = url.searchParams.get("ip");
        const token = url.searchParams.get("token");
        const expectedSubToken = await sha256(ADMIN_PASS);
        
        if (token !== expectedSubToken) return new Response("Invalid Sub Token", { status: 403 });

        const now = Date.now();
        let query = `SELECT * FROM nodes WHERE enable = 1 AND (traffic_limit = 0 OR traffic_used < traffic_limit) AND (expire_time = 0 OR expire_time > ?)`;
        let sqlParams = [now];
        if (ip) { query += " AND vps_ip = ?"; sqlParams.push(ip); }
        
        const { results: targetNodes } = await db.prepare(query).bind(...sqlParams).all();
        let subLinks = [];
        
        for (let node of targetNodes) {
            const vpsInfo = await db.prepare("SELECT name FROM servers WHERE ip = ?").bind(node.vps_ip).first();
            const remark = encodeURIComponent(vpsInfo ? vpsInfo.name : "KUI_Node");
            
            if (node.protocol === "VLESS") {
                subLinks.push(`vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=none&type=tcp#${remark}`);
            } else if (node.protocol === "Reality") {
                subLinks.push(`vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id}&type=tcp&headerType=none#${remark}-Reality`);
            } else if (node.protocol === "Hysteria2") {
                subLinks.push(`hysteria2://${node.uuid}@${node.vps_ip}:${node.port}/?insecure=1&sni=${node.sni}#${remark}-Hy2`);
            }
        }
        
        return new Response(btoa(unescape(encodeURIComponent(subLinks.join('\n')))), { 
            headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
        });
    }

    // --- [接口] 面板前端登录 ---
    if (action === "login" && method === "POST") {
        if (await verifyAuth(request.headers.get("Authorization"), ADMIN_PASS)) return Response.json({ success: true });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // --- [接口] 失联巡检 (触发器) ---
    if (action === "cron" && method === "GET") {
        const nowMs = Date.now();
        const TIMEOUT_MS = 3 * 60 * 1000; // 3 分钟未上报视为失联
        
        const { results } = await db.prepare(`SELECT ip, name, last_report FROM servers WHERE last_report < ? AND alert_sent = 0`).bind(nowMs - TIMEOUT_MS).all();
        
        if (results && results.length > 0) {
            const tgBotToken = env.TG_BOT_TOKEN; 
            const tgChatId = env.TG_CHAT_ID;
            const updateStmts = [];
            
            for (let vps of results) {
                if (tgBotToken && tgChatId) {
                    const dateStr = new Date(vps.last_report).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
                    const text = `⚠️ [KUI 节点失联告警]\n\n节点别名: ${vps.name}\n公网IP: ${vps.ip}\n最后在线: ${dateStr}\n请检查节点运行状态！`;
                    await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { 
                        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: tgChatId, text }) 
                    });
                }
                updateStmts.push(db.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(vps.ip));
            }
            if (updateStmts.length > 0) await db.batch(updateStmts);
        }
        return Response.json({ success: true, alerted: results ? results.length : 0 });
    }

    // ==============================================
    // 以下全部属于面板私有接口，必须携带有效的动态签名 Header
    // ==============================================
    if (!(await verifyAuth(request.headers.get("Authorization"), ADMIN_PASS))) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    try {
        if (action === "data" && method === "GET") {
            const servers = (await db.prepare("SELECT * FROM servers ORDER BY last_report DESC").all()).results;
            const nodes = (await db.prepare("SELECT * FROM nodes").all()).results;
            return Response.json({ servers, nodes });
        }
        
        // 获取 ECharts 的 7 天流量统计
        if (action === "stats" && method === "GET") {
            const ip = url.searchParams.get("ip");
            const sevenDaysAgoMs = Date.now() - (7 * 24 * 60 * 60 * 1000);
            const query = `
                SELECT 
                    strftime('%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) as day, 
                    SUM(delta_bytes) as total_bytes 
                FROM traffic_stats 
                WHERE ip = ? AND timestamp > ? 
                GROUP BY day 
                ORDER BY day ASC
            `;
            const { results } = await db.prepare(query).bind(ip, sevenDaysAgoMs).all();
            return Response.json(results || []);
        }

        // VPS CRUD 操作
        if (action === "vps") {
            if (method === "POST") { 
                const { ip, name } = await request.json();
                // 核心修复：新加机器默认 alert_sent = 0
                await db.prepare("INSERT OR IGNORE INTO servers (ip, name, alert_sent) VALUES (?, ?, 0)").bind(ip, name).run(); 
                return Response.json({ success: true }); 
            }
            if (method === "DELETE") { 
                await db.prepare("DELETE FROM servers WHERE ip = ?").bind(url.searchParams.get("ip")).run(); 
                return Response.json({ success: true }); 
            }
        }

        // Nodes CRUD 操作
        if (action === "nodes") {
            if (method === "POST") {
                const n = await request.json();
                await db.prepare(`
                    INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id, enable, traffic_used, traffic_limit, expire_time) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).bind(
                    n.id, n.uuid, n.vps_ip, n.protocol, n.port, n.sni || null, n.private_key || null, n.public_key || null, n.short_id || null, 
                    n.relay_type || null, n.target_ip || null, n.target_port || null, n.target_id || null, 1, 0, n.traffic_limit || 0, n.expire_time || 0
                ).run();
                return Response.json({ success: true });
            }
            if (method === "PUT") {
                const { id, enable, reset_traffic } = await request.json();
                if (reset_traffic) await db.prepare("UPDATE nodes SET traffic_used = 0 WHERE id = ?").bind(id).run();
                else if (enable !== undefined) await db.prepare("UPDATE nodes SET enable = ? WHERE id = ?").bind(enable, id).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") { 
                await db.prepare("DELETE FROM nodes WHERE id = ?").bind(url.searchParams.get("id")).run(); 
                return Response.json({ success: true }); 
            }
        }
        return new Response("Not Found", { status: 404 });
    } catch (err) { 
        return Response.json({ error: err.message }, { status: 500 }); 
    }
}

// ==========================================
// Pages 原生内部定时触发器 (自动执行巡检)
// ==========================================
export async function onRequestScheduled(context) {
    const { env } = context;
    const db = env.DB;
    
    const nowMs = Date.now();
    const TIMEOUT_MS = 3 * 60 * 1000; 

    try {
        const { results } = await db.prepare(`SELECT ip, name, last_report FROM servers WHERE last_report < ? AND alert_sent = 0`).bind(nowMs - TIMEOUT_MS).all();

        if (results && results.length > 0) {
            const tgBotToken = env.TG_BOT_TOKEN; 
            const tgChatId = env.TG_CHAT_ID;
            const updateStmts = [];

            for (let vps of results) {
                if (tgBotToken && tgChatId) {
                    const dateStr = new Date(vps.last_report).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
                    const text = `⚠️ [KUI 节点失联告警]\n\n节点别名: ${vps.name}\n公网IP: ${vps.ip}\n最后在线: ${dateStr}\n请检查节点运行状态！`;
                    await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { 
                        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: tgChatId, text }) 
                    });
                }
                updateStmts.push(db.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(vps.ip));
            }
            
            if (updateStmts.length > 0) await db.batch(updateStmts);
            console.log(`[巡检完成] 发现并告警了 ${results.length} 个失联节点`);
        } else {
            console.log("[巡检完成] 所有节点运行正常");
        }
    } catch (error) {
        console.error("巡检任务执行异常:", error);
    }
}
