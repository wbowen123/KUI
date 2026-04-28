export async function onRequestPost(context) {
    const { env, request } = context;
    
    // 简单的认证校验 (建议加上)
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== env.ADMIN_PASSWORD) {
        return new Response('Unauthorized', { status: 401 });
    }

    try {
        const data = await request.json(); 
        const now = Math.floor(Date.now() / 1000); // 当前时间的秒级时间戳

        const statements = [];

        // 1. 更新当前服务器的实时状态（CPU, 内存, 最后在线时间）
        // 如果服务器恢复连接上报数据，我们将 alert_sent 重置为 0，以便下次失联能正常告警
        statements.push(
            env.DB.prepare(`
                UPDATE servers 
                SET cpu = ?, mem = ?, last_report = ?, alert_sent = 0 
                WHERE ip = ?
            `).bind(data.cpu, data.mem, now, data.ip)
        );

        // 2. 累加本次上报的所有节点流量，并写入历史统计表
        if (data.node_traffic && data.node_traffic.length > 0) {
            const totalDelta = data.node_traffic.reduce((acc, curr) => acc + curr.delta_bytes, 0);
            if (totalDelta > 0) {
                statements.push(
                    env.DB.prepare(`
                        INSERT INTO traffic_stats (ip, delta_bytes, timestamp) 
                        VALUES (?, ?, ?)
                    `).bind(data.ip, totalDelta, now)
                );
            }
        }

        // 3. 执行 D1 批处理，保证原子性（要么都成功，要么都失败）
        if (statements.length > 0) {
            await env.DB.batch(statements);
        }

        return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
        });

    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { 
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}
